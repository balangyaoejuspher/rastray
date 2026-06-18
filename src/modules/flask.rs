use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::fingerprint::Framework;
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct FlaskAnalyzer;

impl FlaskAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for FlaskAnalyzer {
    fn name(&self) -> &'static str {
        "flask"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl.fingerprint.frameworks.contains(&Framework::Flask)
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let aux = compiled_aux_patterns()?;
        let mut findings = Vec::new();
        let project_roots: Vec<PathBuf> = crawl
            .fingerprint
            .projects
            .iter()
            .filter(|p| p.frameworks.contains(&Framework::Flask))
            .map(|p| p.root.clone())
            .collect();
        if project_roots.is_empty() {
            return Ok(findings);
        }
        for file in &crawl.files {
            if file.kind != FileKind::Source {
                continue;
            }
            let Some(ext) = file
                .path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
            else {
                continue;
            };
            if ext != "py" {
                continue;
            }
            if !project_roots.iter().any(|root| file.path.starts_with(root)) {
                continue;
            }
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if !is_flask_app_file(&contents, aux) {
                continue;
            }
            findings.extend(scan_debug_enabled(&file.path, &contents, aux));
            findings.extend(scan_hardcoded_secret_key(&file.path, &contents, aux));
        }
        Ok(findings)
    }
}

struct AuxPatterns {
    flask_marker: Regex,
    debug_run_kwarg: Regex,
    debug_config_assign: Regex,
    debug_attr_assign: Regex,
    secret_key_config_literal: Regex,
    secret_key_attr_literal: Regex,
}

fn compiled_aux_patterns() -> Result<&'static AuxPatterns, AnalyzerError> {
    static CACHE: OnceLock<Result<AuxPatterns, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let flask_marker = Regex::new(r"(?m)^\s*(?:from\s+flask\b|import\s+flask\b)")
            .map_err(|e| format!("flask_marker: {e}"))?;
        let debug_run_kwarg =
            Regex::new(r"\b\w+\s*\.\s*run\s*\([^)]*\bdebug\s*=\s*True\b[^)]*\)")
                .map_err(|e| format!("debug_run_kwarg: {e}"))?;
        let debug_config_assign = Regex::new(
            r#"(?m)^\s*\w+\s*\.\s*config\s*\[\s*['"]DEBUG['"]\s*\]\s*=\s*True\b"#,
        )
        .map_err(|e| format!("debug_config_assign: {e}"))?;
        let debug_attr_assign = Regex::new(r"(?m)^\s*\w+\s*\.\s*debug\s*=\s*True\b")
            .map_err(|e| format!("debug_attr_assign: {e}"))?;
        let secret_key_config_literal = Regex::new(
            r#"(?m)^\s*\w+\s*\.\s*config\s*\[\s*['"]SECRET_KEY['"]\s*\]\s*=\s*(['"])([^'"\r\n]{1,256})(['"])"#,
        )
        .map_err(|e| format!("secret_key_config_literal: {e}"))?;
        let secret_key_attr_literal =
            Regex::new(r#"(?m)^\s*\w+\s*\.\s*secret_key\s*=\s*(['"])([^'"\r\n]{1,256})(['"])"#)
                .map_err(|e| format!("secret_key_attr_literal: {e}"))?;
        Ok(AuxPatterns {
            flask_marker,
            debug_run_kwarg,
            debug_config_assign,
            debug_attr_assign,
            secret_key_config_literal,
            secret_key_attr_literal,
        })
    });
    match cached {
        Ok(p) => Ok(p),
        Err(e) => Err(AnalyzerError::Failed {
            name: "flask",
            message: format!("failed to compile a builtin flask aux pattern: {e}"),
        }),
    }
}

fn is_flask_app_file(contents: &str, aux: &AuxPatterns) -> bool {
    aux.flask_marker.is_match(contents)
}

fn scan_debug_enabled(path: &std::path::Path, contents: &str, aux: &AuxPatterns) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in aux.debug_run_kwarg.find_iter(contents) {
        out.push(make_debug_finding(path, contents, m.start(), m.len()));
    }
    for m in aux.debug_config_assign.find_iter(contents) {
        out.push(make_debug_finding(path, contents, m.start(), m.len()));
    }
    for m in aux.debug_attr_assign.find_iter(contents) {
        out.push(make_debug_finding(path, contents, m.start(), m.len()));
    }
    out
}

fn make_debug_finding(path: &std::path::Path, contents: &str, start: usize, len: usize) -> Finding {
    let (line, column) = byte_offset_to_line_col(contents, start);
    let location = Location::file(path.to_path_buf())
        .with_span(start, len)
        .with_line(line, column);
    Finding::new(
        "RSTR-FLASK-001",
        "Flask app enables the Werkzeug debugger (`debug=True`); a single 500 response exposes an interactive Python console at `/console` that yields remote code execution to anyone who can hit the endpoint"
            .to_string(),
        Severity::Critical,
        Category::Security,
    )
    .with_help(
        "drive `debug` from the environment with a false default: `app.run(debug=os.environ.get('FLASK_DEBUG') == '1')`; for the config form, do the same with `app.config['DEBUG']`. Never ship `debug=True` to production — the Werkzeug console is unauthenticated and pin-protected only when running on the bound interface",
    )
    .with_location(location)
}

fn scan_hardcoded_secret_key(
    path: &std::path::Path,
    contents: &str,
    aux: &AuxPatterns,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in aux.secret_key_config_literal.captures_iter(contents) {
        if let Some(m) = caps.get(0) {
            out.push(make_secret_key_finding(path, contents, m.start(), m.len()));
        }
    }
    for caps in aux.secret_key_attr_literal.captures_iter(contents) {
        if let Some(m) = caps.get(0) {
            out.push(make_secret_key_finding(path, contents, m.start(), m.len()));
        }
    }
    out
}

fn make_secret_key_finding(
    path: &std::path::Path,
    contents: &str,
    start: usize,
    len: usize,
) -> Finding {
    let (line, column) = byte_offset_to_line_col(contents, start);
    let location = Location::file(path.to_path_buf())
        .with_span(start, len)
        .with_line(line, column);
    Finding::new(
        "RSTR-FLASK-002",
        "Flask `SECRET_KEY` assigned from a string literal; sessions, CSRF tokens, and signed URLs are all HMAC'd with this key, so anyone who reads the source (or the published artifact) can forge a session for any user including admin"
            .to_string(),
        Severity::High,
        Category::Security,
    )
    .with_help(
        "load the key from a secret store at startup: `app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']`. Generate a fresh value per environment (`python -c 'import secrets; print(secrets.token_hex(32))'`) and keep it out of git. Rotate when leaked; old sessions become invalid (acceptable trade-off)",
    )
    .with_location(location)
}

fn byte_offset_to_line_col(text: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in text.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::DiscoveredFile;
    use crate::fingerprint::{DetectedProject, Ecosystem, Language, ProjectFingerprint};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn aux() -> Option<&'static AuxPatterns> {
        compiled_aux_patterns().ok()
    }

    #[test]
    fn app_run_debug_true_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n";
        let findings = scan_debug_enabled(&PathBuf::from("app.py"), src, a);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-FLASK-001");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn app_run_debug_true_with_host_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0', port=5000, debug=True)\n";
        assert_eq!(
            scan_debug_enabled(&PathBuf::from("app.py"), src, a).len(),
            1
        );
    }

    #[test]
    fn app_run_debug_false_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)\n";
        assert!(scan_debug_enabled(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn app_run_no_debug_kwarg_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='127.0.0.1')\n";
        assert!(scan_debug_enabled(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn debug_from_env_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "import os\nfrom flask import Flask\napp = Flask(__name__)\napp.run(debug=os.environ.get('FLASK_DEBUG') == '1')\n";
        assert!(scan_debug_enabled(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn config_debug_true_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = True\n";
        let findings = scan_debug_enabled(&PathBuf::from("app.py"), src, a);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-FLASK-001");
    }

    #[test]
    fn config_debug_double_quoted_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.config[\"DEBUG\"] = True\n";
        assert_eq!(
            scan_debug_enabled(&PathBuf::from("app.py"), src, a).len(),
            1
        );
    }

    #[test]
    fn config_debug_false_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = False\n";
        assert!(scan_debug_enabled(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn attr_debug_true_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.debug = True\n";
        let findings = scan_debug_enabled(&PathBuf::from("app.py"), src, a);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn hardcoded_secret_key_config_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.config['SECRET_KEY'] = 'change-me-in-production'\n";
        let findings = scan_hardcoded_secret_key(&PathBuf::from("app.py"), src, a);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-FLASK-002");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn hardcoded_secret_key_attr_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "from flask import Flask\napp = Flask(__name__)\napp.secret_key = 'dev-secret-please-change'\n";
        let findings = scan_hardcoded_secret_key(&PathBuf::from("app.py"), src, a);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-FLASK-002");
    }

    #[test]
    fn secret_key_from_env_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "import os\nfrom flask import Flask\napp = Flask(__name__)\napp.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']\n";
        assert!(scan_hardcoded_secret_key(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn secret_key_from_env_get_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "import os\nfrom flask import Flask\napp = Flask(__name__)\napp.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', '')\n";
        assert!(scan_hardcoded_secret_key(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn secret_key_from_secrets_module_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "import secrets\nfrom flask import Flask\napp = Flask(__name__)\napp.config['SECRET_KEY'] = secrets.token_hex(32)\n";
        assert!(scan_hardcoded_secret_key(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn secret_key_from_fstring_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "import os\nfrom flask import Flask\napp = Flask(__name__)\nname = os.environ['NAME']\napp.config['SECRET_KEY'] = f\"derived-{name}\"\n";
        assert!(scan_hardcoded_secret_key(&PathBuf::from("app.py"), src, a).is_empty());
    }

    #[test]
    fn is_flask_app_file_requires_flask_import() {
        let Some(a) = aux() else {
            return;
        };
        assert!(is_flask_app_file(
            "from flask import Flask\napp = Flask(__name__)\n",
            a
        ));
        assert!(is_flask_app_file(
            "import flask\napp = flask.Flask(__name__)\n",
            a
        ));
        assert!(!is_flask_app_file(
            "from django.conf import settings\nDEBUG = True\n",
            a
        ));
    }

    fn fingerprint_with_flask(root: &str) -> ProjectFingerprint {
        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::Flask);
        let mut languages = BTreeSet::new();
        languages.insert(Language::Python);
        let mut ecosystems = BTreeSet::new();
        ecosystems.insert(Ecosystem::Pypi);
        ProjectFingerprint {
            languages,
            ecosystems,
            frameworks,
            projects: vec![DetectedProject {
                root: PathBuf::from(root),
                manifest: PathBuf::from(format!("{root}/pyproject.toml")),
                language: Language::Python,
                ecosystem: Some(Ecosystem::Pypi),
                frameworks: vec![Framework::Flask],
            }],
        }
    }

    #[test]
    fn wants_returns_false_when_no_flask_framework_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("myapp/app.py"),
                kind: FileKind::Source,
                size: None,
            }],
            ..Default::default()
        };
        assert!(!FlaskAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_when_flask_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("apps/api/app.py"),
                kind: FileKind::Source,
                size: None,
            }],
            fingerprint: fingerprint_with_flask("apps/api"),
            ..Default::default()
        };
        assert!(FlaskAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn analyze_emits_findings_only_inside_flask_project_roots() {
        let tmp = std::env::temp_dir().join(format!("rastray-flask-{}", std::process::id()));
        let api_dir = tmp.join("apps").join("api");
        let other_dir = tmp.join("apps").join("other");
        let _ = std::fs::create_dir_all(&api_dir);
        let _ = std::fs::create_dir_all(&other_dir);

        let app_src = "from flask import Flask\n\
                       app = Flask(__name__)\n\
                       app.config['SECRET_KEY'] = 'hardcoded-bad'\n\
                       app.run(debug=True)\n";
        let app_file = api_dir.join("app.py");
        let _ = std::fs::write(&app_file, app_src);

        let unrelated_src = "import os\nprint('hello')\n";
        let unrelated_file = api_dir.join("script.py");
        let _ = std::fs::write(&unrelated_file, unrelated_src);

        let other_app_src = app_src;
        let other_app_file = other_dir.join("app.py");
        let _ = std::fs::write(&other_app_file, other_app_src);

        let api_root = tmp.join("apps").join("api");
        let crawl = CrawlSummary {
            files: vec![
                DiscoveredFile {
                    path: app_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: unrelated_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: other_app_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
            ],
            skipped: 0,
            errors: vec![],
            fingerprint: fingerprint_with_flask(&api_root.to_string_lossy()),
        };

        let findings = FlaskAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&tmp);

        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(
            codes.contains(&"RSTR-FLASK-001"),
            "expected RSTR-FLASK-001, got {codes:?}"
        );
        assert!(
            codes.contains(&"RSTR-FLASK-002"),
            "expected RSTR-FLASK-002, got {codes:?}"
        );
        assert_eq!(
            findings.len(),
            2,
            "expected exactly 2 findings (both on the in-project app.py), got {findings:?}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.location.as_ref().is_some_and(|l| l.file == app_file)),
            "findings should be scoped to the Flask project's app.py only, got {findings:?}"
        );
    }
}
