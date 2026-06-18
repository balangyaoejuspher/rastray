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
pub struct DjangoAnalyzer;

impl DjangoAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for DjangoAnalyzer {
    fn name(&self) -> &'static str {
        "django"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl.fingerprint.frameworks.contains(&Framework::Django)
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let aux = compiled_aux_patterns()?;
        let mut findings = Vec::new();
        let project_roots: Vec<PathBuf> = crawl
            .fingerprint
            .projects
            .iter()
            .filter(|p| p.frameworks.contains(&Framework::Django))
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
            if !is_django_settings_file(&file.path, &contents, aux) {
                continue;
            }
            if let Some(finding) = scan_debug_true(&file.path, &contents, aux) {
                findings.push(finding);
            }
            if let Some(finding) = scan_wildcard_allowed_hosts(&file.path, &contents, aux) {
                findings.push(finding);
            }
        }
        Ok(findings)
    }
}

struct AuxPatterns {
    debug_true: Regex,
    wildcard_allowed_hosts: Regex,
    installed_apps_marker: Regex,
    middleware_marker: Regex,
}

fn compiled_aux_patterns() -> Result<&'static AuxPatterns, AnalyzerError> {
    static CACHE: OnceLock<Result<AuxPatterns, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let debug_true =
            Regex::new(r"(?m)^\s*DEBUG\s*=\s*True\b").map_err(|e| format!("debug_true: {e}"))?;
        let wildcard_allowed_hosts =
            Regex::new(r#"(?m)^\s*ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*(?:,\s*)?\]"#)
                .map_err(|e| format!("wildcard_allowed_hosts: {e}"))?;
        let installed_apps_marker = Regex::new(r"(?m)^\s*INSTALLED_APPS\s*=")
            .map_err(|e| format!("installed_apps_marker: {e}"))?;
        let middleware_marker =
            Regex::new(r"(?m)^\s*MIDDLEWARE\s*=").map_err(|e| format!("middleware_marker: {e}"))?;
        Ok(AuxPatterns {
            debug_true,
            wildcard_allowed_hosts,
            installed_apps_marker,
            middleware_marker,
        })
    });
    match cached {
        Ok(p) => Ok(p),
        Err(e) => Err(AnalyzerError::Failed {
            name: "django",
            message: format!("failed to compile a builtin django aux pattern: {e}"),
        }),
    }
}

fn is_django_settings_file(path: &std::path::Path, contents: &str, aux: &AuxPatterns) -> bool {
    let normalised = path.to_string_lossy().replace('\\', "/").to_lowercase();
    let basename_is_settings = normalised.rsplit('/').next().is_some_and(|name| {
        name == "settings.py" || name == "base.py" || name == "production.py" || name == "prod.py"
    });
    let in_settings_dir = normalised.contains("/settings/");
    if !(basename_is_settings || in_settings_dir) {
        return false;
    }
    aux.installed_apps_marker.is_match(contents) || aux.middleware_marker.is_match(contents)
}

fn scan_debug_true(path: &std::path::Path, contents: &str, aux: &AuxPatterns) -> Option<Finding> {
    let m = aux.debug_true.find(contents)?;
    let (line, column) = byte_offset_to_line_col(contents, m.start());
    let location = Location::file(path.to_path_buf())
        .with_span(m.start(), m.len())
        .with_line(line, column);
    Some(
        Finding::new(
            "RSTR-DJANGO-001",
            "Django settings file declares `DEBUG = True`; shipping this to production exposes full stack traces with environment variables, SECRET_KEY, database credentials, and template source"
                .to_string(),
            Severity::High,
            Category::Security,
        )
        .with_help(
            "drive DEBUG from the environment with an explicit false-by-default: `DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'`. Keep `DEBUG = True` only in a dev-only settings module (`settings/dev.py`) that is never imported by production",
        )
        .with_location(location),
    )
}

fn scan_wildcard_allowed_hosts(
    path: &std::path::Path,
    contents: &str,
    aux: &AuxPatterns,
) -> Option<Finding> {
    let m = aux.wildcard_allowed_hosts.find(contents)?;
    let (line, column) = byte_offset_to_line_col(contents, m.start());
    let location = Location::file(path.to_path_buf())
        .with_span(m.start(), m.len())
        .with_line(line, column);
    Some(
        Finding::new(
            "RSTR-DJANGO-002",
            "Django settings file declares `ALLOWED_HOSTS = ['*']`; accepts the HTTP Host header from any caller, enabling cache poisoning, password-reset link poisoning, and SSRF via host-relative URLs in emails"
                .to_string(),
            Severity::Critical,
            Category::Security,
        )
        .with_help(
            "set `ALLOWED_HOSTS` to your real production domains: `ALLOWED_HOSTS = ['app.example.com', 'admin.example.com']`. Drive from the environment if the list varies per deployment: `ALLOWED_HOSTS = os.environ['ALLOWED_HOSTS'].split(',')`. Never ship `['*']` to production",
        )
        .with_location(location),
    )
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
    fn debug_true_in_settings_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "INSTALLED_APPS = []\nDEBUG = True\nALLOWED_HOSTS = ['app.example.com']\n";
        let finding = scan_debug_true(&PathBuf::from("settings.py"), src, a);
        assert!(finding.is_some());
        if let Some(f) = finding {
            assert_eq!(f.code, "RSTR-DJANGO-001");
        }
    }

    #[test]
    fn debug_false_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "INSTALLED_APPS = []\nDEBUG = False\nALLOWED_HOSTS = ['app.example.com']\n";
        assert!(scan_debug_true(&PathBuf::from("settings.py"), src, a).is_none());
    }

    #[test]
    fn debug_from_env_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'\n";
        assert!(scan_debug_true(&PathBuf::from("settings.py"), src, a).is_none());
    }

    #[test]
    fn wildcard_allowed_hosts_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "ALLOWED_HOSTS = ['*']\n";
        let finding = scan_wildcard_allowed_hosts(&PathBuf::from("settings.py"), src, a);
        assert!(finding.is_some());
        if let Some(f) = finding {
            assert_eq!(f.code, "RSTR-DJANGO-002");
            assert_eq!(f.severity, Severity::Critical);
        }
    }

    #[test]
    fn wildcard_allowed_hosts_double_quoted_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = "ALLOWED_HOSTS = [\"*\"]\n";
        assert!(scan_wildcard_allowed_hosts(&PathBuf::from("settings.py"), src, a).is_some());
    }

    #[test]
    fn explicit_hosts_are_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = "ALLOWED_HOSTS = ['app.example.com', 'admin.example.com']\n";
        assert!(scan_wildcard_allowed_hosts(&PathBuf::from("settings.py"), src, a).is_none());
    }

    #[test]
    fn is_django_settings_file_recognises_basename_settings_py() {
        let Some(a) = aux() else {
            return;
        };
        let src = "INSTALLED_APPS = [\n    'django.contrib.auth',\n]\n";
        assert!(is_django_settings_file(
            &PathBuf::from("myapp/settings.py"),
            src,
            a
        ));
    }

    #[test]
    fn is_django_settings_file_recognises_settings_dir_layout() {
        let Some(a) = aux() else {
            return;
        };
        let src = "MIDDLEWARE = []\n";
        assert!(is_django_settings_file(
            &PathBuf::from("myapp/settings/production.py"),
            src,
            a
        ));
    }

    #[test]
    fn is_django_settings_file_rejects_random_python_file() {
        let Some(a) = aux() else {
            return;
        };
        let src = "DEBUG = True\n";
        assert!(!is_django_settings_file(
            &PathBuf::from("myapp/views.py"),
            src,
            a
        ));
    }

    #[test]
    fn is_django_settings_file_rejects_settings_py_without_django_markers() {
        let Some(a) = aux() else {
            return;
        };
        let src = "MY_CONSTANT = 1\n";
        assert!(!is_django_settings_file(
            &PathBuf::from("myapp/settings.py"),
            src,
            a
        ));
    }

    fn fingerprint_with_django(root: &str) -> ProjectFingerprint {
        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::Django);
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
                frameworks: vec![Framework::Django],
            }],
        }
    }

    #[test]
    fn wants_returns_false_when_no_django_framework_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("myapp/settings.py"),
                kind: FileKind::Source,
                size: None,
            }],
            ..Default::default()
        };
        assert!(!DjangoAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_when_django_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("apps/api/myapp/settings.py"),
                kind: FileKind::Source,
                size: None,
            }],
            fingerprint: fingerprint_with_django("apps/api"),
            ..Default::default()
        };
        assert!(DjangoAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn analyze_emits_findings_only_for_django_settings_files_inside_project_root() {
        let tmp = std::env::temp_dir().join(format!("rastray-django-{}", std::process::id()));
        let api_dir = tmp.join("apps").join("api").join("myproject");
        let other_dir = tmp.join("apps").join("other");
        let _ = std::fs::create_dir_all(&api_dir);
        let _ = std::fs::create_dir_all(&other_dir);

        let settings_src = "INSTALLED_APPS = [\n    'django.contrib.auth',\n]\n\
                            MIDDLEWARE = []\n\
                            DEBUG = True\n\
                            ALLOWED_HOSTS = ['*']\n";
        let settings_file = api_dir.join("settings.py");
        let _ = std::fs::write(&settings_file, settings_src);

        let views_src = "DEBUG = True\nALLOWED_HOSTS = ['*']\n";
        let views_file = api_dir.join("views.py");
        let _ = std::fs::write(&views_file, views_src);

        let other_settings_src = settings_src;
        let other_settings_file = other_dir.join("settings.py");
        let _ = std::fs::write(&other_settings_file, other_settings_src);

        let api_root = tmp.join("apps").join("api");
        let crawl = CrawlSummary {
            files: vec![
                DiscoveredFile {
                    path: settings_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: views_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: other_settings_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
            ],
            skipped: 0,
            errors: vec![],
            fingerprint: fingerprint_with_django(&api_root.to_string_lossy()),
        };

        let findings = DjangoAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&tmp);

        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(
            codes.contains(&"RSTR-DJANGO-001"),
            "expected RSTR-DJANGO-001, got {codes:?}"
        );
        assert!(
            codes.contains(&"RSTR-DJANGO-002"),
            "expected RSTR-DJANGO-002, got {codes:?}"
        );
        assert_eq!(
            findings.len(),
            2,
            "expected exactly 2 findings (both on the in-project settings.py only), got {findings:?}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.location.as_ref().is_some_and(|l| l.file == settings_file)),
            "findings should be scoped to the Django project's settings.py only, got {findings:?}"
        );
    }
}
