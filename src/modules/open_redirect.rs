use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct OpenRedirectAnalyzer;

impl OpenRedirectAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for OpenRedirectAnalyzer {
    fn name(&self) -> &'static str {
        "open_redirect"
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let patterns = compiled_patterns()?;
        let mut findings = Vec::new();
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
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for pattern in patterns {
                if !pattern.extensions.iter().any(|e| *e == ext) {
                    continue;
                }
                for m in pattern.regex.find_iter(&contents) {
                    let matched = trim_match(m.as_str());
                    let message = format!("`{matched}` {trailer}", trailer = pattern.trailer);
                    let (line, column) = byte_offset_to_line_col(&contents, m.start());
                    let location = Location::file(file.path.clone())
                        .with_span(m.start(), m.len())
                        .with_line(line, column);
                    findings.push(
                        Finding::new(pattern.code, message, pattern.severity, Category::Security)
                            .with_help(pattern.help)
                            .with_location(location),
                    );
                }
            }
        }
        Ok(findings)
    }
}

struct PatternSpec {
    code: &'static str,
    trailer: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
    extensions: &'static [&'static str],
}

struct CompiledPattern {
    code: &'static str,
    trailer: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
    extensions: &'static [&'static str],
}

const JS_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PY_EXTENSIONS: &[&str] = &["py"];
const GO_EXTENSIONS: &[&str] = &["go"];
const RB_EXTENSIONS: &[&str] = &["rb"];

const TRAILER: &str =
    "redirects to a URL taken from request input — open-redirect risk (attacker can send victims to a phishing page on a trusted-looking link)";

const HELP_JS: &str = "validate the target against an allow-list of known-safe paths or full URLs before calling `res.redirect(...)`; if you only need to redirect within your own site, prefix with a single leading `/` and reject anything containing `://`, `\\\\`, or starting with `//`";

const HELP_PY: &str = "validate the target against an allow-list of known-safe paths; for Django, use `url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()})` before `redirect(...)` / `HttpResponseRedirect(...)`; for Flask, use `urllib.parse.urlparse` and reject anything with a `netloc`";

const HELP_GO: &str = "validate the target against an allow-list of known-safe paths before passing to `http.Redirect`; reject anything containing `://`, starting with `//`, or with a non-empty `Host` after `url.Parse`";

const HELP_RB: &str = "validate the target against an allow-list of safe paths before `redirect_to`; for purely internal redirects, use a named route helper (`dashboard_path`) and never pass `params[...]` directly; Rails' default ForbiddenError on cross-origin redirects helps but does not cover same-origin phishing";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-RDR-001",
        trailer: TRAILER,
        severity: Severity::Medium,
        help: HELP_JS,
        pattern: r"\bres\.redirect\s*\(\s*(?:[0-9]+\s*,\s*)?req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*\)",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-RDR-002",
        trailer: TRAILER,
        severity: Severity::Medium,
        help: HELP_PY,
        pattern: r"\bredirect\s*\(\s*request\.(?:args|form|values|cookies|headers|GET|POST)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))\s*\)",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-RDR-002",
        trailer: TRAILER,
        severity: Severity::Medium,
        help: HELP_PY,
        pattern: r"\bHttpResponseRedirect\s*\(\s*request\.(?:GET|POST|COOKIES|META|args|form|values|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))\s*\)",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-RDR-003",
        trailer: TRAILER,
        severity: Severity::Medium,
        help: HELP_GO,
        pattern: r"\bhttp\.Redirect\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\.(?:FormValue|PostFormValue|URL\.Query\(\)\.Get)\s*\([^)]+\)\s*,",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-RDR-004",
        trailer: TRAILER,
        severity: Severity::Medium,
        help: HELP_RB,
        pattern: r"\bredirect_to\s+params\[\s*:?[A-Za-z_][A-Za-z0-9_]*\s*\]",
        extensions: RB_EXTENSIONS,
    },
];

static PATTERNS: OnceLock<Result<Vec<CompiledPattern>, regex::Error>> = OnceLock::new();

fn compiled_patterns() -> Result<&'static [CompiledPattern], AnalyzerError> {
    let cached = PATTERNS.get_or_init(|| {
        PATTERN_SPECS
            .iter()
            .map(|spec| {
                Regex::new(spec.pattern).map(|regex| CompiledPattern {
                    code: spec.code,
                    trailer: spec.trailer,
                    severity: spec.severity,
                    help: spec.help,
                    regex,
                    extensions: spec.extensions,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    });
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(AnalyzerError::Failed {
            name: "open_redirect",
            message: format!("failed to compile a builtin open-redirect pattern: {e}"),
        }),
    }
}

fn trim_match(raw: &str) -> String {
    let trimmed = raw.trim_end_matches([',', ' ', '\t']);
    let trimmed = if let Some(stripped) = trimmed.strip_suffix(')') {
        stripped
    } else {
        trimmed
    };
    let mut out = trimmed.to_string();
    let open = out.matches('(').count();
    let close = out.matches(')').count();
    for _ in 0..open.saturating_sub(close) {
        out.push(')');
    }
    out
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
    use crate::crawler::{CrawlSummary, DiscoveredFile, FileKind};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir() -> Option<PathBuf> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rastray-rdr-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        match std::fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn run_on(name: &str, body: &str) -> Vec<Finding> {
        let Some(dir) = tempdir() else {
            return Vec::new();
        };
        let path = dir.join(name);
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(body.as_bytes());
        }
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: path.clone(),
                kind: FileKind::Source,
                size: Some(body.len() as u64),
            }],
            skipped: 0,
            errors: vec![],
            fingerprint: Default::default(),
        };
        let result = OpenRedirectAnalyzer::new()
            .analyze(&crawl)
            .unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn express_res_redirect_with_req_query_is_flagged() {
        let body = "app.get('/go', (req, res) => { res.redirect(req.query.next); });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-RDR-001"));
    }

    #[test]
    fn express_res_redirect_with_status_and_req_body_is_flagged() {
        let body = "app.post('/go', (req, res) => { res.redirect(302, req.body.url); });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-RDR-001"));
    }

    #[test]
    fn flask_redirect_with_request_args_get_is_flagged() {
        let body = "from flask import redirect, request\n@app.route('/go')\ndef go():\n    return redirect(request.args.get('next'))";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-RDR-002"));
    }

    #[test]
    fn django_httpresponseredirect_with_request_get_is_flagged() {
        let body = "def go(request):\n    return HttpResponseRedirect(request.GET.get('next'))";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-RDR-002"));
    }

    #[test]
    fn go_http_redirect_with_form_value_is_flagged() {
        let body = "func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.FormValue(\"next\"), 302) }";
        let findings = run_on("a.go", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-RDR-003"));
    }

    #[test]
    fn go_http_redirect_with_query_get_is_flagged() {
        let body = "func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.URL.Query().Get(\"next\"), http.StatusFound) }";
        let findings = run_on("a.go", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-RDR-003"));
    }

    #[test]
    fn literal_redirect_target_is_not_flagged() {
        let body = "app.get('/go', (req, res) => { res.redirect('/dashboard'); });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "literal target should not flag: {findings:?}"
        );
    }

    #[test]
    fn url_for_redirect_target_is_not_flagged() {
        let body = "from flask import redirect, url_for\n@app.route('/go')\ndef go():\n    return redirect(url_for('home'))";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "url_for target should not flag: {findings:?}"
        );
    }

    #[test]
    fn intermediate_variable_is_not_flagged() {
        let body = "const next = req.query.next; res.redirect(next);";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "indirect flow is taint analysis territory, not regex: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let body = "res.redirect(req.query.next);";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body = "res.redirect(req.query.next);\nres.redirect(req.body.dest);";
        let findings = run_on("a.js", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("req.query.next")));
        assert!(msgs.iter().any(|m| m.contains("req.body.dest")));
        let unique: std::collections::HashSet<&str> = msgs.iter().copied().collect();
        assert_eq!(
            unique.len(),
            msgs.len(),
            "each finding should have a distinct message: {msgs:?}"
        );
    }

    #[test]
    fn help_text_includes_remediation_idiom_for_language() {
        let js_findings = run_on("a.js", "res.redirect(req.query.next);");
        let js_help = js_findings
            .iter()
            .find(|f| f.code == "RSTR-RDR-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(js_help.contains("allow-list") && js_help.contains("res.redirect"));

        let py_findings = run_on(
            "a.py",
            "def go(request):\n    return HttpResponseRedirect(request.GET.get('next'))",
        );
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-RDR-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(
            py_help.contains("url_has_allowed_host_and_scheme") || py_help.contains("urlparse")
        );

        let go_findings = run_on(
            "a.go",
            "func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.FormValue(\"n\"), 302) }",
        );
        let go_help = go_findings
            .iter()
            .find(|f| f.code == "RSTR-RDR-003")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(go_help.contains("allow-list") && go_help.contains("http.Redirect"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "res.redirect(req.query.next),";
        let out = trim_match(raw);
        assert_eq!(out, "res.redirect(req.query.next)");
    }

    #[test]
    fn rails_redirect_to_params_matches() {
        let body = r#"def callback
  redirect_to params[:next]
end"#;
        let findings = run_on("a.rb", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-RDR-004"));
    }

    #[test]
    fn rails_redirect_to_named_route_not_flagged() {
        let body = r#"def callback
  redirect_to dashboard_path
end"#;
        let findings = run_on("a.rb", body);
        assert!(!findings.iter().any(|f| f.code == "RSTR-RDR-004"));
    }
}
