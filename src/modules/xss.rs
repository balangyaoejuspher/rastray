use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct XssAnalyzer;

impl XssAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for XssAnalyzer {
    fn name(&self) -> &'static str {
        "xss"
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
const PHP_EXTENSIONS: &[&str] = &["php"];

const TRAILER_REFLECTED: &str = "writes request input into the HTTP response — reflected XSS risk";
const TRAILER_DOM_INNER_HTML: &str =
    "assigns location/document data into innerHTML/outerHTML — DOM-based XSS risk";
const TRAILER_DOM_WRITE: &str =
    "passes location/document data to document.write — DOM-based XSS risk";

const HELP_JS_REFLECTED: &str = "HTML-escape the value (e.g. `he.encode(x)`) or send JSON via `res.json(...)` instead; never echo `req.body.*` / `req.query.*` / `req.params.*` directly into the response body";

const HELP_JS_DOM: &str = "use `.textContent` instead of `.innerHTML`, or sanitize with DOMPurify before assignment; never feed `location.*` / `window.name` / `document.URL` / `document.cookie` / `document.referrer` into `innerHTML` / `outerHTML` / `document.write`";

const HELP_PY: &str = "render via an auto-escaping template (Jinja2 with `autoescape=True`) or HTML-escape with `markupsafe.escape(...)`; never return `request.args.get(...)` / `request.form[...]` raw and never wrap user input in `Markup(...)`";

const HELP_GO: &str = "HTML-escape with `html.EscapeString(...)` or render via `html/template`; never write `r.FormValue(...)` / `r.URL.Query().Get(...)` raw into the response";

const HELP_PHP: &str = "HTML-escape with `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')` before echo/print; never write `$_GET[...]` / `$_POST[...]` / `$_REQUEST[...]` raw into the response";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-XSS-001",
        trailer: TRAILER_REFLECTED,
        severity: Severity::High,
        help: HELP_JS_REFLECTED,
        pattern: r"\bres\.(?:send|end|write)\s*\(\s*req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*[,)]",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-002",
        trailer: TRAILER_DOM_INNER_HTML,
        severity: Severity::High,
        help: HELP_JS_DOM,
        pattern: r"\.(?:innerHTML|outerHTML)\s*=\s*(?:location|window\.name|document\.(?:URL|cookie|referrer|baseURI|documentURI))(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-003",
        trailer: TRAILER_DOM_WRITE,
        severity: Severity::High,
        help: HELP_JS_DOM,
        pattern: r"\bdocument\.(?:write|writeln)\s*\(\s*(?:location|window\.name|document\.(?:URL|cookie|referrer|baseURI|documentURI))(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*[,)]",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-004",
        trailer: TRAILER_REFLECTED,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r"\bMarkup\s*\(\s*request\.(?:args|form|json|values|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))\s*\)",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-004",
        trailer: TRAILER_REFLECTED,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r"\breturn\s+request\.(?:args|form|values|cookies|headers)(?:\[[^\]]+\]|\.get\s*\([^)]+\))",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-005",
        trailer: TRAILER_REFLECTED,
        severity: Severity::High,
        help: HELP_GO,
        pattern: r"\bfmt\.(?:Fprintf|Fprint|Fprintln)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,(?:[^,)]*,)*[^,)]*\b[a-zA-Z_][a-zA-Z0-9_]*\.(?:FormValue|PostFormValue|URL\.Query\(\)\.Get)\s*\([^)]+\)",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-005",
        trailer: TRAILER_REFLECTED,
        severity: Severity::High,
        help: HELP_GO,
        pattern: r"\bio\.WriteString\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\.(?:FormValue|PostFormValue|URL\.Query\(\)\.Get)\s*\([^)]+\)",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-006",
        trailer: TRAILER_REFLECTED,
        severity: Severity::High,
        help: HELP_PHP,
        pattern: r#"\b(?:echo|print)\s+[^(;]*\$_(?:GET|POST|REQUEST|COOKIE)\b"#,
        extensions: PHP_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XSS-006",
        trailer: TRAILER_REFLECTED,
        severity: Severity::High,
        help: HELP_PHP,
        pattern: r#"<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"#,
        extensions: PHP_EXTENSIONS,
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
            name: "xss",
            message: format!("failed to compile a builtin xss pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-xss-test-{}-{}", std::process::id(), n));
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
        };
        let result = XssAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn run_on_path(path: PathBuf, body: &str) -> Vec<Finding> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
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
        };
        let result = XssAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn express_res_send_with_req_body_is_flagged() {
        let body = "app.get('/x', (req, res) => { res.send(req.body.html); });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-001"));
    }

    #[test]
    fn express_res_end_with_req_query_is_flagged() {
        let body = "app.get('/x', (req, res) => { res.end(req.query.greeting); });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-001"));
    }

    #[test]
    fn inner_html_assigned_from_location_is_flagged() {
        let body = "document.getElementById('x').innerHTML = location.hash;";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-002"));
    }

    #[test]
    fn outer_html_assigned_from_document_cookie_is_flagged() {
        let body = "el.outerHTML = document.cookie;";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-002"));
    }

    #[test]
    fn document_write_with_location_is_flagged() {
        let body = "document.write(location.search);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-003"));
    }

    #[test]
    fn python_markup_wrap_of_request_is_flagged() {
        let body = "from flask import request\nfrom markupsafe import Markup\nx = Markup(request.args.get('name'))";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-004"));
    }

    #[test]
    fn python_return_request_args_get_is_flagged() {
        let body = "@app.route('/x')\ndef x():\n    return request.args.get('q')";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-004"));
    }

    #[test]
    fn go_fprintf_with_form_value_is_flagged() {
        let body = "func h(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, \"hello %s\", r.FormValue(\"name\")) }";
        let findings = run_on("a.go", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-005"));
    }

    #[test]
    fn go_io_writestring_with_query_get_is_flagged() {
        let body = "func h(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.URL.Query().Get(\"q\")) }";
        let findings = run_on("a.go", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-005"));
    }

    #[test]
    fn literal_html_response_is_not_flagged() {
        let body = "app.get('/x', (req, res) => { res.send('<h1>hi</h1>'); });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "literal HTML should not flag: {findings:?}"
        );
    }

    #[test]
    fn inner_html_with_constant_string_is_not_flagged() {
        let body = "el.innerHTML = '<b>hi</b>';";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "constant assignment should not flag: {findings:?}"
        );
    }

    #[test]
    fn intermediate_variable_is_not_flagged() {
        let body = "const x = req.body.html; res.send(x);";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "indirect flow is taint analysis territory, not regex: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let path = std::env::temp_dir().join(format!("rastray-xss-ext-{}.txt", std::process::id()));
        let body = "res.send(req.body.html);";
        let findings = run_on_path(path, body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body = "res.send(req.body.html);\nres.send(req.query.greeting);";
        let findings = run_on("a.js", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("req.body.html")));
        assert!(msgs.iter().any(|m| m.contains("req.query.greeting")));
        let unique: std::collections::HashSet<&str> = msgs.iter().copied().collect();
        assert_eq!(
            unique.len(),
            msgs.len(),
            "each finding should have a distinct message: {msgs:?}"
        );
    }

    #[test]
    fn help_text_includes_remediation_idiom_for_language() {
        let body_js = "el.innerHTML = location.hash;";
        let js_findings = run_on("a.js", body_js);
        let js_help = js_findings
            .iter()
            .find(|f| f.code == "RSTR-XSS-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(js_help.contains("DOMPurify") || js_help.contains("textContent"));

        let body_py = "from markupsafe import Markup\nfrom flask import request\nx = Markup(request.args.get('q'))";
        let py_findings = run_on("a.py", body_py);
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-XSS-004")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(py_help.contains("markupsafe.escape") || py_help.contains("Jinja2"));

        let body_go = "fmt.Fprintf(w, \"%s\", r.FormValue(\"n\"))";
        let go_findings = run_on("a.go", body_go);
        let go_help = go_findings
            .iter()
            .find(|f| f.code == "RSTR-XSS-005")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(go_help.contains("html.EscapeString") || go_help.contains("html/template"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "res.send(req.body.html,";
        let out = trim_match(raw);
        assert_eq!(out, "res.send(req.body.html)");
    }

    #[test]
    fn php_echo_request_input_matches() {
        let body = r#"<?php echo $_GET['name']; ?>"#;
        let findings = run_on("a.php", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-006"));
    }

    #[test]
    fn php_print_request_input_matches() {
        let body = r#"<?php print "Hello " . $_POST['name']; ?>"#;
        let findings = run_on("a.php", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-006"));
    }

    #[test]
    fn php_short_echo_request_input_matches() {
        let body = r#"<p><?= $_REQUEST['msg'] ?></p>"#;
        let findings = run_on("a.php", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XSS-006"));
    }

    #[test]
    fn php_echo_with_htmlspecialchars_not_flagged() {
        let body = r#"<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); ?>"#;
        let findings = run_on("a.php", body);
        let xss006 = findings.iter().any(|f| f.code == "RSTR-XSS-006");
        assert!(
            !xss006,
            "should not flag echo when htmlspecialchars is the only request-superglobal reference on the line"
        );
    }
}
