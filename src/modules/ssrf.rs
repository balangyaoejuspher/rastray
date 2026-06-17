use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct SsrfAnalyzer;

impl SsrfAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for SsrfAnalyzer {
    fn name(&self) -> &'static str {
        "ssrf"
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

const SSRF_TRAILER: &str = "issues an HTTP request to a URL taken from request input — SSRF risk";

const SSRF_HELP_JS: &str = "validate the URL against an allow-list of permitted hosts (e.g. `new URL(input).hostname`) or route through a hardened server-side proxy; do not pass `req.body.*` / `req.query.*` / `req.params.*` directly to fetch/axios/http";

const SSRF_HELP_PY: &str = "validate against an allow-list of permitted hosts, or use a hardened proxy; block `localhost`, `127.0.0.1`, `0.0.0.0`, `169.254.169.254` (cloud metadata), and private CIDR ranges before issuing the request";

const SSRF_HELP_GO: &str = "validate the URL against an allow-list of permitted hosts before passing it to `http.Get` / `http.NewRequest`; block private CIDR ranges and `169.254.169.254`";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-SSRF-001",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_JS,
        pattern: r"\bfetch\s*\(\s*req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*[,)]",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSRF-001",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_JS,
        pattern: r"\baxios\s*(?:\.(?:get|post|put|patch|delete|head|options|request))?\s*\(\s*req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*[,)]",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSRF-002",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_JS,
        pattern: r"\b(?:http|https)\.(?:get|request)\s*\(\s*req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*[,)]",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSRF-003",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_PY,
        pattern: r"\brequests\.(?:get|post|put|patch|delete|head|options|request)\s*\(\s*request\.(?:args|form|json|values|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))\s*[,)]",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSRF-003",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_PY,
        pattern: r"\burllib\.request\.urlopen\s*\(\s*request\.(?:args|form|json|values|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))\s*[,)]",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSRF-003",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_PY,
        pattern: r"\burlopen\s*\(\s*request\.(?:args|form|json|values|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))\s*[,)]",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSRF-004",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_GO,
        pattern: r"\bhttp\.(?:Get|Head|Post|PostForm)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\.(?:FormValue|URL\.Query\(\)\.Get|PostFormValue)\s*\([^)]+\)\s*[,)]",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSRF-004",
        trailer: SSRF_TRAILER,
        severity: Severity::High,
        help: SSRF_HELP_GO,
        pattern: r"\bhttp\.NewRequest\s*\(\s*[^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\.(?:FormValue|URL\.Query\(\)\.Get|PostFormValue)\s*\([^)]+\)",
        extensions: GO_EXTENSIONS,
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
            name: "ssrf",
            message: format!("failed to compile a builtin ssrf pattern: {e}"),
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir() -> Option<std::path::PathBuf> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rastray-ssrf-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        match std::fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn analyze_source(name: &str, body: &str) -> Vec<Finding> {
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
        let result = SsrfAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn fetch_with_req_body_url_is_flagged() {
        let findings = analyze_source(
            "api.ts",
            "export async function proxy(req: Request) {\n  const r = await fetch(req.body.url);\n  return r;\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SSRF-001");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("`fetch(req.body.url)`"));
        assert!(findings[0].message.contains("SSRF risk"));
    }

    #[test]
    fn axios_get_with_req_query_is_flagged() {
        let findings = analyze_source(
            "api.js",
            "module.exports = async (req, res) => {\n  const r = await axios.get(req.query.next);\n};\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SSRF-001");
        assert!(findings[0].message.contains("`axios.get(req.query.next)`"));
    }

    #[test]
    fn http_get_with_req_params_is_flagged() {
        let findings = analyze_source(
            "proxy.ts",
            "import http from 'http';\nexport function go(req, res) {\n  http.get(req.params.target, (r) => r.pipe(res));\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SSRF-002");
        assert!(findings[0]
            .message
            .contains("`http.get(req.params.target)`"));
    }

    #[test]
    fn requests_get_with_flask_args_get_is_flagged() {
        let findings = analyze_source(
            "app.py",
            "from flask import request\nimport requests\n\n@app.route('/p')\ndef proxy():\n    return requests.get(request.args.get('url')).text\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SSRF-003");
        assert!(findings[0]
            .message
            .contains("`requests.get(request.args.get('url'))`"));
    }

    #[test]
    fn urlopen_with_flask_args_is_flagged() {
        let findings = analyze_source(
            "app.py",
            "from flask import request\nfrom urllib.request import urlopen\n\n@app.route('/p')\ndef proxy():\n    return urlopen(request.args.get('u')).read()\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SSRF-003");
    }

    #[test]
    fn go_http_get_with_form_value_is_flagged() {
        let findings = analyze_source(
            "handler.go",
            "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) {\n  resp, _ := http.Get(r.FormValue(\"u\"))\n  _ = resp\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SSRF-004");
        assert!(findings[0]
            .message
            .contains("`http.Get(r.FormValue(\"u\"))`"));
    }

    #[test]
    fn go_new_request_with_url_query_is_flagged() {
        let findings = analyze_source(
            "handler.go",
            "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) {\n  req, _ := http.NewRequest(\"GET\", r.URL.Query().Get(\"u\"), nil)\n  _ = req\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SSRF-004");
    }

    #[test]
    fn literal_url_is_not_flagged() {
        let findings = analyze_source(
            "api.ts",
            "const r = await fetch('https://api.example.com/data');\n",
        );
        assert!(findings.is_empty(), "literal URL must not fire SSRF");
    }

    #[test]
    fn fetch_with_validated_local_variable_is_not_flagged() {
        let findings = analyze_source(
            "api.ts",
            "const safeUrl = validate(req.body.url);\nconst r = await fetch(safeUrl);\n",
        );
        assert!(
            findings.is_empty(),
            "fetch on a local variable should not fire; user may have validated it"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let findings = analyze_source("readme.txt", "const r = await fetch(req.body.url);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let findings = analyze_source(
            "api.ts",
            "const a = await fetch(req.body.url);\nconst b = await fetch(req.query.target);\n",
        );
        assert_eq!(findings.len(), 2);
        assert_ne!(
            findings[0].message, findings[1].message,
            "messages should differ because the captured calls differ"
        );
        assert!(findings[0].message.contains("req.body.url"));
        assert!(findings[1].message.contains("req.query.target"));
    }

    #[test]
    fn help_text_includes_remediation_idiom_for_language() {
        let findings = analyze_source("api.ts", "const r = await fetch(req.body.url);\n");
        let help = findings[0].help.as_deref().unwrap_or("");
        assert!(help.contains("allow-list") && help.contains("fetch"));
    }

    #[test]
    fn trim_match_preserves_balanced_parens() {
        assert_eq!(trim_match("fetch(req.body.url)"), "fetch(req.body.url)");
        assert_eq!(trim_match("fetch(req.body.url),"), "fetch(req.body.url)");
        assert_eq!(
            trim_match("requests.get(request.args.get('u'))"),
            "requests.get(request.args.get('u'))"
        );
        assert_eq!(
            trim_match("requests.get(request.args.get('u')),"),
            "requests.get(request.args.get('u'))"
        );
    }
}
