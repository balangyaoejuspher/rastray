use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct WebappConfigAnalyzer;

impl WebappConfigAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for WebappConfigAnalyzer {
    fn name(&self) -> &'static str {
        "webapp_config"
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

const TRAILER_COOKIE_INSECURE: &str =
    "configures a session cookie without `secure: true` — cookie can be transmitted over plaintext HTTP and intercepted";
const TRAILER_COOKIE_NO_HTTPONLY: &str =
    "configures a session cookie without `httpOnly: true` — cookie is readable from client JavaScript and exploitable via XSS";
const TRAILER_COOKIE_SAMESITE_NONE: &str =
    "sets `sameSite: 'none'` without `secure: true` (browsers reject this combination) or with `secure: true` opens cross-site CSRF surface — only set `none` when third-party embedding is required";
const TRAILER_CORS_WILDCARD_CREDS: &str =
    "combines `origin: true` (or `*`) with `credentials: true` — the browser drops the wildcard and the request still succeeds against any origin, defeating SOP and enabling cross-site credential theft";
const TRAILER_CORS_HEADER_LITERAL: &str =
    "writes `Access-Control-Allow-Origin: *` while also setting `Access-Control-Allow-Credentials: true` — same browser-level vulnerability as the middleware form";
const TRAILER_CSRF_FLASK_DISABLED: &str =
    "disables Flask-WTF CSRF protection globally (`WTF_CSRF_ENABLED = False`) — every form POST becomes CSRF-able";
const TRAILER_CSRF_DJANGO_EXEMPT: &str =
    "applies `@csrf_exempt` to a state-changing view — that view is CSRF-able even though the rest of the project is protected";

const HELP_COOKIE: &str = "set `{ secure: true, httpOnly: true, sameSite: 'strict' }` (or `'lax'` if cross-site links must work); for express-session also set `cookie: { ... }` not `secure: 'auto'`; review at the per-cookie level — auth cookies should never have `secure: false`";
const HELP_CORS_JS: &str = "either drop `credentials: true` (most public APIs do not need credentialed cross-origin requests), or replace `origin: true` / `*` with an explicit allow-list of trusted origins: `cors({ origin: ['https://app.example.com'], credentials: true })`";
const HELP_CORS_HEADER: &str = "do not pair `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — the spec forbids it, browsers will reject, and any allow-list that responds dynamically per request must explicitly enumerate trusted origins";
const HELP_CSRF_FLASK: &str = "keep `WTF_CSRF_ENABLED = True` (the default) and use `{{ csrf_token() }}` in every form; if you genuinely need to disable per-route, use `@csrf.exempt` on the single view rather than disabling globally";
const HELP_CSRF_DJANGO: &str = "remove `@csrf_exempt` and let Django's middleware enforce the token; if the view receives webhooks from a known third party, verify the request signature instead of disabling CSRF protection";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-COOKIE-001",
        trailer: TRAILER_COOKIE_INSECURE,
        severity: Severity::High,
        help: HELP_COOKIE,
        pattern: r"\bcookie\s*:\s*\{[^}]*\bsecure\s*:\s*false\b",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-COOKIE-002",
        trailer: TRAILER_COOKIE_NO_HTTPONLY,
        severity: Severity::High,
        help: HELP_COOKIE,
        pattern: r"\bcookie\s*:\s*\{[^}]*\bhttpOnly\s*:\s*false\b",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-COOKIE-003",
        trailer: TRAILER_COOKIE_SAMESITE_NONE,
        severity: Severity::Medium,
        help: HELP_COOKIE,
        pattern: r#"\bsameSite\s*:\s*['"]none['"]"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CORS-001",
        trailer: TRAILER_CORS_WILDCARD_CREDS,
        severity: Severity::High,
        help: HELP_CORS_JS,
        pattern: r#"\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*(?:true|\*|['"]\*['"])[^}]*\bcredentials\s*:\s*true"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CORS-001",
        trailer: TRAILER_CORS_WILDCARD_CREDS,
        severity: Severity::High,
        help: HELP_CORS_JS,
        pattern: r#"\bcors\s*\(\s*\{[^}]*\bcredentials\s*:\s*true[^}]*\borigin\s*:\s*(?:true|\*|['"]\*['"])"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CORS-002",
        trailer: TRAILER_CORS_HEADER_LITERAL,
        severity: Severity::High,
        help: HELP_CORS_HEADER,
        pattern: r#"setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CSRF-001",
        trailer: TRAILER_CSRF_FLASK_DISABLED,
        severity: Severity::High,
        help: HELP_CSRF_FLASK,
        pattern: r#"(?:\bWTF_CSRF_ENABLED\s*=\s*False\b|\[\s*['"]WTF_CSRF_ENABLED['"]\s*\]\s*=\s*False\b)"#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CSRF-002",
        trailer: TRAILER_CSRF_DJANGO_EXEMPT,
        severity: Severity::Medium,
        help: HELP_CSRF_DJANGO,
        pattern: r"@csrf_exempt\b",
        extensions: PY_EXTENSIONS,
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
            name: "webapp_config",
            message: format!("failed to compile a builtin webapp-config pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-webcfg-test-{}-{}", std::process::id(), n));
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
        let result = WebappConfigAnalyzer::new()
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
    fn express_session_cookie_secure_false_is_flagged() {
        let body = "app.use(session({ cookie: { secure: false, httpOnly: true } }));";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-COOKIE-001"));
    }

    #[test]
    fn express_session_cookie_httponly_false_is_flagged() {
        let body = "app.use(session({ cookie: { secure: true, httpOnly: false } }));";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-COOKIE-002"));
    }

    #[test]
    fn samesite_none_string_is_flagged() {
        let body = "res.cookie('id', token, { sameSite: 'none', secure: true });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-COOKIE-003"));
    }

    #[test]
    fn cors_origin_true_with_credentials_is_flagged() {
        let body = "app.use(cors({ origin: true, credentials: true }));";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-CORS-001"));
    }

    #[test]
    fn cors_credentials_then_origin_wildcard_is_flagged() {
        let body = "app.use(cors({ credentials: true, origin: '*' }));";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-CORS-001"));
    }

    #[test]
    fn cors_header_wildcard_is_flagged() {
        let body = "res.setHeader('Access-Control-Allow-Origin', '*');";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-CORS-002"));
    }

    #[test]
    fn flask_csrf_disabled_globally_is_flagged() {
        let body = "app.config['WTF_CSRF_ENABLED'] = False";
        let findings = run_on("settings.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-CSRF-001"));
    }

    #[test]
    fn django_csrf_exempt_decorator_is_flagged() {
        let body = "from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef handler(request):\n    return HttpResponse('ok')";
        let findings = run_on("views.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-CSRF-002"));
    }

    #[test]
    fn cors_with_explicit_origin_allowlist_is_not_flagged() {
        let body = "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "explicit allow-list with credentials should not flag: {findings:?}"
        );
    }

    #[test]
    fn cors_wildcard_without_credentials_is_not_flagged() {
        let body = "app.use(cors({ origin: '*' }));";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "wildcard without credentials is the safe public-API case: {findings:?}"
        );
    }

    #[test]
    fn hardened_session_cookie_is_not_flagged() {
        let body =
            "app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'strict' } }));";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "hardened cookie should not flag: {findings:?}"
        );
    }

    #[test]
    fn flask_csrf_enabled_explicitly_is_not_flagged() {
        let body = "app.config['WTF_CSRF_ENABLED'] = True";
        let findings = run_on("settings.py", body);
        assert!(
            findings.is_empty(),
            "explicit True should not flag: {findings:?}"
        );
    }

    #[test]
    fn samesite_strict_string_is_not_flagged() {
        let body = "res.cookie('id', token, { sameSite: 'strict', secure: true });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "sameSite: 'strict' should not flag: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let body = "app.use(cors({ origin: true, credentials: true }));";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body = "app.use(cors({ origin: true, credentials: true }));\napp.use(cors({ credentials: true, origin: '*' }));";
        let findings = run_on("a.js", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        let unique: std::collections::HashSet<&str> = msgs.iter().copied().collect();
        assert!(!unique.is_empty());
    }

    #[test]
    fn help_text_includes_remediation_idiom() {
        let cors_findings = run_on(
            "a.js",
            "app.use(cors({ origin: true, credentials: true }));",
        );
        let cors_help = cors_findings
            .iter()
            .find(|f| f.code == "RSTR-CORS-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(cors_help.contains("allow-list") || cors_help.contains("credentials: true"));

        let flask_findings = run_on("settings.py", "app.config['WTF_CSRF_ENABLED'] = False");
        let flask_help = flask_findings
            .iter()
            .find(|f| f.code == "RSTR-CSRF-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(flask_help.contains("csrf_token") || flask_help.contains("WTF_CSRF_ENABLED"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "cors({ origin: true, credentials: true },";
        let out = trim_match(raw);
        assert_eq!(out, "cors({ origin: true, credentials: true })");
    }
}
