use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct JwtAnalyzer;

impl JwtAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for JwtAnalyzer {
    fn name(&self) -> &'static str {
        "jwt"
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

const TRAILER_ALG_NONE: &str =
    "accepts `alg: 'none'` (or the wildcard `algorithms: ['*']`) — an attacker can forge a token signed with the `none` algorithm and bypass authentication entirely";
const TRAILER_VERIFY_FALSE: &str =
    "skips signature verification (`verify: false` / `verify_signature: False`) — the token contents are taken at face value, defeating the whole point of JWT";
const TRAILER_HARDCODED_SECRET: &str =
    "uses a hardcoded HMAC secret in source — once the binary or repo leaks the secret leaks; rotate to an environment variable or a secret-manager fetch";
const TRAILER_MISSING_ALGORITHMS: &str =
    "verifies a token without passing an explicit `algorithms` list — accepts whatever algorithm the token header claims, enabling alg-confusion attacks (HS256 forgery using the RS256 public key)";

const HELP_JS: &str = "always pass an explicit `algorithms` list to `jwt.verify(...)` (e.g. `{ algorithms: ['RS256'] }`), never `'none'` or `'*'`; load the secret from `process.env.JWT_SECRET` rather than a string literal; the default `jsonwebtoken` config refuses `none` but `algorithms: ['none']` re-enables it explicitly";
const HELP_PY: &str = "always pass `algorithms=['RS256']` (or the specific algorithm you signed with) to `jwt.decode(...)`, never `['*']` or `['none']`; never set `options={'verify_signature': False}` on untrusted tokens; load the secret from `os.environ['JWT_SECRET']` not a string literal";
const HELP_GO: &str = "validate the token's signing method inside the keyfunc: `if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, errors.New(\"unexpected signing method\") }`; never return a secret without checking `token.Method`; load the secret from `os.Getenv(\"JWT_SECRET\")` not a string literal";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-JWT-001",
        trailer: TRAILER_ALG_NONE,
        severity: Severity::Critical,
        help: HELP_JS,
        pattern: r#"\balgorithms?\s*:\s*\[?\s*['"](?:none|\*)['"]"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-001",
        trailer: TRAILER_ALG_NONE,
        severity: Severity::Critical,
        help: HELP_PY,
        pattern: r#"\balgorithms\s*=\s*\[\s*['"](?:none|\*)['"]"#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-002",
        trailer: TRAILER_VERIFY_FALSE,
        severity: Severity::Critical,
        help: HELP_JS,
        pattern: r"\bjwt\.decode\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*\{[^}]*\bverify\s*:\s*false\b",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-002",
        trailer: TRAILER_VERIFY_FALSE,
        severity: Severity::Critical,
        help: HELP_PY,
        pattern: r#"\bverify_signature['"]\s*:\s*False\b"#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-002",
        trailer: TRAILER_VERIFY_FALSE,
        severity: Severity::Critical,
        help: HELP_PY,
        pattern: r"\bjwt\.decode\s*\([^)]*\bverify\s*=\s*False\b",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-003",
        trailer: TRAILER_HARDCODED_SECRET,
        severity: Severity::High,
        help: HELP_JS,
        pattern: r#"\bjwt\.sign\s*\(\s*[^,]+,\s*['"][A-Za-z0-9_\-+/=!@#$%^&*]{6,}['"]"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-003",
        trailer: TRAILER_HARDCODED_SECRET,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r#"\bjwt\.encode\s*\(\s*[^,]+,\s*['"][A-Za-z0-9_\-+/=!@#$%^&*]{6,}['"]"#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-004",
        trailer: TRAILER_MISSING_ALGORITHMS,
        severity: Severity::High,
        help: HELP_JS,
        pattern: r"\bjwt\.verify\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-004",
        trailer: TRAILER_MISSING_ALGORITHMS,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r"\bjwt\.decode\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-JWT-005",
        trailer: TRAILER_MISSING_ALGORITHMS,
        severity: Severity::High,
        help: HELP_GO,
        pattern: r"\bjwt\.Parse(?:WithClaims)?\s*\([\s\S]{1,400}?return\s+[A-Za-z_][A-Za-z0-9_.]*\s*,\s*nil",
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
            name: "jwt",
            message: format!("failed to compile a builtin jwt pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-jwt-test-{}-{}", std::process::id(), n));
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
        let result = JwtAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn js_alg_none_is_flagged_as_critical() {
        let body = "jwt.verify(token, secret, { algorithms: ['none'] });";
        let findings = run_on("a.js", body);
        let found = findings.iter().find(|f| f.code == "RSTR-JWT-001");
        assert!(found.is_some());
        if let Some(f) = found {
            assert_eq!(f.severity, Severity::Critical);
        }
    }

    #[test]
    fn js_alg_wildcard_is_flagged() {
        let body = "jwt.verify(token, secret, { algorithms: ['*'] });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-001"));
    }

    #[test]
    fn py_alg_none_is_flagged() {
        let body = "jwt.decode(token, key, algorithms=['none'])";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-001"));
    }

    #[test]
    fn js_verify_false_is_flagged() {
        let body = "const payload = jwt.decode(token, { verify: false });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-002"));
    }

    #[test]
    fn py_verify_signature_false_is_flagged() {
        let body = "claims = jwt.decode(token, options={'verify_signature': False})";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-002"));
    }

    #[test]
    fn py_verify_false_keyword_is_flagged() {
        let body = "claims = jwt.decode(token, key, verify=False)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-002"));
    }

    #[test]
    fn js_hardcoded_secret_in_sign_is_flagged() {
        let body = "const t = jwt.sign(payload, 'mySuperSecret123');";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-003"));
    }

    #[test]
    fn py_hardcoded_secret_in_encode_is_flagged() {
        let body = "t = jwt.encode(payload, 'mySuperSecret123', algorithm='HS256')";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-003"));
    }

    #[test]
    fn js_verify_without_algorithms_is_flagged() {
        let body = "const payload = jwt.verify(token, secret);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-004"));
    }

    #[test]
    fn py_decode_without_algorithms_is_flagged() {
        let body = "claims = jwt.decode(token, key)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-004"));
    }

    #[test]
    fn go_jwt_parse_without_alg_check_is_flagged() {
        let body = "token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return mySecret, nil })";
        let findings = run_on("a.go", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-JWT-005"));
    }

    #[test]
    fn js_verify_with_algorithms_is_not_flagged() {
        let body = "const payload = jwt.verify(token, secret, { algorithms: ['RS256'] });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "explicit RS256 algorithms list is the hardened form: {findings:?}"
        );
    }

    #[test]
    fn py_decode_with_algorithms_is_not_flagged() {
        let body = "claims = jwt.decode(token, key, algorithms=['RS256'])";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "explicit algorithms list should not flag: {findings:?}"
        );
    }

    #[test]
    fn js_sign_with_env_var_secret_is_not_flagged() {
        let body = "const t = jwt.sign(payload, process.env.JWT_SECRET);";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "env var secret should not flag: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let body = "jwt.verify(token, secret, { algorithms: ['none'] });";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body = "jwt.verify(t1, s1);\njwt.verify(t2, s2);";
        let findings = run_on("a.js", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("jwt.verify(t1, s1)")));
        assert!(msgs.iter().any(|m| m.contains("jwt.verify(t2, s2)")));
    }

    #[test]
    fn help_text_includes_remediation_idiom() {
        let js_findings = run_on(
            "a.js",
            "jwt.verify(token, secret, { algorithms: ['none'] });",
        );
        let js_help = js_findings
            .iter()
            .find(|f| f.code == "RSTR-JWT-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(js_help.contains("algorithms") && js_help.contains("RS256"));

        let py_findings = run_on(
            "a.py",
            "claims = jwt.decode(token, options={'verify_signature': False})",
        );
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-JWT-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(py_help.contains("os.environ") || py_help.contains("algorithms"));

        let go_findings = run_on(
            "a.go",
            "token, err := jwt.Parse(s, func(t *jwt.Token) (interface{}, error) { return secret, nil })",
        );
        let go_help = go_findings
            .iter()
            .find(|f| f.code == "RSTR-JWT-005")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(go_help.contains("SigningMethodHMAC") || go_help.contains("token.Method"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "jwt.verify(token, secret),";
        let out = trim_match(raw);
        assert_eq!(out, "jwt.verify(token, secret)");
    }
}
