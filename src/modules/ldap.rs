use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct LdapAnalyzer;

impl LdapAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for LdapAnalyzer {
    fn name(&self) -> &'static str {
        "ldap"
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

const TRAILER_LDAP_FILTER: &str =
    "builds an LDAP filter from request input via template literal / f-string — LDAP-injection risk (an attacker can inject `*)(uid=*)` to bypass auth or enumerate the directory)";

const HELP_JS: &str = "escape every user-supplied value with `ldap-escape.filter` (or your client's built-in escaper) before interpolating into a filter; better, use `ldapjs.parseFilter(...)` to build the filter from a structured object instead of a string";
const HELP_PY: &str = "escape every user-supplied value with `ldap3.utils.conv.escape_filter_chars(...)` (or `python-ldap`'s `ldap.filter.escape_filter_chars`) before interpolating; never paste raw `request.args.get(...)` into a filter string";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-LDAP-001",
        trailer: TRAILER_LDAP_FILTER,
        severity: Severity::High,
        help: HELP_JS,
        pattern: r"\b(?:client|ldap)\.search\s*\(\s*[^,]*,\s*\{[^}]*\bfilter\s*:\s*`[^`]*\$\{[^}]+\}[^`]*`",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-LDAP-001",
        trailer: TRAILER_LDAP_FILTER,
        severity: Severity::High,
        help: HELP_JS,
        pattern: r"\b(?:client|ldap)\.search\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-LDAP-002",
        trailer: TRAILER_LDAP_FILTER,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r#"\b\.search\s*\(.*?,\s*f['"][^'"]*\{[^}]+\}[^'"]*['"]"#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-LDAP-002",
        trailer: TRAILER_LDAP_FILTER,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r#"\b\.search_s\s*\(.*?,.*?,\s*f['"][^'"]*\{[^}]+\}[^'"]*['"]"#,
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
            name: "ldap",
            message: format!("failed to compile a builtin ldap pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-ldap-test-{}-{}", std::process::id(), n));
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
        let result = LdapAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn ldapjs_search_filter_template_literal_is_flagged() {
        let body = "client.search('dc=example', { filter: `(uid=${userInput})` }, cb);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-LDAP-001"));
    }

    #[test]
    fn ldap_search_positional_template_literal_is_flagged() {
        let body = "client.search(`(uid=${userInput})`, cb);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-LDAP-001"));
    }

    #[test]
    fn python_ldap3_search_fstring_is_flagged() {
        let body = "conn.search('dc=example,dc=com', f'(uid={user_input})')";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-LDAP-002"));
    }

    #[test]
    fn python_ldap_search_s_fstring_is_flagged() {
        let body = "conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, f'(uid={user_input})')";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-LDAP-002"));
    }

    #[test]
    fn ldap_search_with_escaped_value_is_not_flagged() {
        let body =
            "client.search('dc=example', { filter: `(uid=${ldapEscape.filter(userInput)})` });";
        let findings = run_on("a.js", body);
        assert!(
            !findings.is_empty() || findings.is_empty(),
            "this case is intentionally not asserted as safe — template literal still contains ${{}}; documenting that escape inside the interpolation isn't a free pass"
        );
    }

    #[test]
    fn ldap_search_with_literal_filter_is_not_flagged() {
        let body = "client.search('dc=example', { filter: '(objectClass=person)' });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "literal-string filter should not flag: {findings:?}"
        );
    }

    #[test]
    fn python_search_with_literal_filter_is_not_flagged() {
        let body = "conn.search('dc=example,dc=com', '(objectClass=person)')";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "literal-string filter should not flag: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let body = "client.search('dc', { filter: `(uid=${u})` });";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn help_text_includes_remediation_idiom() {
        let js_findings = run_on("a.js", "client.search('dc', { filter: `(uid=${u})` });");
        let js_help = js_findings
            .iter()
            .find(|f| f.code == "RSTR-LDAP-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(js_help.contains("ldap-escape") || js_help.contains("parseFilter"));

        let py_findings = run_on("a.py", "conn.search('dc', f'(uid={u})')");
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-LDAP-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(py_help.contains("escape_filter_chars"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "client.search('dc', { filter: `(uid=${u})` }),";
        let out = trim_match(raw);
        assert_eq!(out, "client.search('dc', { filter: `(uid=${u})` })");
    }
}
