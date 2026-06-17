use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct RedosAnalyzer;

impl RedosAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for RedosAnalyzer {
    fn name(&self) -> &'static str {
        "redos"
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

const TRAILER_NESTED_QUANT: &str =
    "contains a nested quantifier of the form `(X+)+`, `(X*)+`, `(X+)*`, or similar — catastrophic backtracking risk: input crafted as `aaaa...aab` runs in exponential time and DoSes the engine";
const TRAILER_ALT_OVERLAP_QUANT: &str =
    "applies a quantifier to an alternation whose branches overlap (e.g. `(a|a)+`, `(ab|a)+`) — catastrophic backtracking risk, same exponential blow-up as nested quantifiers";

const HELP: &str = "rewrite using an atomic group, possessive quantifier, or character class instead of a nested quantifier (`(a+)+` → `a+`, `(?:[ab])+` instead of `(a|b)+`); validate input length BEFORE matching as a defence-in-depth measure; consider a linear-time regex engine (RE2 / re2-wasm / Rust's `regex` crate) for any pattern that touches user input";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-REDOS-001",
        trailer: TRAILER_NESTED_QUANT,
        severity: Severity::High,
        help: HELP,
        pattern: r"/[^/\n]*\([^()\n]*[+*]\)[+*][^/\n]*/[gimsuy]*",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-REDOS-001",
        trailer: TRAILER_NESTED_QUANT,
        severity: Severity::High,
        help: HELP,
        pattern: r#"\bnew\s+RegExp\s*\(\s*['"][^'"\n]*\([^()\n]*[+*]\)[+*][^'"\n]*['"]"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-REDOS-001",
        trailer: TRAILER_NESTED_QUANT,
        severity: Severity::High,
        help: HELP,
        pattern: r#"\bre\.(?:compile|match|search|fullmatch|findall|finditer|sub)\s*\(\s*[rRfF]?['"][^'"\n]*\([^()\n]*[+*]\)[+*][^'"\n]*['"]"#,
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
            name: "redos",
            message: format!("failed to compile a builtin redos pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-redos-test-{}-{}", std::process::id(), n));
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
        let result = RedosAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn js_regex_literal_nested_quantifier_is_flagged() {
        let body = "const re = /^(a+)+$/;";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-REDOS-001"));
    }

    #[test]
    fn js_regex_literal_star_inside_plus_is_flagged() {
        let body = "const re = /^(a*)+$/;";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-REDOS-001"));
    }

    #[test]
    fn js_new_regexp_string_nested_quantifier_is_flagged() {
        let body = "const re = new RegExp('^(a+)+$');";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-REDOS-001"));
    }

    #[test]
    fn python_re_compile_nested_quantifier_is_flagged() {
        let body = "import re\npat = re.compile(r'^(a+)+$')";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-REDOS-001"));
    }

    #[test]
    fn js_regex_literal_simple_plus_is_not_flagged() {
        let body = "const re = /^a+$/;";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "simple a+ should not flag: {findings:?}"
        );
    }

    #[test]
    fn js_regex_literal_anchored_charclass_is_not_flagged() {
        let body = "const re = /^[a-z0-9]+$/;";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "char class with single quantifier should not flag: {findings:?}"
        );
    }

    #[test]
    fn python_re_compile_simple_pattern_is_not_flagged() {
        let body = "import re\npat = re.compile(r'^[a-z]+$')";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "simple [a-z]+ should not flag: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let body = "const re = /^(a+)+$/;";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn help_text_includes_remediation_idiom() {
        let findings = run_on("a.js", "const re = /^(a+)+$/;");
        let help = findings
            .iter()
            .find(|f| f.code == "RSTR-REDOS-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(
            help.contains("RE2") || help.contains("atomic group") || help.contains("possessive")
        );
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "re.compile(r'^(a+)+$'),";
        let out = trim_match(raw);
        assert_eq!(out, "re.compile(r'^(a+)+$')");
    }
}
