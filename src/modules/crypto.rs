use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct CryptoAnalyzer;

impl CryptoAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for CryptoAnalyzer {
    fn name(&self) -> &'static str {
        "crypto"
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
                    let (line, column) = byte_offset_to_line_col(&contents, m.start());
                    let location = Location::file(file.path.clone())
                        .with_span(m.start(), m.len())
                        .with_line(line, column);
                    findings.push(
                        Finding::new(
                            pattern.code,
                            pattern.message.to_string(),
                            pattern.severity,
                            Category::Security,
                        )
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
    message: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
    extensions: &'static [&'static str],
}

struct CompiledPattern {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
    extensions: &'static [&'static str],
}

const JS_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PY_EXTENSIONS: &[&str] = &["py"];
const JAVA_EXTENSIONS: &[&str] = &["java", "kt", "kts"];
const GO_EXTENSIONS: &[&str] = &["go"];
const RUST_EXTENSIONS: &[&str] = &["rs"];

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-CRY-001",
        message: "MD5 used for hashing; vulnerable to collisions, do not use for security",
        severity: Severity::High,
        help: "replace MD5 with SHA-256 (or SHA-3) from a vetted crypto library",
        pattern: r"\bhashlib\.md5\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-001",
        message: "MD5 used for hashing; vulnerable to collisions, do not use for security",
        severity: Severity::High,
        help: "replace MD5 with SHA-256 (or SHA-3) from a vetted crypto library",
        pattern: r#"crypto\.createHash\s*\(\s*["']md5["']\s*\)"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-001",
        message: "MD5 used for hashing; vulnerable to collisions, do not use for security",
        severity: Severity::High,
        help: "replace MD5 with SHA-256 (or SHA-3) from a vetted crypto library",
        pattern: r#"MessageDigest\.getInstance\s*\(\s*"MD5""#,
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-001",
        message: "MD5 used for hashing; vulnerable to collisions, do not use for security",
        severity: Severity::High,
        help: "replace MD5 with SHA-256 (or SHA-3) from a vetted crypto library",
        pattern: r"\bmd5\.New\s*\(\s*\)",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-002",
        message: "SHA-1 used for hashing; broken against collision attacks (SHAttered)",
        severity: Severity::High,
        help: "replace SHA-1 with SHA-256 (or SHA-3)",
        pattern: r"\bhashlib\.sha1\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-002",
        message: "SHA-1 used for hashing; broken against collision attacks (SHAttered)",
        severity: Severity::High,
        help: "replace SHA-1 with SHA-256 (or SHA-3)",
        pattern: r#"crypto\.createHash\s*\(\s*["']sha1["']\s*\)"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-002",
        message: "SHA-1 used for hashing; broken against collision attacks (SHAttered)",
        severity: Severity::High,
        help: "replace SHA-1 with SHA-256 (or SHA-3)",
        pattern: r#"MessageDigest\.getInstance\s*\(\s*"SHA-?1""#,
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-002",
        message: "SHA-1 used for hashing; broken against collision attacks (SHAttered)",
        severity: Severity::High,
        help: "replace SHA-1 with SHA-256 (or SHA-3)",
        pattern: r"\bsha1\.New\s*\(\s*\)",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-003",
        message: "DES/3DES cipher used; both are deprecated for new code",
        severity: Severity::High,
        help: "use AES-GCM (or ChaCha20-Poly1305) via a vetted library",
        pattern: r#"Cipher\.getInstance\s*\(\s*"(?i)(des|3des|desede)"#,
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-003",
        message: "DES/3DES cipher used; both are deprecated for new code",
        severity: Severity::High,
        help: "use AES-GCM (or ChaCha20-Poly1305) via a vetted library",
        pattern: r"\b(DES|TripleDES)\.new\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-003",
        message: "DES/3DES cipher used; both are deprecated for new code",
        severity: Severity::High,
        help: "use AES-GCM (or ChaCha20-Poly1305) via a vetted library",
        pattern: r"\bdes\.NewCipher\s*\(",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-004",
        message: "ECB cipher mode used; leaks plaintext patterns regardless of cipher",
        severity: Severity::High,
        help: "use an authenticated mode like GCM, or at minimum CBC with a random IV",
        pattern: r#"Cipher\.getInstance\s*\(\s*"[A-Z]+/ECB"#,
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-004",
        message: "ECB cipher mode used; leaks plaintext patterns regardless of cipher",
        severity: Severity::High,
        help: "use an authenticated mode like GCM, or at minimum CBC with a random IV",
        pattern: r"\bMODE_ECB\b",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-005",
        message: "Math.random() is not cryptographically secure; do not use for tokens, secrets, or IDs",
        severity: Severity::Medium,
        help: "use crypto.randomBytes() / crypto.getRandomValues() instead",
        pattern: r"\bMath\.random\s*\(\s*\)",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-006",
        message: "random module is not cryptographically secure; do not use for tokens or secrets",
        severity: Severity::Medium,
        help: "use the secrets module (e.g. secrets.token_hex, secrets.token_urlsafe) instead",
        pattern: r"\brandom\.(random|randint|choice|getrandbits)\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-006",
        message: "math/rand is not cryptographically secure; do not use for tokens or secrets",
        severity: Severity::Medium,
        help: "use crypto/rand instead",
        pattern: r#"\bmath/rand\b|"math/rand""#,
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-CRY-007",
        message: "rand crate's thread_rng() is not cryptographically secure; do not use for tokens or keys",
        severity: Severity::Medium,
        help: "use rand::rngs::OsRng (or getrandom directly) instead",
        pattern: r"\bthread_rng\s*\(\s*\)",
        extensions: RUST_EXTENSIONS,
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
                    message: spec.message,
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
            name: "crypto",
            message: format!("failed to compile a builtin crypto pattern: {e}"),
        }),
    }
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

    #[test]
    fn compiled_patterns_compile_cleanly() {
        let result = compiled_patterns();
        assert!(result.is_ok());
    }

    #[test]
    fn md5_python_call_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let py_md5 = patterns
            .iter()
            .find(|p| p.code == "RSTR-CRY-001" && p.extensions.contains(&"py"))
            .map(|p| &p.regex);
        let Some(re) = py_md5 else { return };
        assert!(re.is_match("h = hashlib.md5(data)"));
        assert!(re.is_match("hashlib.md5 ( raw )"));
        assert!(!re.is_match("hashlib.sha256(data)"));
    }

    #[test]
    fn sha1_js_create_hash_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let js_sha1 = patterns
            .iter()
            .find(|p| p.code == "RSTR-CRY-002" && p.extensions.contains(&"js"))
            .map(|p| &p.regex);
        let Some(re) = js_sha1 else { return };
        assert!(re.is_match("crypto.createHash('sha1')"));
        assert!(re.is_match("crypto.createHash(\"sha1\")"));
        assert!(!re.is_match("crypto.createHash('sha256')"));
    }

    #[test]
    fn ecb_mode_java_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let java_ecb = patterns
            .iter()
            .find(|p| p.code == "RSTR-CRY-004" && p.extensions.contains(&"java"))
            .map(|p| &p.regex);
        let Some(re) = java_ecb else { return };
        assert!(re.is_match(r#"Cipher.getInstance("AES/ECB/PKCS5Padding")"#));
        assert!(re.is_match(r#"Cipher.getInstance("DES/ECB/NoPadding")"#));
        assert!(!re.is_match(r#"Cipher.getInstance("AES/GCM/NoPadding")"#));
    }

    #[test]
    fn math_random_js_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let js_mr = patterns
            .iter()
            .find(|p| p.code == "RSTR-CRY-005")
            .map(|p| &p.regex);
        let Some(re) = js_mr else { return };
        assert!(re.is_match("const token = Math.random()"));
        assert!(re.is_match("Math.random ( )"));
        assert!(!re.is_match("crypto.randomBytes(16)"));
    }

    #[test]
    fn python_random_module_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let py_rand = patterns
            .iter()
            .find(|p| p.code == "RSTR-CRY-006" && p.extensions.contains(&"py"))
            .map(|p| &p.regex);
        let Some(re) = py_rand else { return };
        assert!(re.is_match("random.random()"));
        assert!(re.is_match("random.randint(0, 100)"));
        assert!(re.is_match("random.choice(items)"));
        assert!(!re.is_match("secrets.token_hex(32)"));
    }

    #[test]
    fn byte_offset_to_line_col_handles_newlines() {
        assert_eq!(byte_offset_to_line_col("abc\ndef", 0), (1, 1));
        assert_eq!(byte_offset_to_line_col("abc\ndef", 4), (2, 1));
        assert_eq!(byte_offset_to_line_col("abc\ndef", 6), (2, 3));
    }
}
