use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct SecretsAnalyzer;

impl SecretsAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for SecretsAnalyzer {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let patterns = compiled_patterns()?;
        let mut findings = Vec::new();
        for file in &crawl.files {
            if !is_scannable(file.kind) {
                continue;
            }
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for pattern in patterns {
                for m in pattern.regex.find_iter(&contents) {
                    if is_example_value(pattern.code, m.as_str()) {
                        continue;
                    }
                    if let Some(threshold) = pattern.min_entropy {
                        if shannon_entropy(m.as_str()) < threshold {
                            continue;
                        }
                    }
                    let (line, column) = byte_offset_to_line_col(&contents, m.start());
                    let location = Location::file(file.path.clone())
                        .with_span(m.start(), m.len())
                        .with_line(line, column);
                    findings.push(
                        Finding::new(
                            pattern.code,
                            format!("possible {} detected", pattern.name),
                            pattern.severity,
                            Category::Secret,
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

pub fn scan_text_for_secrets(
    contents: &str,
    synthetic_path: std::path::PathBuf,
) -> Result<Vec<Finding>, AnalyzerError> {
    let patterns = compiled_patterns()?;
    let mut findings = Vec::new();
    for pattern in patterns {
        for m in pattern.regex.find_iter(contents) {
            if is_example_value(pattern.code, m.as_str()) {
                continue;
            }
            if let Some(threshold) = pattern.min_entropy {
                if shannon_entropy(m.as_str()) < threshold {
                    continue;
                }
            }
            let (line, column) = byte_offset_to_line_col(contents, m.start());
            let location = Location::file(synthetic_path.clone())
                .with_span(m.start(), m.len())
                .with_line(line, column);
            findings.push(
                Finding::new(
                    pattern.code,
                    format!("possible {} detected", pattern.name),
                    pattern.severity,
                    Category::Secret,
                )
                .with_help(pattern.help)
                .with_location(location),
            );
        }
    }
    Ok(findings)
}

fn is_scannable(kind: FileKind) -> bool {
    matches!(
        kind,
        FileKind::Manifest | FileKind::Source | FileKind::Config
    )
}

fn is_example_value(code: &str, value: &str) -> bool {
    let allowlist = match code {
        "RSTR-SEC-001" => AWS_ACCESS_KEY_EXAMPLES,
        _ => return false,
    };
    allowlist.contains(&value)
}

const AWS_ACCESS_KEY_EXAMPLES: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAIOSFODNN7EXAMPLF",
    "AKIA1234567890ABCDEF",
];

struct PatternSpec {
    code: &'static str,
    name: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
    min_entropy: Option<f64>,
}

struct CompiledPattern {
    code: &'static str,
    name: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
    min_entropy: Option<f64>,
}

const DEFAULT_MIN_ENTROPY: f64 = 3.0;

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-SEC-001",
        name: "AWS access key ID",
        severity: Severity::Critical,
        help: "rotate the credential immediately and purge it from git history",
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
        min_entropy: Some(DEFAULT_MIN_ENTROPY),
    },
    PatternSpec {
        code: "RSTR-SEC-002",
        name: "GitHub personal access token",
        severity: Severity::High,
        help: "revoke the token at https://github.com/settings/tokens and rotate",
        pattern: r"\bghp_[0-9a-zA-Z]{36}\b",
        min_entropy: Some(DEFAULT_MIN_ENTROPY),
    },
    PatternSpec {
        code: "RSTR-SEC-003",
        name: "GitHub fine-grained personal access token",
        severity: Severity::High,
        help: "revoke the token at https://github.com/settings/tokens and rotate",
        pattern: r"\bgithub_pat_[0-9a-zA-Z_]{82}\b",
        min_entropy: Some(DEFAULT_MIN_ENTROPY),
    },
    PatternSpec {
        code: "RSTR-SEC-004",
        name: "Slack bot token",
        severity: Severity::High,
        help: "revoke at https://api.slack.com/apps and rotate",
        pattern: r"\bxoxb-[0-9]+-[0-9]+-[0-9a-zA-Z]+\b",
        min_entropy: Some(DEFAULT_MIN_ENTROPY),
    },
    PatternSpec {
        code: "RSTR-SEC-005",
        name: "Stripe live secret key",
        severity: Severity::Critical,
        help: "rotate the key in the Stripe dashboard and audit recent API usage",
        pattern: r"\bsk_live_[0-9a-zA-Z]{24,99}\b",
        min_entropy: Some(DEFAULT_MIN_ENTROPY),
    },
    PatternSpec {
        code: "RSTR-SEC-006",
        name: "Google API key",
        severity: Severity::High,
        help: "rotate the key in Google Cloud Console and audit recent usage",
        pattern: r"\bAIza[0-9A-Za-z_\-]{35}\b",
        min_entropy: Some(DEFAULT_MIN_ENTROPY),
    },
    PatternSpec {
        code: "RSTR-SEC-007",
        name: "PEM private key",
        severity: Severity::Critical,
        help: "remove the key from version control history and rotate immediately",
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----",
        min_entropy: None,
    },
    PatternSpec {
        code: "RSTR-SEC-008",
        name: "npm access token",
        severity: Severity::High,
        help: "revoke at https://www.npmjs.com/settings/<user>/tokens and rotate",
        pattern: r"\bnpm_[A-Za-z0-9]{36}\b",
        min_entropy: Some(DEFAULT_MIN_ENTROPY),
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
                    name: spec.name,
                    severity: spec.severity,
                    help: spec.help,
                    regex,
                    min_entropy: spec.min_entropy,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    });
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(AnalyzerError::Failed {
            name: "secrets",
            message: format!("failed to compile a builtin secret pattern: {e}"),
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

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for byte in s.bytes() {
        counts[byte as usize] = counts[byte as usize].saturating_add(1);
    }
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_offset_at_start_is_line_1_col_1() {
        assert_eq!(byte_offset_to_line_col("hello", 0), (1, 1));
    }

    #[test]
    fn byte_offset_advances_column_within_line() {
        assert_eq!(byte_offset_to_line_col("hello", 3), (1, 4));
    }

    #[test]
    fn byte_offset_after_newline_advances_line_resets_column() {
        let text = "ab\ncd";
        assert_eq!(byte_offset_to_line_col(text, 3), (2, 1));
        assert_eq!(byte_offset_to_line_col(text, 4), (2, 2));
    }

    #[test]
    fn byte_offset_handles_multiple_newlines() {
        let text = "a\nb\nc";
        assert_eq!(byte_offset_to_line_col(text, 4), (3, 1));
    }

    #[test]
    fn all_builtin_patterns_compile() {
        let result = compiled_patterns();
        assert!(result.is_ok());
        if let Ok(patterns) = result {
            assert_eq!(patterns.len(), PATTERN_SPECS.len());
            assert!(patterns.len() >= 8);
        }
    }

    #[test]
    fn aws_pattern_matches_canonical_example() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let aws = patterns.iter().find(|p| p.code == "RSTR-SEC-001");
        assert!(aws.is_some());
        if let Some(p) = aws {
            assert!(p.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
            assert!(!p.regex.is_match("AKIA"));
            assert!(!p.regex.is_match("akiaiosfodnn7example"));
        }
    }

    #[test]
    fn github_pat_pattern_distinguishes_classic_and_fine_grained() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let classic = patterns.iter().find(|p| p.code == "RSTR-SEC-002");
        let fine = patterns.iter().find(|p| p.code == "RSTR-SEC-003");
        assert!(classic.is_some());
        assert!(fine.is_some());
        if let (Some(c), Some(f)) = (classic, fine) {
            let classic_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
            assert!(c.regex.is_match(classic_token));
            assert!(!f.regex.is_match(classic_token));
        }
    }

    #[test]
    fn pem_private_key_marker_matches_common_variants() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let pem = patterns.iter().find(|p| p.code == "RSTR-SEC-007");
        assert!(pem.is_some());
        if let Some(p) = pem {
            assert!(p.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
            assert!(p.regex.is_match("-----BEGIN PRIVATE KEY-----"));
            assert!(p.regex.is_match("-----BEGIN EC PRIVATE KEY-----"));
            assert!(p.regex.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
        }
    }

    #[test]
    fn is_scannable_includes_manifest_source_config() {
        assert!(is_scannable(FileKind::Manifest));
        assert!(is_scannable(FileKind::Source));
        assert!(is_scannable(FileKind::Config));
        assert!(!is_scannable(FileKind::Other));
    }

    #[test]
    fn is_scannable_excludes_test_files_by_default() {
        assert!(!is_scannable(FileKind::Test));
    }

    #[test]
    fn is_example_value_matches_canonical_aws_docs_examples() {
        assert!(is_example_value("RSTR-SEC-001", "AKIAIOSFODNN7EXAMPLE"));
        assert!(is_example_value("RSTR-SEC-001", "AKIAIOSFODNN7EXAMPLF"));
        assert!(is_example_value("RSTR-SEC-001", "AKIA1234567890ABCDEF"));
    }

    #[test]
    fn is_example_value_rejects_real_looking_aws_key() {
        assert!(!is_example_value("RSTR-SEC-001", "AKIAABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn is_example_value_is_scoped_per_rule_code() {
        assert!(!is_example_value("RSTR-SEC-002", "AKIAIOSFODNN7EXAMPLE"));
        assert!(!is_example_value("RSTR-SEC-007", "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn scan_text_skips_canonical_aws_example_end_to_end() {
        let contents = "let key = \"AKIAIOSFODNN7EXAMPLE\";";
        let findings = scan_text_for_secrets(contents, std::path::PathBuf::from("synthetic"))
            .unwrap_or_default();
        assert!(findings.iter().all(|f| f.code != "RSTR-SEC-001"));
    }

    #[test]
    fn shannon_entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn shannon_entropy_of_uniform_string_is_zero() {
        assert_eq!(shannon_entropy("AAAAAAAA"), 0.0);
    }

    #[test]
    fn shannon_entropy_of_two_balanced_chars_is_one_bit() {
        let h = shannon_entropy("ABABABAB");
        assert!((h - 1.0).abs() < 1e-9);
    }

    #[test]
    fn shannon_entropy_of_canonical_aws_example_clears_default_threshold() {
        let h = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(h >= DEFAULT_MIN_ENTROPY);
    }

    #[test]
    fn shannon_entropy_of_low_entropy_aws_placeholder_is_below_threshold() {
        let h = shannon_entropy("AKIAAAAAAAAAAAAAAAAA");
        assert!(h < DEFAULT_MIN_ENTROPY);
    }

    #[test]
    fn entropy_filter_rejects_uniform_aws_match() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let aws = patterns.iter().find(|p| p.code == "RSTR-SEC-001");
        assert!(aws.is_some());
        if let Some(p) = aws {
            let placeholder = "AKIAAAAAAAAAAAAAAAAA";
            let captured = p.regex.find(placeholder);
            assert!(captured.is_some());
            if let Some(m) = captured {
                assert!(shannon_entropy(m.as_str()) < DEFAULT_MIN_ENTROPY);
            }
        }
    }

    #[test]
    fn pem_private_key_marker_has_no_entropy_threshold() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let pem = patterns.iter().find(|p| p.code == "RSTR-SEC-007");
        assert!(pem.is_some());
        if let Some(p) = pem {
            assert!(p.min_entropy.is_none());
        }
    }

    #[test]
    fn token_patterns_have_default_entropy_threshold() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        for p in patterns.iter().filter(|p| p.code != "RSTR-SEC-007") {
            assert_eq!(p.min_entropy, Some(DEFAULT_MIN_ENTROPY));
        }
    }
}
