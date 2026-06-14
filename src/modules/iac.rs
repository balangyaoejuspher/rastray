use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::CrawlSummary;
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct IacAnalyzer;

impl IacAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for IacAnalyzer {
    fn name(&self) -> &'static str {
        "iac"
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let patterns = compiled_patterns()?;
        let mut findings = Vec::new();
        for file in &crawl.files {
            if !is_dockerfile(&file.path) {
                continue;
            }
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for pattern in patterns {
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

fn is_dockerfile(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower == "dockerfile"
        || lower == "containerfile"
        || lower.starts_with("dockerfile.")
        || lower.ends_with(".dockerfile")
}

struct PatternSpec {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
}

struct CompiledPattern {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
}

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-IAC-001",
        message: "image tag ':latest'; pulls a moving target and breaks build reproducibility",
        severity: Severity::Medium,
        help: "pin to a specific tag (alpine:3.20) or a digest (alpine@sha256:...)",
        pattern: r"(?im)^\s*FROM\s+\S+:latest\b",
    },
    PatternSpec {
        code: "RSTR-IAC-001",
        message: "FROM directive uses no tag; defaults to :latest",
        severity: Severity::Medium,
        help: "pin to a specific tag or @sha256: digest",
        pattern: r"(?im)^\s*FROM\s+[^:@\s]+\s*$",
    },
    PatternSpec {
        code: "RSTR-IAC-002",
        message: "explicit USER root; container will run privileged",
        severity: Severity::High,
        help: "switch to a non-root USER for the runtime stage, or omit and rely on the base image's default",
        pattern: r"(?im)^\s*USER\s+root\s*$",
    },
    PatternSpec {
        code: "RSTR-IAC-003",
        message: "ADD with a remote URL; bypasses caching, no checksum verification, and may follow redirects",
        severity: Severity::Medium,
        help: "use RUN curl -fsSL <url> -o <file> with a sha256sum check instead",
        pattern: r"(?im)^\s*ADD\s+https?://",
    },
    PatternSpec {
        code: "RSTR-IAC-005",
        message: "chmod 777 grants world-writable permissions; rarely correct",
        severity: Severity::High,
        help: "use the minimum permissions needed (typically 0755 for dirs, 0644 for files)",
        pattern: r"\bchmod\s+(0?)777\b",
    },
    PatternSpec {
        code: "RSTR-IAC-006",
        message: "curl|sh pattern pipes remote content into a shell; no signature check and TLS failure becomes a silent compromise",
        severity: Severity::High,
        help: "download the script, inspect/verify it (gpg, sha256), then execute",
        pattern: r"(?i)curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b",
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
                })
            })
            .collect::<Result<Vec<_>, _>>()
    });
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(AnalyzerError::Failed {
            name: "iac",
            message: format!("failed to compile a builtin iac pattern: {e}"),
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
    use std::path::PathBuf;

    #[test]
    fn compiled_patterns_compile_cleanly() {
        let result = compiled_patterns();
        if let Err(e) = &result {
            eprintln!("pattern compile error: {e:?}");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn is_dockerfile_recognises_canonical_and_variant_names() {
        assert!(is_dockerfile(&PathBuf::from("Dockerfile")));
        assert!(is_dockerfile(&PathBuf::from("dockerfile")));
        assert!(is_dockerfile(&PathBuf::from("Dockerfile.dev")));
        assert!(is_dockerfile(&PathBuf::from("Containerfile")));
        assert!(is_dockerfile(&PathBuf::from("dev.dockerfile")));
        assert!(!is_dockerfile(&PathBuf::from("Makefile")));
        assert!(!is_dockerfile(&PathBuf::from("docker-compose.yml")));
    }

    #[test]
    fn from_latest_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-IAC-001" && p.message.contains("latest"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("FROM alpine:latest\n"));
        assert!(re.is_match("FROM node:latest\nRUN npm i\n"));
        assert!(!re.is_match("FROM alpine:3.20\n"));
    }

    #[test]
    fn user_root_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-IAC-002")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("FROM alpine\nUSER root\n"));
        assert!(!re.is_match("FROM alpine\nUSER appuser\n"));
    }

    #[test]
    fn add_remote_url_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-IAC-003")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("ADD https://example.com/get.sh /tmp/\n"));
        assert!(!re.is_match("ADD ./local-file /tmp/\n"));
    }

    #[test]
    fn chmod_777_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-IAC-005")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("RUN chmod 777 /tmp/foo\n"));
        assert!(re.is_match("RUN chmod 0777 /tmp/foo\n"));
        assert!(!re.is_match("RUN chmod 755 /usr/bin/app\n"));
    }

    #[test]
    fn curl_pipe_sh_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-IAC-006")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("RUN curl -fsSL https://get.example.com | bash\n"));
        assert!(re.is_match("RUN curl https://get.example.com | sudo sh\n"));
        assert!(!re.is_match("RUN curl -fsSL https://get.example.com -o /tmp/get.sh\n"));
    }
}
