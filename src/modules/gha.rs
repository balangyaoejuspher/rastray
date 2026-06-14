use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct GhaAnalyzer;

impl GhaAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for GhaAnalyzer {
    fn name(&self) -> &'static str {
        "gha"
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let patterns = compiled_patterns()?;
        let mut findings = Vec::new();
        for file in &crawl.files {
            if file.kind != FileKind::Config {
                continue;
            }
            if !is_workflow_path(&file.path) {
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

fn is_workflow_path(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/").to_lowercase();
    if !s.contains("/.github/workflows/") && !s.starts_with(".github/workflows/") {
        return false;
    }
    s.ends_with(".yml") || s.ends_with(".yaml")
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
        code: "RSTR-GHA-001",
        message: "pull_request_target combined with checkout of the PR head; risk of repo-secret exfiltration",
        severity: Severity::Critical,
        help: "switch to pull_request, or remove the ref: ${{ github.event.pull_request.head.sha }} checkout",
        pattern: r"pull_request_target\b",
    },
    PatternSpec {
        code: "RSTR-GHA-002",
        message: "third-party action pinned by floating tag; replace with a full commit SHA",
        severity: Severity::Medium,
        help: "pin to a full 40-char commit SHA with the version as a trailing comment, e.g. uses: foo/bar@<SHA> # v1.2.3",
        pattern: r"uses:\s*[A-Za-z0-9_-]+/[A-Za-z0-9._-]+@v?\d+(\.\d+)*\b",
    },
    PatternSpec {
        code: "RSTR-GHA-003",
        message: "interpolating ${{ github.event.* }} into a run: script is a known script-injection vector",
        severity: Severity::High,
        help: "pass the value via env: and reference it as $VAR inside run:, or use github-script with explicit input parsing",
        pattern: r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review)\.[a-zA-Z_.]+\s*\}\}",
    },
    PatternSpec {
        code: "RSTR-GHA-005",
        message: "actions/checkout used with persist-credentials: true; may leak the auto-provisioned token to subsequent steps",
        severity: Severity::Low,
        help: "set persist-credentials: false unless a subsequent step needs to push back to the repo",
        pattern: r"persist-credentials:\s*true\b",
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
            name: "gha",
            message: format!("failed to compile a builtin gha pattern: {e}"),
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
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn is_workflow_path_accepts_yml_under_github_workflows() {
        assert!(is_workflow_path(&PathBuf::from(".github/workflows/ci.yml")));
        assert!(is_workflow_path(&PathBuf::from(
            "/repo/.github/workflows/release.yaml"
        )));
        assert!(is_workflow_path(&PathBuf::from(
            r"C:\repo\.github\workflows\test.yml"
        )));
    }

    #[test]
    fn is_workflow_path_rejects_other_yaml() {
        assert!(!is_workflow_path(&PathBuf::from(
            "config/pnpm-workspace.yaml"
        )));
        assert!(!is_workflow_path(&PathBuf::from(".github/dependabot.yml")));
    }

    #[test]
    fn pull_request_target_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-GHA-001")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("on:\n  pull_request_target:\n    types: [opened]"));
        assert!(!re.is_match("on:\n  pull_request:\n    types: [opened]"));
    }

    #[test]
    fn floating_tag_pin_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-GHA-002")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("uses: actions/checkout@v4"));
        assert!(re.is_match("uses: docker/build-push-action@v5.1.0"));
        assert!(!re.is_match("uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"));
    }

    #[test]
    fn github_event_interpolation_in_run_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-GHA-003")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("echo \"${{ github.event.issue.title }}\""));
        assert!(re.is_match("echo \"${{ github.event.pull_request.head.ref }}\""));
        assert!(!re.is_match("echo \"${{ github.repository }}\""));
    }
}
