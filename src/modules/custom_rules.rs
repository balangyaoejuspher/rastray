use std::fs;
use std::sync::Arc;

use regex::Regex;

use crate::cli::Severity;
use crate::config::CustomRule;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug)]
pub struct CustomRulesAnalyzer {
    rules: Arc<Vec<CompiledRule>>,
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    regex: Regex,
    message: String,
    severity: Severity,
    help: Option<String>,
    extensions: Vec<String>,
}

impl CustomRulesAnalyzer {
    pub fn new(custom_rules: &[CustomRule]) -> Self {
        let mut compiled = Vec::with_capacity(custom_rules.len());
        for rule in custom_rules {
            let Ok(regex) = Regex::new(&rule.pattern) else {
                continue;
            };
            let severity = rule
                .severity
                .as_deref()
                .and_then(|s| s.parse::<Severity>().ok())
                .unwrap_or(Severity::Medium);
            let extensions = rule
                .extensions
                .iter()
                .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                .collect();
            compiled.push(CompiledRule {
                id: rule.id.clone(),
                regex,
                message: rule.message.clone(),
                severity,
                help: rule.help.clone(),
                extensions,
            });
        }
        Self {
            rules: Arc::new(compiled),
        }
    }
}

impl Analyzer for CustomRulesAnalyzer {
    fn name(&self) -> &'static str {
        "custom_rules"
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        if self.rules.is_empty() {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();
        for file in &crawl.files {
            if file.kind != FileKind::Source && file.kind != FileKind::Config {
                continue;
            }
            let ext = file
                .path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase());
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for rule in self.rules.iter() {
                if !rule.extensions.is_empty() {
                    let Some(ref e) = ext else { continue };
                    if !rule.extensions.iter().any(|r| r == e) {
                        continue;
                    }
                }
                for m in rule.regex.find_iter(&contents) {
                    let (line, column) = byte_offset_to_line_col(&contents, m.start());
                    let location = Location::file(file.path.clone())
                        .with_span(m.start(), m.len())
                        .with_line(line, column);
                    let mut finding = Finding::new(
                        rule.id.clone(),
                        rule.message.clone(),
                        rule.severity,
                        Category::Security,
                    )
                    .with_location(location);
                    if let Some(help) = &rule.help {
                        finding = finding.with_help(help.clone());
                    }
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
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
    use crate::crawler::{CrawlSummary, DiscoveredFile, FileKind};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir() -> Option<PathBuf> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rastray-customrule-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        match std::fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn run_with(rules: Vec<CustomRule>, name: &str, body: &str) -> Vec<Finding> {
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
        let result = CustomRulesAnalyzer::new(&rules)
            .analyze(&crawl)
            .unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn rule(id: &str, pattern: &str, message: &str) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            pattern: pattern.to_string(),
            message: message.to_string(),
            severity: None,
            help: None,
            extensions: vec![],
        }
    }

    #[test]
    fn empty_rules_returns_no_findings() {
        let findings = run_with(vec![], "a.rs", "fn main() {}");
        assert!(findings.is_empty());
    }

    #[test]
    fn matches_simple_regex() {
        let r = rule("ACME-001", r"\bTODO\b", "TODO marker found");
        let findings = run_with(vec![r], "a.rs", "fn main() { /* TODO: fix */ }");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "ACME-001");
        assert_eq!(findings[0].message, "TODO marker found");
    }

    #[test]
    fn default_severity_is_medium() {
        let r = rule("ACME-001", r"x", "found x");
        let findings = run_with(vec![r], "a.rs", "let x = 1;");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn explicit_severity_overrides_default() {
        let mut r = rule("ACME-002", r"foo", "found foo");
        r.severity = Some("high".to_string());
        let findings = run_with(vec![r], "a.rs", "foo");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn help_text_propagates_to_finding() {
        let mut r = rule("ACME-003", r"foo", "found foo");
        r.help = Some("rename foo to bar".to_string());
        let findings = run_with(vec![r], "a.rs", "foo");
        assert_eq!(findings[0].help.as_deref(), Some("rename foo to bar"));
    }

    #[test]
    fn extensions_filter_restricts_match() {
        let mut r = rule("ACME-004", r"foo", "found foo");
        r.extensions = vec!["py".to_string()];
        let rs_findings = run_with(vec![r.clone()], "a.rs", "foo");
        assert!(rs_findings.is_empty(), "rs should not match py-only rule");
        let py_findings = run_with(vec![r], "a.py", "foo");
        assert_eq!(py_findings.len(), 1);
    }

    #[test]
    fn extensions_strip_leading_dot() {
        let mut r = rule("ACME-005", r"foo", "found foo");
        r.extensions = vec![".py".to_string()];
        let findings = run_with(vec![r], "a.py", "foo");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn invalid_regex_is_silently_dropped_in_constructor() {
        let bad = CustomRule {
            id: "BAD-001".to_string(),
            pattern: "(unclosed".to_string(),
            message: "msg".to_string(),
            severity: None,
            help: None,
            extensions: vec![],
        };
        let analyzer = CustomRulesAnalyzer::new(&[bad]);
        assert_eq!(analyzer.rules.len(), 0);
    }

    #[test]
    fn finding_location_carries_line_and_column() {
        let r = rule("ACME-006", r"banana", "fruit");
        let findings = run_with(vec![r], "a.rs", "apple\nbanana\norange\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].location.is_some(), "missing location");
        if let Some(loc) = findings[0].location.as_ref() {
            assert_eq!(loc.line, Some(2));
            assert_eq!(loc.column, Some(1));
        }
    }
}
