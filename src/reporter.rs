use std::path::{Path, PathBuf};

use miette::{Diagnostic, NamedSource, SourceSpan};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

use crate::cli::{OutputFormat, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub file: PathBuf,
    pub byte_offset: Option<usize>,
    pub byte_length: Option<usize>,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl Location {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            file: path.into(),
            byte_offset: None,
            byte_length: None,
            line: None,
            column: None,
        }
    }

    pub fn with_span(mut self, offset: usize, length: usize) -> Self {
        self.byte_offset = Some(offset);
        self.byte_length = Some(length);
        self
    }

    pub fn with_line(mut self, line: usize, column: usize) -> Self {
        self.line = Some(line);
        self.column = Some(column);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secret,
    Security,
    Dependency,
    Performance,
    Crawler,
    Internal,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Secret => "secret",
            Category::Security => "security",
            Category::Dependency => "dependency",
            Category::Performance => "performance",
            Category::Crawler => "crawler",
            Category::Internal => "internal",
        }
    }
}

impl Serialize for Severity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: String,
    pub message: String,
    pub severity: Severity,
    pub category: Category,
    pub help: Option<String>,
    pub location: Option<Location>,
}

impl Finding {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        severity: Severity,
        category: Category,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity,
            category,
            help: None,
            location: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub stats: ReportStats,
    pub perf: ReportPerf,
    #[serde(skip)]
    pub summary_only: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct ReportStats {
    pub files_scanned: usize,
    pub manifests: usize,
    pub source_files: usize,
    pub config_files: usize,
    pub other_files: usize,
    pub crawl_errors: usize,
    pub skipped: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct ReportPerf {
    pub walk_ms: u64,
    pub analyze_ms: u64,
    pub total_ms: u64,
    pub bytes_scanned: u64,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn extend<I: IntoIterator<Item = Finding>>(&mut self, iter: I) {
        self.findings.extend(iter);
    }

    pub fn has_at_or_above(&self, min: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= min)
    }

    pub fn apply_min_severity(&mut self, min: Severity) {
        self.findings.retain(|f| f.severity >= min);
    }

    pub fn render(
        &self,
        format: OutputFormat,
        output_path: Option<&Path>,
    ) -> Result<(), ReporterError> {
        match format {
            OutputFormat::Json => render_json(self, output_path),
            OutputFormat::Human => render_human(self),
            OutputFormat::GhActions => render_gh_actions(self),
            OutputFormat::Sarif => render_sarif(self, output_path),
            OutputFormat::Cyclonedx | OutputFormat::SpdxJson => Ok(()),
        }
    }
}

#[derive(Debug, Error)]
pub enum ReporterError {
    #[error("failed to serialize report as JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("failed to read source file '{path}' for diagnostic rendering: {source}")]
    SourceRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write report to stdout: {0}")]
    Io(#[from] std::io::Error),
}

fn render_json(report: &Report, output_path: Option<&Path>) -> Result<(), ReporterError> {
    let payload = serde_json::to_string_pretty(report)?;
    write_or_print(&payload, output_path)
}

fn write_or_print(payload: &str, output_path: Option<&Path>) -> Result<(), ReporterError> {
    match output_path {
        Some(path) => std::fs::write(path, payload).map_err(ReporterError::Io),
        None => {
            println!("{payload}");
            Ok(())
        }
    }
}

fn render_gh_actions(report: &Report) -> Result<(), ReporterError> {
    for finding in &report.findings {
        println!("{}", gh_actions_line(finding));
    }
    Ok(())
}

fn render_sarif(report: &Report, output_path: Option<&Path>) -> Result<(), ReporterError> {
    let payload = serde_json::to_string_pretty(&sarif_document(report))?;
    write_or_print(&payload, output_path)
}

fn sarif_document(report: &Report) -> serde_json::Value {
    use std::collections::BTreeMap;

    let mut rules_by_id: BTreeMap<String, &Finding> = BTreeMap::new();
    for f in &report.findings {
        rules_by_id.entry(f.code.clone()).or_insert(f);
    }

    let rules: Vec<serde_json::Value> = rules_by_id.values().map(|f| sarif_rule(f)).collect();

    let results: Vec<serde_json::Value> = report.findings.iter().map(sarif_result).collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rastray",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/balangyaoejuspher/rastray",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ]
    })
}

fn sarif_rule(f: &Finding) -> serde_json::Value {
    let mut rule = json!({
        "id": f.code,
        "name": f.code,
        "shortDescription": { "text": f.message },
        "defaultConfiguration": { "level": sarif_level(f.severity) },
        "properties": { "category": f.category.as_str() },
    });
    if let Some(help) = &f.help {
        rule["help"] = json!({ "text": help });
    }
    rule
}

fn sarif_result(f: &Finding) -> serde_json::Value {
    let mut result = json!({
        "ruleId": f.code,
        "level": sarif_level(f.severity),
        "message": { "text": f.message },
    });

    if let Some(loc) = &f.location {
        let mut physical = json!({
            "artifactLocation": { "uri": loc.file.display().to_string() }
        });
        let mut region = serde_json::Map::new();
        if let Some(line) = loc.line {
            region.insert("startLine".to_string(), json!(line));
        }
        if let Some(col) = loc.column {
            region.insert("startColumn".to_string(), json!(col));
        }
        if let Some(offset) = loc.byte_offset {
            region.insert("charOffset".to_string(), json!(offset));
            if let Some(len) = loc.byte_length {
                region.insert("charLength".to_string(), json!(len));
            }
        }
        if !region.is_empty() {
            physical["region"] = serde_json::Value::Object(region);
        }
        result["locations"] = json!([{ "physicalLocation": physical }]);
    }

    result
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn gh_actions_line(finding: &Finding) -> String {
    let kind = match finding.severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "notice",
    };

    let mut params: Vec<String> = Vec::new();
    if let Some(loc) = &finding.location {
        let file = loc.file.display().to_string();
        params.push(format!("file={}", escape_gh_property(&file)));
        if let Some(line) = loc.line {
            params.push(format!("line={line}"));
        }
        if let Some(col) = loc.column {
            params.push(format!("col={col}"));
        }
    }
    params.push(format!(
        "title={}",
        escape_gh_property(&format!("rastray::{}", finding.code))
    ));

    let message = escape_gh_data(&finding.message);

    if params.is_empty() {
        format!("::{kind}::{message}")
    } else {
        format!("::{kind} {}::{message}", params.join(","))
    }
}

fn escape_gh_property(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn escape_gh_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn render_human(report: &Report) -> Result<(), ReporterError> {
    print_summary_block(report);

    if report.findings.is_empty() || report.summary_only {
        return Ok(());
    }

    println!();
    for finding in &report.findings {
        render_finding(finding)?;
    }

    Ok(())
}

const SUMMARY_RULE: &str = "═══════════════════════════════════════════════════════════════";
const BAR_WIDTH: usize = 10;

fn print_summary_block(report: &Report) {
    let total_secs = report.perf.total_ms as f64 / 1000.0;
    println!("{SUMMARY_RULE}");
    println!(
        "  RASTRAY SCAN REPORT — {} files in {:.2}s",
        report.stats.files_scanned, total_secs
    );
    println!("{SUMMARY_RULE}");
    println!();

    print_severity_distribution(report);
    println!();
    print_category_distribution(report);
    println!();
    print_coverage(report);
    println!();
    print_performance(report);
    println!("{SUMMARY_RULE}");
}

fn print_severity_distribution(report: &Report) {
    let counts = severity_counts(report);
    let labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    let max = *counts.iter().max().unwrap_or(&0);

    println!("  Severity distribution");
    println!("  ════════════════════════");
    for (label, count) in labels.iter().zip(counts.iter()) {
        println!(
            "  {label:<10}{bar}    {count}",
            bar = render_bar(*count, max, BAR_WIDTH)
        );
    }
}

fn severity_counts(report: &Report) -> [usize; 5] {
    let mut counts = [0usize; 5];
    for f in &report.findings {
        let idx = match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        counts[idx] = counts[idx].saturating_add(1);
    }
    counts
}

fn print_category_distribution(report: &Report) {
    let mut counts = [0usize; 5];
    for f in &report.findings {
        let idx = match f.category {
            Category::Secret => 0,
            Category::Security => 1,
            Category::Dependency => 2,
            Category::Performance => 3,
            Category::Crawler => 4,
            Category::Internal => 5,
        };
        counts[idx] = counts[idx].saturating_add(1);
    }
    let labels = [
        "Secrets",
        "Dependencies",
        "Performance",
        "Crawler",
        "Internal",
    ];

    println!("  Category distribution");
    println!("  ═══════════════════════");
    for (label, count) in labels.iter().zip(counts.iter()) {
        println!("  {label:<14}{count}");
    }
}

fn print_coverage(report: &Report) {
    let stats = &report.stats;
    println!("  Coverage");
    println!("  ════════");
    println!("  Manifests     {} files", stats.manifests);
    println!("  Source        {} files", stats.source_files);
    println!("  Config        {} files", stats.config_files);
    println!("  Other         {} files", stats.other_files);
    println!(
        "  Skipped       {}, crawl errors: {}",
        stats.skipped, stats.crawl_errors
    );
}

fn print_performance(report: &Report) {
    let perf = &report.perf;
    let walk_secs = perf.walk_ms as f64 / 1000.0;
    let analyze_secs = perf.analyze_ms as f64 / 1000.0;
    let total_secs = perf.total_ms as f64 / 1000.0;
    let files = report.stats.files_scanned as u64;
    let findings = report.findings.len() as u64;

    println!("  Performance");
    println!("  ═══════════");
    println!(
        "  Walk:     {:.2}s    {}",
        walk_secs,
        format_rate(files, perf.walk_ms, "files")
    );
    println!(
        "  Analyze:  {:.2}s    {}",
        analyze_secs,
        format_rate(findings, perf.analyze_ms, "findings")
    );
    println!(
        "  Total:    {:.2}s    {}",
        total_secs,
        format_bytes(perf.bytes_scanned)
    );
}

fn render_bar(count: usize, max: usize, width: usize) -> String {
    if max == 0 {
        return "░".repeat(width);
    }
    let filled = count.saturating_mul(width).saturating_add(max / 2) / max;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);
    let mut s = String::with_capacity(width * 3);
    for _ in 0..filled {
        s.push('▓');
    }
    for _ in 0..empty {
        s.push('░');
    }
    s
}

fn format_rate(count: u64, ms: u64, unit: &str) -> String {
    if ms == 0 {
        return format!("{count} {unit}");
    }
    let per_sec = count.saturating_mul(1000) / ms;
    if per_sec >= 1_000_000 {
        format!("{:.1}M {unit}/s", per_sec as f64 / 1_000_000.0)
    } else if per_sec >= 1_000 {
        format!("{:.1}k {unit}/s", per_sec as f64 / 1_000.0)
    } else {
        format!("{per_sec} {unit}/s")
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB scanned", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB scanned", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB scanned", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B scanned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, category: Category) -> Finding {
        Finding::new("RSTR-TST-000", "test", severity, category)
    }

    #[test]
    fn format_bytes_handles_all_buckets() {
        assert_eq!(format_bytes(0), "0 B scanned");
        assert_eq!(format_bytes(512), "512 B scanned");
        assert_eq!(format_bytes(1023), "1023 B scanned");
        assert_eq!(format_bytes(1024), "1.0 KB scanned");
        assert_eq!(format_bytes(2048), "2.0 KB scanned");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB scanned");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB scanned");
    }

    #[test]
    fn format_rate_handles_zero_ms_without_panic() {
        assert_eq!(format_rate(100, 0, "files"), "100 files");
    }

    #[test]
    fn format_rate_scales_units() {
        assert_eq!(format_rate(50, 1000, "files"), "50 files/s");
        assert_eq!(format_rate(5_000, 1000, "files"), "5.0k files/s");
        assert_eq!(format_rate(5_000_000, 1000, "files"), "5.0M files/s");
    }

    #[test]
    fn render_bar_returns_only_empty_blocks_when_max_zero() {
        let bar = render_bar(0, 0, 10);
        assert_eq!(bar.chars().count(), 10);
        assert!(bar.chars().all(|c| c == '░'));
    }

    #[test]
    fn render_bar_full_when_count_equals_max() {
        let bar = render_bar(7, 7, 10);
        assert_eq!(bar.chars().count(), 10);
        assert!(bar.chars().all(|c| c == '▓'));
    }

    #[test]
    fn render_bar_proportional_partial() {
        let bar = render_bar(3, 10, 10);
        assert_eq!(bar.chars().count(), 10);
        let filled = bar.chars().filter(|c| *c == '▓').count();
        assert_eq!(filled, 3);
    }

    #[test]
    fn severity_counts_buckets_findings_correctly() {
        let mut report = Report::new();
        report.push(finding(Severity::Critical, Category::Secret));
        report.push(finding(Severity::Critical, Category::Secret));
        report.push(finding(Severity::High, Category::Secret));
        report.push(finding(Severity::Low, Category::Crawler));
        let counts = severity_counts(&report);
        assert_eq!(counts, [2, 1, 0, 1, 0]);
    }

    #[test]
    fn severity_counts_empty_report_is_all_zero() {
        let report = Report::new();
        assert_eq!(severity_counts(&report), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn apply_min_severity_drops_below_threshold() {
        let mut report = Report::new();
        report.push(finding(Severity::Info, Category::Secret));
        report.push(finding(Severity::Low, Category::Secret));
        report.push(finding(Severity::High, Category::Secret));
        report.apply_min_severity(Severity::Medium);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::High);
    }

    #[test]
    fn has_at_or_above_recognises_threshold() {
        let mut report = Report::new();
        report.push(finding(Severity::Low, Category::Secret));
        assert!(report.has_at_or_above(Severity::Low));
        assert!(!report.has_at_or_above(Severity::Medium));
    }

    fn finding_with_location(
        severity: Severity,
        message: &str,
        path: &str,
        line: usize,
        col: usize,
    ) -> Finding {
        Finding::new("RSTR-TST-100", message, severity, Category::Secret)
            .with_location(Location::file(path).with_line(line, col))
    }

    #[test]
    fn gh_actions_line_uses_error_for_critical_and_high() {
        let f = finding_with_location(Severity::Critical, "boom", "src/a.rs", 1, 1);
        let line = gh_actions_line(&f);
        assert!(line.starts_with("::error "));
        let f = finding_with_location(Severity::High, "boom", "src/a.rs", 1, 1);
        assert!(gh_actions_line(&f).starts_with("::error "));
    }

    #[test]
    fn gh_actions_line_uses_warning_for_medium() {
        let f = finding_with_location(Severity::Medium, "warn", "src/a.rs", 1, 1);
        assert!(gh_actions_line(&f).starts_with("::warning "));
    }

    #[test]
    fn gh_actions_line_uses_notice_for_low_and_info() {
        let f = finding_with_location(Severity::Low, "note", "src/a.rs", 1, 1);
        assert!(gh_actions_line(&f).starts_with("::notice "));
        let f = finding_with_location(Severity::Info, "note", "src/a.rs", 1, 1);
        assert!(gh_actions_line(&f).starts_with("::notice "));
    }

    #[test]
    fn gh_actions_line_includes_file_line_col_when_present() {
        let f = finding_with_location(Severity::High, "msg", "src/a.rs", 10, 5);
        let line = gh_actions_line(&f);
        assert!(line.contains("file=src/a.rs"));
        assert!(line.contains("line=10"));
        assert!(line.contains("col=5"));
        assert!(line.ends_with("::msg"));
    }

    #[test]
    fn gh_actions_line_emits_title_with_finding_code() {
        let f = finding_with_location(Severity::High, "msg", "src/a.rs", 1, 1);
        let line = gh_actions_line(&f);
        assert!(line.contains("title=rastray%3A%3ARSTR-TST-100"));
    }

    #[test]
    fn gh_actions_line_omits_location_when_none() {
        let f = Finding::new(
            "RSTR-TST-200",
            "anywhere",
            Severity::Medium,
            Category::Crawler,
        );
        let line = gh_actions_line(&f);
        assert!(line.starts_with("::warning "));
        assert!(line.contains("title="));
        assert!(!line.contains("file="));
        assert!(line.ends_with("::anywhere"));
    }

    #[test]
    fn escape_gh_property_encodes_separators_and_control_chars() {
        assert_eq!(escape_gh_property("a,b"), "a%2Cb");
        assert_eq!(escape_gh_property("a:b"), "a%3Ab");
        assert_eq!(escape_gh_property("a%b"), "a%25b");
        assert_eq!(escape_gh_property("a\nb"), "a%0Ab");
        assert_eq!(escape_gh_property("a\rb"), "a%0Db");
    }

    #[test]
    fn escape_gh_data_keeps_colons_and_commas_but_encodes_newlines() {
        assert_eq!(escape_gh_data("a,b:c"), "a,b:c");
        assert_eq!(escape_gh_data("multi\nline"), "multi%0Aline");
        assert_eq!(escape_gh_data("100%"), "100%25");
    }

    #[test]
    fn gh_actions_line_escapes_messages_with_newlines() {
        let f = finding_with_location(Severity::High, "first\nsecond", "src/a.rs", 1, 1);
        let line = gh_actions_line(&f);
        assert!(line.ends_with("::first%0Asecond"));
    }

    #[test]
    fn sarif_level_maps_severities() {
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Low), "note");
        assert_eq!(sarif_level(Severity::Info), "note");
    }

    #[test]
    fn sarif_document_has_required_top_level_fields() {
        let report = Report::new();
        let doc = sarif_document(&report);
        assert_eq!(doc["version"], "2.1.0");
        assert!(doc["$schema"].as_str().unwrap_or("").contains("sarif"));
        assert!(doc["runs"].is_array());
        assert_eq!(doc["runs"].as_array().map(|a| a.len()), Some(1));
    }

    #[test]
    fn sarif_document_lists_tool_driver_metadata() {
        let report = Report::new();
        let doc = sarif_document(&report);
        let driver = &doc["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "rastray");
        assert!(driver["version"].is_string());
        assert_eq!(
            driver["informationUri"],
            "https://github.com/balangyaoejuspher/rastray"
        );
    }

    #[test]
    fn sarif_document_deduplicates_rules_by_code() {
        let mut report = Report::new();
        report.push(finding_with_location(Severity::High, "first", "a.rs", 1, 1));
        report.push(finding_with_location(
            Severity::High,
            "second",
            "a.rs",
            2,
            1,
        ));
        let doc = sarif_document(&report);
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(rules.len(), 1);
        let results = doc["runs"][0]["results"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn sarif_result_contains_location_when_finding_has_one() {
        let mut report = Report::new();
        report.push(finding_with_location(
            Severity::Medium,
            "msg",
            "src/a.rs",
            7,
            3,
        ));
        let doc = sarif_document(&report);
        let r = &doc["runs"][0]["results"][0];
        assert_eq!(r["ruleId"], "RSTR-TST-100");
        assert_eq!(r["level"], "warning");
        let physical = &r["locations"][0]["physicalLocation"];
        assert_eq!(physical["artifactLocation"]["uri"], "src/a.rs");
        assert_eq!(physical["region"]["startLine"], 7);
        assert_eq!(physical["region"]["startColumn"], 3);
    }

    #[test]
    fn sarif_result_omits_locations_when_finding_has_none() {
        let mut report = Report::new();
        report.push(finding(Severity::Low, Category::Crawler));
        let doc = sarif_document(&report);
        let r = &doc["runs"][0]["results"][0];
        assert!(r["locations"].is_null());
    }
}

fn render_finding(finding: &Finding) -> Result<(), ReporterError> {
    let diag = FindingDiagnostic::from_finding(finding)?;
    let report: miette::Report = miette::Report::new(diag);
    eprintln!("{report:?}");
    Ok(())
}

#[derive(Debug, Error)]
#[error("{message}")]
struct FindingDiagnostic {
    code: String,
    severity: Severity,
    category: Category,
    message: String,
    help: Option<String>,
    src: Option<NamedSource<String>>,
    span: Option<SourceSpan>,
}

impl FindingDiagnostic {
    fn from_finding(finding: &Finding) -> Result<Self, ReporterError> {
        let (src, span) = match &finding.location {
            Some(loc) => build_source(loc)?,
            None => (None, None),
        };

        Ok(Self {
            code: finding.code.clone(),
            severity: finding.severity,
            category: finding.category,
            message: finding.message.clone(),
            help: finding.help.clone(),
            src,
            span,
        })
    }
}

impl Diagnostic for FindingDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "{}::{}",
            self.category.as_str(),
            self.code
        )))
    }

    fn severity(&self) -> Option<miette::Severity> {
        Some(match self.severity {
            Severity::Info | Severity::Low => miette::Severity::Advice,
            Severity::Medium => miette::Severity::Warning,
            Severity::High | Severity::Critical => miette::Severity::Error,
        })
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.help
            .as_ref()
            .map(|h| Box::new(h.clone()) as Box<dyn std::fmt::Display>)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.src.as_ref().map(|s| s as &dyn miette::SourceCode)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        let span = self.span?;
        Some(Box::new(std::iter::once(
            miette::LabeledSpan::new_with_span(Some("here".to_string()), span),
        )))
    }
}

fn build_source(
    location: &Location,
) -> Result<(Option<NamedSource<String>>, Option<SourceSpan>), ReporterError> {
    let contents = match std::fs::read_to_string(&location.file) {
        Ok(c) => c,
        Err(_) => return Ok((None, None)),
    };

    let display_name = location.file.display().to_string();
    let named = NamedSource::new(display_name, contents);

    let span = match (location.byte_offset, location.byte_length) {
        (Some(offset), Some(length)) => Some(SourceSpan::from((offset, length))),
        (Some(offset), None) => Some(SourceSpan::from((offset, 0_usize))),
        _ => None,
    };

    Ok((Some(named), span))
}
