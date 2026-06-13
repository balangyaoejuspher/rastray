use std::path::PathBuf;

use miette::{Diagnostic, NamedSource, SourceSpan};
use serde::Serialize;
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
    Dependency,
    Performance,
    Crawler,
    Internal,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Secret => "secret",
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

    pub fn render(&self, format: OutputFormat) -> Result<(), ReporterError> {
        match format {
            OutputFormat::Json => render_json(self),
            OutputFormat::Human => render_human(self),
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

fn render_json(report: &Report) -> Result<(), ReporterError> {
    let payload = serde_json::to_string_pretty(report)?;
    println!("{payload}");
    Ok(())
}

fn render_human(report: &Report) -> Result<(), ReporterError> {
    print_summary_block(report);

    if report.findings.is_empty() {
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
            Category::Dependency => 1,
            Category::Performance => 2,
            Category::Crawler => 3,
            Category::Internal => 4,
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
