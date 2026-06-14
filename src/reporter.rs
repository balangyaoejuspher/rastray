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
            OutputFormat::Markdown => render_markdown(self, output_path),
            OutputFormat::Html => render_html(self, output_path),
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

    #[error("--format html requires -o/--output FILE; an HTML report cannot be written to stdout")]
    HtmlRequiresOutputPath,
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

const MARKDOWN_PER_BUCKET: [(Severity, usize); 5] = [
    (Severity::Critical, usize::MAX),
    (Severity::High, 10),
    (Severity::Medium, 5),
    (Severity::Low, 5),
    (Severity::Info, 0),
];

fn render_markdown(report: &Report, output_path: Option<&Path>) -> Result<(), ReporterError> {
    let payload = markdown_document(report);
    write_or_print(&payload, output_path)
}

fn markdown_document(report: &Report) -> String {
    let mut out = String::new();
    let total_secs = report.perf.total_ms as f64 / 1000.0;
    out.push_str(&format!(
        "## rastray scan — {} findings across {} files in {:.2}s\n\n",
        report.findings.len(),
        report.stats.files_scanned,
        total_secs
    ));

    out.push_str("### Severity\n\n");
    out.push_str("| Severity | Count |\n|---|---:|\n");
    let sev_counts = severity_counts(report);
    let sev_labels = ["Critical", "High", "Medium", "Low", "Info"];
    for (label, count) in sev_labels.iter().zip(sev_counts.iter()) {
        out.push_str(&format!("| {label} | {count} |\n"));
    }
    out.push('\n');

    out.push_str("### Category\n\n");
    out.push_str("| Category | Count |\n|---|---:|\n");
    for (label, count) in category_counts(report) {
        out.push_str(&format!("| {label} | {count} |\n"));
    }
    out.push('\n');

    if !report.findings.is_empty() {
        out.push_str("### Findings\n\n");
        let mut shown_total = 0usize;
        for (severity, cap) in MARKDOWN_PER_BUCKET {
            if cap == 0 {
                continue;
            }
            let bucket: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|f| f.severity == severity)
                .collect();
            if bucket.is_empty() {
                continue;
            }
            let take = bucket.len().min(cap);
            shown_total += take;
            out.push_str(&format!(
                "<details open>\n<summary><strong>{}</strong> — showing {} of {}</summary>\n\n",
                severity.as_str().to_ascii_uppercase(),
                take,
                bucket.len()
            ));
            out.push_str("| Code | Location | Message |\n|---|---|---|\n");
            for finding in bucket.iter().take(take) {
                let loc = format_markdown_location(finding);
                let msg = escape_markdown_cell(&finding.message);
                out.push_str(&format!("| `{}` | {} | {} |\n", finding.code, loc, msg));
            }
            if bucket.len() > take {
                out.push_str(&format!(
                    "\n_{} more {} finding(s) omitted. Use `--format json` for the full list._\n",
                    bucket.len() - take,
                    severity.as_str()
                ));
            }
            out.push_str("\n</details>\n\n");
        }
        if shown_total < report.findings.len() {
            out.push_str(&format!(
                "_Showing {} of {} findings. Use `--format json` for the full list._\n",
                shown_total,
                report.findings.len()
            ));
        }
    } else {
        out.push_str("No findings. ✓\n");
    }

    out
}

fn format_markdown_location(finding: &Finding) -> String {
    match &finding.location {
        Some(loc) => {
            let file = loc.file.display().to_string();
            let file = file.trim_start_matches(r"\\?\");
            match (loc.line, loc.column) {
                (Some(line), Some(col)) => format!("`{file}:{line}:{col}`"),
                (Some(line), None) => format!("`{file}:{line}`"),
                _ => format!("`{file}`"),
            }
        }
        None => "—".to_string(),
    }
}

fn escape_markdown_cell(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('|', r"\|")
        .replace(['\r', '\n'], " ")
}

const HTML_CSS: &str = include_str!("reporter_html/report.css");
const HTML_JS: &str = include_str!("reporter_html/report.js");

fn render_html(report: &Report, output_path: Option<&Path>) -> Result<(), ReporterError> {
    let Some(path) = output_path else {
        return Err(ReporterError::HtmlRequiresOutputPath);
    };
    let payload = html_document(report);
    std::fs::write(path, payload).map_err(ReporterError::Io)
}

fn html_document(report: &Report) -> String {
    let mut out = String::with_capacity(16 * 1024);
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    out.push_str(&format!(
        "<title>rastray scan — {} findings</title>\n",
        report.findings.len()
    ));
    out.push_str("<style>\n");
    out.push_str(HTML_CSS);
    out.push_str("</style>\n</head>\n<body>\n");

    let total_secs = report.perf.total_ms as f64 / 1000.0;
    out.push_str(&format!(
        "<header><h1>rastray scan</h1><p class=\"summary\"><strong>{}</strong> findings across <strong>{}</strong> files in <strong>{:.2}s</strong></p></header>\n",
        report.findings.len(),
        report.stats.files_scanned,
        total_secs
    ));

    out.push_str("<section class=\"charts\">\n");
    out.push_str("<div class=\"chart-card\"><h2>Severity</h2>\n");
    out.push_str(&render_severity_donut(report));
    out.push_str("</div>\n");
    out.push_str("<div class=\"chart-card\"><h2>Category</h2>\n");
    out.push_str(&render_category_bars(report));
    out.push_str("</div>\n");
    out.push_str("</section>\n");

    out.push_str("<section class=\"controls\">\n");
    out.push_str("<input type=\"search\" id=\"filter\" placeholder=\"Filter by code, file, or message…\" aria-label=\"Filter findings\">\n");
    out.push_str("<div class=\"chips\">\n");
    for label in ["all", "critical", "high", "medium", "low", "info"] {
        let cls = if label == "all" {
            "chip active"
        } else {
            "chip"
        };
        out.push_str(&format!(
            "<button class=\"{}\" data-severity=\"{}\">{}</button>\n",
            cls,
            label,
            label.to_ascii_uppercase()
        ));
    }
    out.push_str("</div>\n</section>\n");

    out.push_str("<section class=\"findings\">\n");
    out.push_str("<div class=\"table-scroll\">\n");
    out.push_str("<table id=\"findings-table\">\n<thead><tr>\n");
    out.push_str("<th class=\"sortable\" data-key=\"severity\">Severity</th>\n");
    out.push_str("<th class=\"sortable\" data-key=\"code\">Code</th>\n");
    out.push_str("<th class=\"sortable\" data-key=\"category\">Category</th>\n");
    out.push_str("<th class=\"sortable\" data-key=\"file\">Location</th>\n");
    out.push_str("<th>Message</th>\n");
    out.push_str("</tr></thead>\n<tbody>\n");
    for f in &report.findings {
        out.push_str(&render_finding_row(f));
    }
    out.push_str("</tbody>\n</table>\n");
    out.push_str("</div>\n");
    if report.findings.is_empty() {
        out.push_str("<p class=\"empty\">No findings. ✓</p>\n");
    }
    out.push_str("</section>\n");

    out.push_str(
        "<footer><p>Generated by <a href=\"https://crates.io/crates/rastray\">rastray</a> v",
    );
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str("</p></footer>\n");
    out.push_str("<script>\n");
    out.push_str(HTML_JS);
    out.push_str("</script>\n</body>\n</html>\n");
    out
}

fn render_severity_donut(report: &Report) -> String {
    let counts = severity_counts(report);
    let labels = ["critical", "high", "medium", "low", "info"];
    let label_display = ["Critical", "High", "Medium", "Low", "Info"];
    let total: usize = counts.iter().sum();
    let mut svg = String::new();
    svg.push_str(
        "<svg class=\"donut\" viewBox=\"0 0 42 42\" aria-label=\"Severity distribution\">\n",
    );
    svg.push_str("<circle class=\"donut-ring\" cx=\"21\" cy=\"21\" r=\"15.915\" fill=\"transparent\"></circle>\n");
    if total > 0 {
        let circumference = 100.0_f64;
        let mut offset = 25.0_f64;
        for (idx, count) in counts.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let fraction = (*count as f64 / total as f64) * circumference;
            svg.push_str(&format!(
                "<circle class=\"donut-segment seg-{}\" cx=\"21\" cy=\"21\" r=\"15.915\" fill=\"transparent\" stroke-width=\"6\" stroke-dasharray=\"{:.3} {:.3}\" stroke-dashoffset=\"{:.3}\"></circle>\n",
                labels[idx],
                fraction,
                circumference - fraction,
                offset
            ));
            offset = (offset - fraction).rem_euclid(circumference);
        }
        svg.push_str(&format!(
            "<text x=\"21\" y=\"21\" class=\"donut-total\" text-anchor=\"middle\" dominant-baseline=\"central\">{}</text>\n",
            total
        ));
    } else {
        svg.push_str("<text x=\"21\" y=\"21\" class=\"donut-total\" text-anchor=\"middle\" dominant-baseline=\"central\">0</text>\n");
    }
    svg.push_str("</svg>\n");
    svg.push_str("<ul class=\"legend\">\n");
    for (idx, count) in counts.iter().enumerate() {
        svg.push_str(&format!(
            "<li><span class=\"swatch seg-{}\"></span>{} <span class=\"count\">{}</span></li>\n",
            labels[idx], label_display[idx], count
        ));
    }
    svg.push_str("</ul>\n");
    svg
}

fn render_category_bars(report: &Report) -> String {
    let counts = category_counts(report);
    let max = counts.iter().map(|(_, n)| *n).max().unwrap_or(0).max(1);
    let mut html = String::new();
    html.push_str("<ul class=\"bars\">\n");
    for (label, count) in counts {
        let pct = (count as f64 / max as f64) * 100.0;
        html.push_str(&format!(
            "<li><span class=\"bar-label\">{label}</span><span class=\"bar\"><span class=\"bar-fill\" style=\"width:{:.1}%\"></span></span><span class=\"bar-count\">{count}</span></li>\n",
            pct
        ));
    }
    html.push_str("</ul>\n");
    html
}

fn render_finding_row(f: &Finding) -> String {
    let sev = f.severity.as_str();
    let loc = match &f.location {
        Some(l) => {
            let file = l.file.display().to_string();
            let file = file.trim_start_matches(r"\\?\").to_string();
            match (l.line, l.column) {
                (Some(line), Some(col)) => format!("{file}:{line}:{col}"),
                (Some(line), None) => format!("{file}:{line}"),
                _ => file,
            }
        }
        None => String::new(),
    };
    let help_attr = f
        .help
        .as_deref()
        .map(|h| format!(" title=\"{}\"", escape_html_attr(h)))
        .unwrap_or_default();
    format!(
        "<tr data-severity=\"{sev}\" data-code=\"{code}\" data-category=\"{cat}\" data-file=\"{file}\">\n  <td data-label=\"Severity\"><span class=\"sev sev-{sev}\">{sev_disp}</span></td>\n  <td data-label=\"Code\"><code>{code}</code></td>\n  <td data-label=\"Category\">{cat}</td>\n  <td data-label=\"Location\"><code class=\"loc\">{loc_html}</code></td>\n  <td data-label=\"Message\"{help_attr}>{msg}</td>\n</tr>\n",
        sev = sev,
        sev_disp = sev.to_ascii_uppercase(),
        code = escape_html_text(&f.code),
        cat = f.category.as_str(),
        file = escape_html_attr(&loc),
        loc_html = escape_html_text(&loc),
        msg = escape_html_text(&f.message),
        help_attr = help_attr,
    )
}

fn escape_html_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_html_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
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

const CATEGORY_BUCKETS: &[(&str, Category)] = &[
    ("Secrets", Category::Secret),
    ("Security", Category::Security),
    ("Dependencies", Category::Dependency),
    ("Performance", Category::Performance),
    ("Crawler", Category::Crawler),
    ("Internal", Category::Internal),
];

fn category_counts(report: &Report) -> Vec<(&'static str, usize)> {
    CATEGORY_BUCKETS
        .iter()
        .map(|(label, category)| {
            let count = report
                .findings
                .iter()
                .filter(|f| f.category == *category)
                .count();
            (*label, count)
        })
        .collect()
}

fn print_category_distribution(report: &Report) {
    println!("  Category distribution");
    println!("  ═══════════════════════");
    for (label, count) in category_counts(report) {
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
    fn category_counts_label_to_count_pairing_is_correct() {
        let mut report = Report::new();
        report.push(finding(Severity::High, Category::Security));
        report.push(finding(Severity::High, Category::Security));
        report.push(finding(Severity::Medium, Category::Performance));
        report.push(finding(Severity::Low, Category::Dependency));
        let counts = category_counts(&report);
        let lookup = |needle: &str| -> usize {
            counts
                .iter()
                .find(|(label, _)| *label == needle)
                .map(|(_, n)| *n)
                .unwrap_or(usize::MAX)
        };
        assert_eq!(lookup("Secrets"), 0);
        assert_eq!(lookup("Security"), 2);
        assert_eq!(lookup("Dependencies"), 1);
        assert_eq!(lookup("Performance"), 1);
        assert_eq!(lookup("Crawler"), 0);
        assert_eq!(lookup("Internal"), 0);
    }

    #[test]
    fn category_counts_handles_internal_category_without_panic() {
        let mut report = Report::new();
        report.push(finding(Severity::Info, Category::Internal));
        report.push(finding(Severity::Info, Category::Internal));
        let counts = category_counts(&report);
        let internal = counts
            .iter()
            .find(|(label, _)| *label == "Internal")
            .map(|(_, n)| *n)
            .unwrap_or(0);
        assert_eq!(internal, 2);
    }

    #[test]
    fn category_counts_covers_every_category_variant() {
        for variant in [
            Category::Secret,
            Category::Security,
            Category::Dependency,
            Category::Performance,
            Category::Crawler,
            Category::Internal,
        ] {
            assert!(
                CATEGORY_BUCKETS.iter().any(|(_, c)| *c == variant),
                "category {variant:?} missing from CATEGORY_BUCKETS — summary block would silently drop it"
            );
        }
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

    fn finding_with_message(severity: Severity, message: &str, file: &str, line: usize) -> Finding {
        Finding::new("RSTR-TST-100", message, severity, Category::Security)
            .with_location(Location::file(file).with_line(line, 1))
    }

    #[test]
    fn markdown_document_includes_header_and_tables() {
        let mut report = Report::new();
        report.stats.files_scanned = 12;
        report.perf.total_ms = 250;
        report.push(finding_with_message(
            Severity::High,
            "hardcoded token",
            "src/a.rs",
            10,
        ));
        let md = markdown_document(&report);
        assert!(md.starts_with("## rastray scan — 1 findings across 12 files in 0.25s"));
        assert!(md.contains("### Severity"));
        assert!(md.contains("| High | 1 |"));
        assert!(md.contains("### Category"));
        assert!(md.contains("| Security | 1 |"));
        assert!(md.contains("### Findings"));
        assert!(md.contains("`RSTR-TST-100`"));
        assert!(md.contains("hardcoded token"));
        assert!(md.contains("src/a.rs:10:1"));
    }

    #[test]
    fn markdown_document_reports_empty_findings_cleanly() {
        let report = Report::new();
        let md = markdown_document(&report);
        assert!(md.contains("0 findings"));
        assert!(md.contains("No findings. ✓"));
        assert!(!md.contains("### Findings\n\n<details"));
    }

    #[test]
    fn markdown_document_caps_high_at_ten_and_notes_omission() {
        let mut report = Report::new();
        for i in 0..15 {
            report.push(finding_with_message(
                Severity::High,
                &format!("issue {i}"),
                "src/a.rs",
                i + 1,
            ));
        }
        let md = markdown_document(&report);
        assert!(md.contains("<strong>HIGH</strong> — showing 10 of 15"));
        assert!(md.contains("5 more high finding(s) omitted"));
        assert!(md.contains("Showing 10 of 15 findings"));
    }

    #[test]
    fn markdown_document_shows_all_critical_without_cap() {
        let mut report = Report::new();
        for i in 0..50 {
            report.push(finding_with_message(
                Severity::Critical,
                &format!("crit {i}"),
                "src/a.rs",
                i + 1,
            ));
        }
        let md = markdown_document(&report);
        assert!(md.contains("<strong>CRITICAL</strong> — showing 50 of 50"));
        assert!(!md.contains("more critical finding(s) omitted"));
    }

    #[test]
    fn markdown_document_skips_info_bucket_entirely() {
        let mut report = Report::new();
        report.push(finding_with_message(
            Severity::Info,
            "informational note",
            "src/a.rs",
            1,
        ));
        let md = markdown_document(&report);
        assert!(!md.contains("informational note"));
        assert!(md.contains("Showing 0 of 1 findings"));
    }

    #[test]
    fn escape_markdown_cell_escapes_pipes_and_collapses_newlines() {
        assert_eq!(escape_markdown_cell("a | b"), r"a \| b");
        assert_eq!(escape_markdown_cell("line1\nline2"), "line1 line2");
        assert_eq!(escape_markdown_cell("line1\r\nline2"), "line1  line2");
        assert_eq!(escape_markdown_cell(r"a\b"), r"a\\b");
    }

    #[test]
    fn format_markdown_location_strips_windows_extended_prefix() {
        let f = finding_with_message(Severity::High, "x", r"\\?\C:\proj\src\a.rs", 5);
        let s = format_markdown_location(&f);
        assert!(s.contains("C:\\proj\\src\\a.rs:5:1"));
        assert!(!s.contains(r"\\?\"));
    }

    fn html_finding(severity: Severity, message: &str, file: &str, line: usize) -> Finding {
        Finding::new("RSTR-TST-300", message, severity, Category::Security)
            .with_help("do the thing")
            .with_location(Location::file(file).with_line(line, 1))
    }

    #[test]
    fn html_document_includes_required_sections() {
        let mut report = Report::new();
        report.stats.files_scanned = 5;
        report.perf.total_ms = 420;
        report.push(html_finding(
            Severity::High,
            "tag with <script>",
            "src/a.rs",
            10,
        ));
        let html = html_document(&report);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<title>rastray scan — 1 findings</title>"));
        assert!(html.contains("class=\"donut\""));
        assert!(html.contains("class=\"bars\""));
        assert!(html.contains("id=\"findings-table\""));
        assert!(html.contains("class=\"sev sev-high\""));
        assert!(html.contains("data-severity=\"high\""));
        assert!(html.contains("RSTR-TST-300"));
        assert!(html.contains("tag with &lt;script&gt;"));
        assert!(!html.contains("tag with <script>"));
        assert!(html.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn html_document_renders_empty_findings_with_placeholder() {
        let report = Report::new();
        let html = html_document(&report);
        assert!(html.contains("No findings. ✓"));
        assert!(html.contains("class=\"donut\""));
    }

    #[test]
    fn html_render_requires_output_path() {
        let report = Report::new();
        let res = render_html(&report, None);
        assert!(matches!(res, Err(ReporterError::HtmlRequiresOutputPath)));
    }

    #[test]
    fn html_donut_includes_segment_per_nonzero_severity() {
        let mut report = Report::new();
        report.push(finding(Severity::Critical, Category::Security));
        report.push(finding(Severity::Medium, Category::Performance));
        let svg = render_severity_donut(&report);
        assert!(svg.contains("seg-critical"));
        assert!(svg.contains("seg-medium"));
        assert!(!svg.contains("seg-high stroke-width=\"6\" stroke-dasharray"));
    }

    #[test]
    fn escape_html_text_escapes_lt_gt_amp() {
        assert_eq!(
            escape_html_text("a < b && c > d"),
            "a &lt; b &amp;&amp; c &gt; d"
        );
        assert_eq!(escape_html_text("plain"), "plain");
    }

    #[test]
    fn escape_html_attr_also_escapes_quotes() {
        assert_eq!(escape_html_attr("a\"b'c"), "a&quot;b&#39;c");
    }

    #[test]
    fn render_finding_row_uses_title_attr_for_help_text() {
        let f = html_finding(Severity::Medium, "msg", "src/a.rs", 1);
        let row = render_finding_row(&f);
        assert!(row.contains(" title=\"do the thing\""));
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
