#![allow(dead_code)]

mod cli;
mod config;
mod crawler;
mod modules;
mod reporter;

use std::process::ExitCode;

use miette::Diagnostic;
use thiserror::Error;

use crate::cli::{Cli, Severity};
use crate::config::{Config, ConfigError};
use crate::crawler::{CrawlSummary, FileKind};
use crate::modules::{default_registry, Analyzer, AnalyzerError};
use crate::reporter::{Category, Finding, Report, ReporterError};

#[derive(Debug, Error, Diagnostic)]
enum AppError {
    #[error(transparent)]
    #[diagnostic(code(rastray::crawl))]
    Crawl(#[from] crawler::CrawlError),

    #[error(transparent)]
    #[diagnostic(code(rastray::report))]
    Report(#[from] ReporterError),

    #[error(transparent)]
    #[diagnostic(code(rastray::config))]
    Config(#[from] ConfigError),
}

mod exit {
    pub const OK: u8 = 0;
    pub const FINDINGS: u8 = 1;
    pub const RUNTIME_ERROR: u8 = 2;
}

fn main() -> ExitCode {
    let _ = miette::set_hook(Box::new(|_| {
        Box::new(
            miette::MietteHandlerOpts::new()
                .terminal_links(true)
                .unicode(true)
                .context_lines(2)
                .build(),
        )
    }));

    let cli = Cli::parsed();

    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            let report: miette::Report = err.into();
            eprintln!("{report:?}");
            ExitCode::from(exit::RUNTIME_ERROR)
        }
    }
}

fn run(cli: Cli) -> Result<u8, AppError> {
    let total_start = std::time::Instant::now();
    let format = cli.effective_format();
    let min_severity = cli.min_severity;
    let summary_only = cli.summary_only;

    let config = load_config(&cli)?;

    let walk_start = std::time::Instant::now();
    let crawl = crawler::walk_project(&cli)?;
    let walk_ms = walk_start.elapsed().as_millis() as u64;

    let mut report = Report::new();
    report.summary_only = summary_only;
    populate_stats(&mut report, &crawl);

    for err in &crawl.errors {
        report.push(
            Finding::new(
                "RSTR-CRAWL-001",
                format!("crawl warning: {err}"),
                Severity::Info,
                Category::Crawler,
            )
            .with_help("review filesystem permissions and re-run the scan"),
        );
    }

    let analyze_start = std::time::Instant::now();
    run_analyzers(&cli, &crawl, &mut report);
    let analyze_ms = analyze_start.elapsed().as_millis() as u64;

    config.apply(&mut report.findings, &cli.path);

    report.apply_min_severity(min_severity);

    report.perf.walk_ms = walk_ms;
    report.perf.analyze_ms = analyze_ms;
    report.perf.total_ms = total_start.elapsed().as_millis() as u64;

    report.render(format, cli.output.as_deref())?;

    let exit_code = if report.has_at_or_above(min_severity) {
        exit::FINDINGS
    } else {
        exit::OK
    };

    Ok(exit_code)
}

fn populate_stats(report: &mut Report, crawl: &CrawlSummary) {
    let stats = &mut report.stats;
    stats.files_scanned = crawl.total();
    stats.manifests = crawl.count_of(FileKind::Manifest);
    stats.source_files = crawl.count_of(FileKind::Source);
    stats.config_files = crawl.count_of(FileKind::Config);
    stats.other_files = crawl.count_of(FileKind::Other);
    stats.crawl_errors = crawl.errors.len();
    stats.skipped = crawl.skipped;
    report.perf.bytes_scanned = crawl.files.iter().filter_map(|f| f.size).sum();
}

fn run_analyzers(cli: &Cli, crawl: &CrawlSummary, report: &mut Report) {
    for analyzer in default_registry(cli) {
        match analyzer.analyze(crawl) {
            Ok(findings) => report.extend(findings),
            Err(err) => report.push(analyzer_error_finding(analyzer.as_ref(), err)),
        }
    }
}

fn analyzer_error_finding(analyzer: &(dyn Analyzer + Send + Sync), err: AnalyzerError) -> Finding {
    Finding::new(
        "RSTR-INT-001",
        format!("analyzer '{}' failed: {err}", analyzer.name()),
        Severity::Medium,
        Category::Internal,
    )
    .with_help("re-run with --verbose for additional context")
}

fn load_config(cli: &Cli) -> Result<Config, ConfigError> {
    if cli.no_config {
        return Ok(Config::default());
    }
    if let Some(path) = &cli.config {
        return Config::load(path);
    }
    match Config::discover(&cli.path) {
        Some(path) => Config::load(&path),
        None => Ok(Config::default()),
    }
}
