#![allow(dead_code)]

mod baseline;
mod cli;
mod config;
mod crawler;
mod git_changes;
mod lsp;
mod modules;
mod reporter;
mod sbom;
mod suppression;

use std::process::ExitCode;

use miette::Diagnostic;
use thiserror::Error;

use crate::baseline::{Baseline, BaselineError};
use crate::cli::{Cli, Command, FailOn, OutputFormat, Severity};
use crate::config::{Config, ConfigError};
use crate::crawler::{CrawlSummary, FileKind};
use crate::git_changes::{changed_files_since, resolve_reference, GitChangesError};
use crate::modules::dependencies::collect_packages;
use crate::modules::{default_registry, Analyzer, AnalyzerError};
use crate::reporter::{Category, Finding, Report, ReporterError};
use crate::sbom::{render_cyclonedx, render_spdx_json, SbomError};
use crate::suppression::Suppressions;

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

    #[error(transparent)]
    #[diagnostic(code(rastray::baseline))]
    Baseline(#[from] BaselineError),

    #[error(transparent)]
    #[diagnostic(code(rastray::git))]
    GitChanges(#[from] GitChangesError),

    #[error(transparent)]
    #[diagnostic(code(rastray::sbom))]
    Sbom(#[from] SbomError),
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

    if matches!(cli.command, Some(Command::Lsp)) {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                eprintln!("failed to start runtime for lsp: {err}");
                return ExitCode::from(exit::RUNTIME_ERROR);
            }
        };
        runtime.block_on(lsp::run_lsp_server());
        return ExitCode::from(exit::OK);
    }

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
    let mut crawl = crawler::walk_project(&cli)?;
    if let Some(reference) = resolve_reference(cli.since.as_deref(), cli.changed_only) {
        let changed = changed_files_since(&cli.path, &reference)?;
        crawl
            .files
            .retain(|f| match std::fs::canonicalize(&f.path) {
                Ok(canonical) => changed.contains(&canonical),
                Err(_) => changed.contains(&f.path),
            });
    }
    let walk_ms = walk_start.elapsed().as_millis() as u64;

    if matches!(format, OutputFormat::Cyclonedx | OutputFormat::SpdxJson) {
        let packages = collect_packages(&crawl);
        let tool_version = env!("CARGO_PKG_VERSION");
        match format {
            OutputFormat::Cyclonedx => {
                render_cyclonedx(&packages, tool_version, cli.output.as_deref())?;
            }
            OutputFormat::SpdxJson => {
                render_spdx_json(&packages, tool_version, cli.output.as_deref())?;
            }
            _ => {}
        }
        let _ = walk_ms;
        return Ok(exit::OK);
    }

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

    let mut suppressions = Suppressions::new();
    suppressions.apply(&mut report.findings);

    if let Some(path) = &cli.write_baseline {
        let snapshot = Baseline::from_findings(&report.findings);
        snapshot.write(path)?;
    }

    if let Some(path) = &cli.baseline {
        let baseline = Baseline::load(path)?;
        baseline.apply(&mut report.findings);
    }

    report.apply_min_severity(min_severity);

    report.perf.walk_ms = walk_ms;
    report.perf.analyze_ms = analyze_ms;
    report.perf.total_ms = total_start.elapsed().as_millis() as u64;

    report.render(format, cli.output.as_deref())?;

    let exit_code = match resolve_fail_threshold(&cli, &config) {
        Some(threshold) if report.has_at_or_above(threshold) => exit::FINDINGS,
        _ => exit::OK,
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

fn resolve_fail_threshold(cli: &Cli, config: &Config) -> Option<Severity> {
    let setting = cli.fail_on.or_else(|| config.fail_on());
    match setting {
        Some(FailOn::Never) => None,
        Some(FailOn::AtOrAbove(sev)) => Some(sev),
        None => Some(cli.min_severity),
    }
}
