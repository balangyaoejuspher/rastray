#![allow(dead_code)]

mod autofix;
mod baseline;
mod cli;
mod config;
mod crawler;
mod git_changes;
mod history;
mod image;
mod lsp;
mod modules;
mod reporter;
mod sbom;
mod suppression;

use std::process::ExitCode;

use miette::Diagnostic;
use thiserror::Error;

use crate::autofix::{
    plan_and_apply as autofix_apply, print_previews as autofix_print, AutoFixError,
};
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

    #[error(transparent)]
    #[diagnostic(code(rastray::autofix))]
    AutoFix(#[from] AutoFixError),

    #[error(transparent)]
    #[diagnostic(code(rastray::history))]
    History(#[from] history::HistoryScanError),

    #[error(transparent)]
    #[diagnostic(code(rastray::image))]
    Image(#[from] image::ImageScanError),
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

    if let Some(Command::Secrets {
        history,
        since,
        max_commits,
        path,
    }) = &cli.command
    {
        let code = match run_secrets_subcommand(
            *history,
            since.clone(),
            *max_commits,
            path.clone(),
            cli.effective_format(),
            cli.output.clone(),
            cli.min_severity,
            cli.min_confidence,
        ) {
            Ok(c) => c,
            Err(err) => {
                let report: miette::Report = err.into();
                eprintln!("{report:?}");
                exit::RUNTIME_ERROR
            }
        };
        return ExitCode::from(code);
    }

    if let Some(Command::Image {
        max_file_bytes,
        archive,
    }) = &cli.command
    {
        let code = match run_image_subcommand(
            archive.clone(),
            *max_file_bytes,
            cli.effective_format(),
            cli.output.clone(),
            cli.min_severity,
            cli.min_confidence,
        ) {
            Ok(c) => c,
            Err(err) => {
                let report: miette::Report = err.into();
                eprintln!("{report:?}");
                exit::RUNTIME_ERROR
            }
        };
        return ExitCode::from(code);
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
    run_analyzers(&cli, &config, &crawl, &mut report);
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

    if cli.fix {
        let outcome = autofix_apply(&report.findings, &cli.path, cli.fix_yes)?;
        autofix_print(&outcome, cli.fix_yes);
        return Ok(exit::OK);
    }

    report.apply_min_severity(min_severity);
    report.apply_min_confidence(cli.min_confidence);

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

fn run_analyzers(cli: &Cli, config: &Config, crawl: &CrawlSummary, report: &mut Report) {
    for analyzer in default_registry(cli, config) {
        match analyzer.analyze(crawl) {
            Ok(findings) => {
                let kept = findings
                    .into_iter()
                    .filter(|f| cli.no_default_skip || !is_default_noise(f));
                report.extend(kept);
            }
            Err(err) => report.push(analyzer_error_finding(analyzer.as_ref(), err)),
        }
    }
}

const NOISY_IN_TEST_PATHS: &[&str] = &["RSTR-SEC-007", "RSTR-SEC-006"];

const TEST_PATH_SEGMENTS: &[&str] = &[
    "tests",
    "test",
    "unittests",
    "unittest",
    "spec",
    "specs",
    "__tests__",
    "fixtures",
    "fixture",
    "samples",
    "sample",
    "examples",
    "example",
    "testdata",
    "test-fixtures",
    "test_fixtures",
];

fn is_default_noise(finding: &Finding) -> bool {
    if !NOISY_IN_TEST_PATHS.contains(&finding.code.as_str()) {
        return false;
    }
    let Some(location) = &finding.location else {
        return false;
    };
    looks_like_test_path(&location.file)
}

fn looks_like_test_path(path: &std::path::Path) -> bool {
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            if let Some(s) = name.to_str() {
                let lower = s.to_ascii_lowercase();
                if TEST_PATH_SEGMENTS.iter().any(|seg| *seg == lower) {
                    return true;
                }
            }
        }
    }
    false
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

#[allow(clippy::too_many_arguments)]
fn run_secrets_subcommand(
    history: bool,
    since: Option<String>,
    max_commits: Option<usize>,
    path: std::path::PathBuf,
    format: OutputFormat,
    output: Option<std::path::PathBuf>,
    min_severity: Severity,
    min_confidence: cli::Confidence,
) -> Result<u8, AppError> {
    if !history {
        eprintln!("`rastray secrets` currently requires --history; for a working-tree scan use `rastray <path>`");
        return Ok(exit::RUNTIME_ERROR);
    }

    let opts = history::HistoryScanOptions { since, max_commits };
    let result = history::scan_history(&path, &opts)?;

    let mut report = Report::new();
    for f in result.findings {
        report.push(f);
    }
    report.stats.files_scanned = result.stats.blobs_scanned;

    report.apply_min_severity(min_severity);
    report.apply_min_confidence(min_confidence);

    report.render(format, output.as_deref())?;

    Ok(if report.findings.is_empty() {
        exit::OK
    } else {
        exit::FINDINGS
    })
}

fn run_image_subcommand(
    archive: std::path::PathBuf,
    max_file_bytes: u64,
    format: OutputFormat,
    output: Option<std::path::PathBuf>,
    min_severity: Severity,
    min_confidence: cli::Confidence,
) -> Result<u8, AppError> {
    let opts = image::ImageScanOptions { max_file_bytes };
    let result = image::scan_image_archive(&archive, &opts)?;

    let mut report = Report::new();
    for f in result.findings {
        report.push(f);
    }
    report.stats.files_scanned = result.stats.files_scanned;

    report.apply_min_severity(min_severity);
    report.apply_min_confidence(min_confidence);

    report.render(format, output.as_deref())?;

    Ok(if report.findings.is_empty() {
        exit::OK
    } else {
        exit::FINDINGS
    })
}

#[cfg(test)]
mod default_skip_tests {
    use super::*;
    use crate::reporter::Location;
    use std::path::PathBuf;

    fn finding_with(code: &str, path: &str) -> Finding {
        Finding::new(code, "msg", Severity::High, Category::Security)
            .with_location(Location::file(PathBuf::from(path)))
    }

    #[test]
    fn sec_007_in_fixtures_is_skipped() {
        let f = finding_with("RSTR-SEC-007", "/repo/tests/fixtures/private-key.pem");
        assert!(is_default_noise(&f));
    }

    #[test]
    fn sec_007_in_repo_root_is_not_skipped() {
        let f = finding_with("RSTR-SEC-007", "/repo/secrets.pem");
        assert!(!is_default_noise(&f));
    }

    #[test]
    fn unrelated_rule_is_never_skipped() {
        let f = finding_with("RSTR-INJ-001", "/repo/tests/test_sqli.py");
        assert!(!is_default_noise(&f));
    }

    #[test]
    fn finding_without_location_is_not_skipped() {
        let f = Finding::new("RSTR-SEC-007", "msg", Severity::High, Category::Security);
        assert!(!is_default_noise(&f));
    }

    #[test]
    fn sec_007_in_unittests_is_skipped() {
        let f = finding_with("RSTR-SEC-007", "/repo/unittests/scans/sample.pem");
        assert!(is_default_noise(&f));
    }
}
