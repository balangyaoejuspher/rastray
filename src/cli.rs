use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!("unknown severity '{other}'")),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    #[default]
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "med",
            Confidence::High => "high",
        }
    }
}

impl FromStr for Confidence {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Confidence::Low),
            "medium" | "med" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            other => Err(format!("unknown confidence '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputFormat {
    Human,
    Json,
    GhActions,
    Sarif,
    Markdown,
    Html,
    Cyclonedx,
    SpdxJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    Never,
    AtOrAbove(Severity),
}

impl FailOn {
    pub fn as_threshold(self) -> Option<Severity> {
        match self {
            FailOn::Never => None,
            FailOn::AtOrAbove(s) => Some(s),
        }
    }
}

fn parse_fail_on(s: &str) -> Result<FailOn, String> {
    if s.eq_ignore_ascii_case("never") || s.eq_ignore_ascii_case("none") {
        Ok(FailOn::Never)
    } else {
        s.parse::<Severity>().map(FailOn::AtOrAbove)
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "rastray",
    author,
    version,
    about = "Blazing-fast static analysis for security, dependencies, and performance.",
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: PathBuf,

    #[arg(long = "min-severity", value_enum, default_value_t = Severity::Low)]
    pub min_severity: Severity,

    #[arg(long = "min-confidence", value_enum, default_value_t = Confidence::Low)]
    pub min_confidence: Confidence,

    #[arg(long = "json", default_value_t = false)]
    pub json: bool,

    #[arg(long = "format", value_enum)]
    pub format: Option<OutputFormat>,

    #[arg(long = "output", short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    #[arg(long = "config", value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(long = "no-config", default_value_t = false)]
    pub no_config: bool,

    #[arg(long = "fail-on", value_name = "LEVEL", value_parser = parse_fail_on)]
    pub fail_on: Option<FailOn>,

    #[arg(long = "baseline", value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    #[arg(long = "write-baseline", value_name = "FILE")]
    pub write_baseline: Option<PathBuf>,

    #[arg(long = "since", value_name = "REF")]
    pub since: Option<String>,

    #[arg(long = "changed-only", default_value_t = false)]
    pub changed_only: bool,

    #[arg(long = "summary-only", default_value_t = false)]
    pub summary_only: bool,

    #[arg(long = "fix", default_value_t = false)]
    pub fix: bool,

    #[arg(long = "yes", default_value_t = false)]
    pub fix_yes: bool,

    #[arg(long = "offline", default_value_t = false)]
    pub offline: bool,

    #[arg(long = "no-cache", default_value_t = false)]
    pub no_cache: bool,

    #[arg(long = "no-default-skip", default_value_t = false)]
    pub no_default_skip: bool,

    #[arg(long = "no-ignore", default_value_t = false)]
    pub no_ignore: bool,

    #[arg(long = "hidden", default_value_t = false)]
    pub include_hidden: bool,

    #[arg(long = "follow-links", default_value_t = false)]
    pub follow_links: bool,

    #[arg(long = "include-minified", default_value_t = false)]
    pub include_minified: bool,

    #[arg(long = "threads", short = 'j', value_name = "N")]
    pub threads: Option<usize>,

    #[arg(long = "max-depth", value_name = "N")]
    pub max_depth: Option<usize>,

    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(
        short = 'q',
        long = "quiet",
        default_value_t = false,
        conflicts_with = "verbose"
    )]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Lsp,
    Secrets {
        #[arg(long = "history", default_value_t = false)]
        history: bool,

        #[arg(long = "since", value_name = "REF")]
        since: Option<String>,

        #[arg(long = "max-commits", value_name = "N")]
        max_commits: Option<usize>,

        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
    },
    Image {
        #[arg(long = "max-file-bytes", value_name = "N", default_value_t = 4 * 1024 * 1024)]
        max_file_bytes: u64,

        #[arg(value_name = "ARCHIVE")]
        archive: PathBuf,
    },
    InstallHooks {
        #[arg(long = "force", default_value_t = false)]
        force: bool,

        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
    },
}

impl Cli {
    pub fn parsed() -> Self {
        Self::parse()
    }

    pub fn effective_format(&self) -> OutputFormat {
        if let Some(fmt) = self.format {
            return fmt;
        }
        if self.json {
            OutputFormat::Json
        } else {
            OutputFormat::Human
        }
    }
}
