use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, ValueEnum};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputFormat {
    Human,
    Json,
    GhActions,
    Sarif,
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

    #[arg(long = "json", default_value_t = false)]
    pub json: bool,

    #[arg(long = "format", value_enum)]
    pub format: Option<OutputFormat>,

    #[arg(long = "output", short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    #[arg(long = "summary-only", default_value_t = false)]
    pub summary_only: bool,

    #[arg(long = "offline", default_value_t = false)]
    pub offline: bool,

    #[arg(long = "no-cache", default_value_t = false)]
    pub no_cache: bool,

    #[arg(long = "no-ignore", default_value_t = false)]
    pub no_ignore: bool,

    #[arg(long = "hidden", default_value_t = false)]
    pub include_hidden: bool,

    #[arg(long = "follow-links", default_value_t = false)]
    pub follow_links: bool,

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
