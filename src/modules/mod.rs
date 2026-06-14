pub mod crypto;
pub mod dependencies;
pub mod injection;
pub mod performance;
pub mod secrets;

use thiserror::Error;

use crate::cli::Cli;
use crate::crawler::CrawlSummary;
use crate::reporter::Finding;

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("analyzer '{name}' failed: {message}")]
    Failed { name: &'static str, message: String },
}

pub trait Analyzer {
    fn name(&self) -> &'static str;

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError>;
}

pub fn default_registry(cli: &Cli) -> Vec<Box<dyn Analyzer + Send + Sync>> {
    vec![
        Box::new(secrets::SecretsAnalyzer::new()),
        Box::new(crypto::CryptoAnalyzer::new()),
        Box::new(injection::InjectionAnalyzer::new()),
        Box::new(dependencies::DependenciesAnalyzer::with_options(
            cli.offline,
            cli.no_cache,
        )),
        Box::new(performance::PerformanceAnalyzer::new()),
    ]
}
