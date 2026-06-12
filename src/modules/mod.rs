pub mod dependencies;
pub mod performance;
pub mod secrets;

use thiserror::Error;

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

pub fn default_registry() -> Vec<Box<dyn Analyzer + Send + Sync>> {
    vec![
        Box::new(secrets::SecretsAnalyzer::new()),
        Box::new(dependencies::DependenciesAnalyzer::new()),
        Box::new(performance::PerformanceAnalyzer::new()),
    ]
}
