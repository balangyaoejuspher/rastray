use crate::crawler::CrawlSummary;
use crate::reporter::Finding;

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct SecretsAnalyzer;

impl SecretsAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for SecretsAnalyzer {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn analyze(&self, _crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        Ok(Vec::new())
    }
}
