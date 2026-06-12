use crate::crawler::CrawlSummary;
use crate::reporter::Finding;

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct DependenciesAnalyzer;

impl DependenciesAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for DependenciesAnalyzer {
    fn name(&self) -> &'static str {
        "dependencies"
    }

    fn analyze(&self, _crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        Ok(Vec::new())
    }
}
