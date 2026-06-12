use crate::crawler::CrawlSummary;
use crate::reporter::Finding;

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct PerformanceAnalyzer;

impl PerformanceAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for PerformanceAnalyzer {
    fn name(&self) -> &'static str {
        "performance"
    }

    fn analyze(&self, _crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        Ok(Vec::new())
    }
}
