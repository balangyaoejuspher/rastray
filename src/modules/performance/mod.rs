use std::fs;
use std::path::Path;

use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::Finding;

use super::{Analyzer, AnalyzerError};

mod go;
mod python;
mod rust;
mod shared;
mod typescript;

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

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let mut findings = Vec::new();
        for file in &crawl.files {
            if file.kind != FileKind::Source {
                continue;
            }
            let ext = file
                .path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase());
            let Some(ext) = ext else {
                continue;
            };
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            findings.extend(analyze_file(&ext, &file.path, &contents));
        }
        Ok(findings)
    }
}

fn analyze_file(ext: &str, path: &Path, source: &str) -> Vec<Finding> {
    match ext {
        "rs" => rust::analyze(path, source),
        "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => typescript::analyze(path, source),
        "py" => python::analyze(path, source),
        "go" => go::analyze(path, source),
        _ => Vec::new(),
    }
}
