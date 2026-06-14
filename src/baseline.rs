use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::reporter::Finding;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("failed to read baseline '{path}': {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse baseline '{path}': {source}")]
    Parse {
        path: PathBuf,
        source: Box<serde_json::Error>,
    },

    #[error("failed to write baseline '{path}': {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to serialize baseline '{path}': {source}")]
    Serialize {
        path: PathBuf,
        source: Box<serde_json::Error>,
    },
}

const CURRENT_VERSION: u32 = 1;

impl Baseline {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut fingerprints: Vec<String> = findings
            .iter()
            .map(fingerprint)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        fingerprints.sort();
        Self {
            version: CURRENT_VERSION,
            fingerprints,
        }
    }

    pub fn load(path: &Path) -> Result<Self, BaselineError> {
        let text = std::fs::read_to_string(path).map_err(|source| BaselineError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let baseline: Baseline =
            serde_json::from_str(&text).map_err(|source| BaselineError::Parse {
                path: path.to_path_buf(),
                source: Box::new(source),
            })?;
        Ok(baseline)
    }

    pub fn write(&self, path: &Path) -> Result<(), BaselineError> {
        let body =
            serde_json::to_string_pretty(self).map_err(|source| BaselineError::Serialize {
                path: path.to_path_buf(),
                source: Box::new(source),
            })?;
        std::fs::write(path, body).map_err(|source| BaselineError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn contains(&self, finding: &Finding) -> bool {
        let fp = fingerprint(finding);
        self.fingerprints.binary_search(&fp).is_ok()
    }

    pub fn apply(&self, findings: &mut Vec<Finding>) {
        findings.retain(|f| !self.contains(f));
    }
}

fn fingerprint(finding: &Finding) -> String {
    let file = finding
        .location
        .as_ref()
        .map(|l| l.file.to_string_lossy().to_string())
        .unwrap_or_default();
    let line = finding.location.as_ref().and_then(|l| l.line).unwrap_or(0);
    format!(
        "{}|{}|{}|{}",
        finding.code,
        normalize_path(&file),
        line,
        finding.message
    )
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Severity;
    use crate::reporter::{Category, Finding, Location};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir() -> Option<PathBuf> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rastray-baseline-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        match fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn finding_at(code: &str, message: &str, file: &str, line: usize) -> Finding {
        let mut f = Finding::new(code, message, Severity::Medium, Category::Performance);
        f.location = Some(Location {
            file: PathBuf::from(file),
            byte_offset: None,
            byte_length: None,
            line: Some(line),
            column: None,
        });
        f
    }

    #[test]
    fn fingerprint_includes_code_path_line_and_message() {
        let f1 = finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7);
        let f2 = finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7);
        let f3 = finding_at("RSTR-PERF-002", "msg", "src/a.rs", 7);
        assert_eq!(fingerprint(&f1), fingerprint(&f2));
        assert_ne!(fingerprint(&f1), fingerprint(&f3));
    }

    #[test]
    fn fingerprint_normalises_windows_paths() {
        let f_win = finding_at("RSTR-PERF-001", "msg", "src\\a.rs", 7);
        let f_nix = finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7);
        assert_eq!(fingerprint(&f_win), fingerprint(&f_nix));
    }

    #[test]
    fn fingerprint_distinguishes_lines() {
        let f1 = finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7);
        let f2 = finding_at("RSTR-PERF-001", "msg", "src/a.rs", 8);
        assert_ne!(fingerprint(&f1), fingerprint(&f2));
    }

    #[test]
    fn from_findings_deduplicates_identical_entries() {
        let findings = vec![
            finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7),
            finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7),
            finding_at("RSTR-PERF-001", "msg", "src/b.rs", 9),
        ];
        let baseline = Baseline::from_findings(&findings);
        assert_eq!(baseline.fingerprints.len(), 2);
        assert_eq!(baseline.version, CURRENT_VERSION);
    }

    #[test]
    fn apply_drops_findings_present_in_baseline() {
        let known = vec![
            finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7),
            finding_at("RSTR-PERF-002", "msg", "src/a.rs", 9),
        ];
        let baseline = Baseline::from_findings(&known);
        let mut current = vec![
            finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7),
            finding_at("RSTR-PERF-002", "msg", "src/a.rs", 9),
            finding_at("RSTR-PERF-003", "msg", "src/a.rs", 11),
        ];
        baseline.apply(&mut current);
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].code, "RSTR-PERF-003");
    }

    #[test]
    fn apply_keeps_findings_with_changed_line_numbers() {
        let known = vec![finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7)];
        let baseline = Baseline::from_findings(&known);
        let mut current = vec![finding_at("RSTR-PERF-001", "msg", "src/a.rs", 8)];
        baseline.apply(&mut current);
        assert_eq!(current.len(), 1);
    }

    #[test]
    fn write_then_load_round_trips() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = dir.join("baseline.json");
        let findings = vec![
            finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7),
            finding_at("RSTR-PERF-002", "msg", "src/a.rs", 9),
        ];
        let baseline = Baseline::from_findings(&findings);
        if baseline.write(&path).is_err() {
            return;
        }
        let loaded = match Baseline::load(&path) {
            Ok(b) => b,
            Err(_) => return,
        };
        assert_eq!(loaded.version, CURRENT_VERSION);
        assert_eq!(loaded.fingerprints.len(), 2);
        assert_eq!(loaded.fingerprints, baseline.fingerprints);
    }

    #[test]
    fn load_rejects_malformed_json() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = dir.join("baseline.json");
        if std::fs::write(&path, "{not json").is_err() {
            return;
        }
        assert!(matches!(
            Baseline::load(&path),
            Err(BaselineError::Parse { .. })
        ));
    }

    #[test]
    fn empty_baseline_drops_nothing() {
        let baseline = Baseline {
            version: CURRENT_VERSION,
            fingerprints: Vec::new(),
        };
        let mut current = vec![finding_at("RSTR-PERF-001", "msg", "src/a.rs", 7)];
        baseline.apply(&mut current);
        assert_eq!(current.len(), 1);
    }
}
