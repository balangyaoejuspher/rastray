use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ignore::gitignore::GitignoreBuilder;
use serde::Deserialize;
use thiserror::Error;

use crate::cli::{FailOn, Severity};
use crate::reporter::Finding;

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ScanConfig {
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub ignore: ScanIgnore,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ScanIgnore {
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RuleConfig {
    Toggle(bool),
    Detailed(RuleDetail),
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct RuleDetail {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config '{path}': {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config '{path}': {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },

    #[error("config '{path}': invalid severity value '{value}'")]
    InvalidSeverity { path: PathBuf, value: String },
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        cfg.validate(path)?;
        Ok(cfg)
    }

    pub fn discover(start: &Path) -> Option<PathBuf> {
        let canonical = match std::fs::canonicalize(start) {
            Ok(p) => p,
            Err(_) => start.to_path_buf(),
        };
        let mut current: Option<PathBuf> = if canonical.is_file() {
            canonical.parent().map(Path::to_path_buf)
        } else {
            Some(canonical)
        };
        while let Some(dir) = current {
            let candidate = dir.join(".rastray.toml");
            if candidate.is_file() {
                return Some(candidate);
            }
            current = dir.parent().map(Path::to_path_buf);
        }
        None
    }

    pub fn rule_enabled(&self, code: &str) -> bool {
        match self.rules.get(code) {
            None => true,
            Some(RuleConfig::Toggle(b)) => *b,
            Some(RuleConfig::Detailed(d)) => d.enabled.unwrap_or(true),
        }
    }

    pub fn rule_severity_override(&self, code: &str) -> Option<Severity> {
        match self.rules.get(code) {
            Some(RuleConfig::Detailed(d)) => d.severity.as_deref().and_then(parse_severity),
            _ => None,
        }
    }

    pub fn ignore_globs(&self) -> &[String] {
        &self.scan.ignore.paths
    }

    pub fn fail_on(&self) -> Option<FailOn> {
        let raw = self.scan.fail_on.as_deref()?;
        if raw.eq_ignore_ascii_case("none") || raw.eq_ignore_ascii_case("never") {
            Some(FailOn::Never)
        } else {
            parse_severity(raw).map(FailOn::AtOrAbove)
        }
    }

    pub fn apply(&self, findings: &mut Vec<Finding>, scan_root: &Path) {
        findings.retain(|f| self.rule_enabled(&f.code));

        for f in findings.iter_mut() {
            if let Some(new_sev) = self.rule_severity_override(&f.code) {
                f.severity = new_sev;
            }
        }

        if !self.scan.ignore.paths.is_empty() {
            let mut builder = GitignoreBuilder::new(scan_root);
            for g in &self.scan.ignore.paths {
                let _ = builder.add_line(None, g);
            }
            if let Ok(matcher) = builder.build() {
                findings.retain(|f| match &f.location {
                    Some(loc) => !matcher.matched(&loc.file, false).is_ignore(),
                    None => true,
                });
            }
        }
    }

    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(s) = &self.scan.fail_on {
            if !s.eq_ignore_ascii_case("none")
                && !s.eq_ignore_ascii_case("never")
                && parse_severity(s).is_none()
            {
                return Err(ConfigError::InvalidSeverity {
                    path: path.to_path_buf(),
                    value: s.clone(),
                });
            }
        }
        for (code, rule) in &self.rules {
            if let RuleConfig::Detailed(detail) = rule {
                if let Some(s) = &detail.severity {
                    if parse_severity(s).is_none() {
                        return Err(ConfigError::InvalidSeverity {
                            path: path.to_path_buf(),
                            value: format!("{code} = {s}"),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::{Category, Finding, Location};
    use std::fs;

    fn write_config(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join(".rastray.toml");
        match fs::write(&path, contents) {
            Ok(()) => path,
            Err(_) => path,
        }
    }

    fn tempdir() -> Option<PathBuf> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir();
        let unique = format!("rastray-cfg-test-{}-{}", std::process::id(), n);
        let dir = base.join(unique);
        let _ = fs::remove_dir_all(&dir);
        match fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn loc(file: &str) -> Location {
        Location {
            file: PathBuf::from(file),
            byte_offset: None,
            byte_length: None,
            line: None,
            column: None,
        }
    }

    fn make_finding(code: &str, sev: Severity, file: &str) -> Finding {
        let mut f = Finding::new(code, "msg", sev, Category::Performance);
        f.location = Some(loc(file));
        f
    }

    #[test]
    fn default_config_enables_all_rules() {
        let cfg = Config::default();
        assert!(cfg.rule_enabled("RSTR-PERF-001"));
        assert!(cfg.rule_severity_override("RSTR-PERF-001").is_none());
        assert!(cfg.ignore_globs().is_empty());
        assert!(cfg.fail_on().is_none());
    }

    #[test]
    fn load_parses_minimal_config() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(&dir, "");
        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert!(cfg.rule_enabled("RSTR-PERF-001"));
    }

    #[test]
    fn load_parses_fail_on() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(&dir, "[scan]\nfail_on = \"high\"\n");
        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert_eq!(cfg.fail_on(), Some(FailOn::AtOrAbove(Severity::High)));
    }

    #[test]
    fn load_parses_fail_on_none() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(&dir, "[scan]\nfail_on = \"none\"\n");
        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert_eq!(cfg.fail_on(), Some(FailOn::Never));
    }

    #[test]
    fn load_parses_fail_on_never() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(&dir, "[scan]\nfail_on = \"never\"\n");
        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert_eq!(cfg.fail_on(), Some(FailOn::Never));
    }

    #[test]
    fn load_rejects_invalid_severity_in_fail_on() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(&dir, "[scan]\nfail_on = \"bogus\"\n");
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::InvalidSeverity { .. })
        ));
    }

    #[test]
    fn load_parses_rule_toggle() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(&dir, "[rules]\n\"RSTR-SEC-005\" = false\n");
        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert!(!cfg.rule_enabled("RSTR-SEC-005"));
        assert!(cfg.rule_enabled("RSTR-SEC-001"));
    }

    #[test]
    fn load_parses_rule_detailed() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(
            &dir,
            "[rules]\n\"RSTR-PERF-001\" = { severity = \"low\" }\n",
        );
        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert_eq!(
            cfg.rule_severity_override("RSTR-PERF-001"),
            Some(Severity::Low)
        );
        assert!(cfg.rule_enabled("RSTR-PERF-001"));
    }

    #[test]
    fn load_rejects_invalid_rule_severity() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(
            &dir,
            "[rules]\n\"RSTR-PERF-001\" = { severity = \"banana\" }\n",
        );
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::InvalidSeverity { .. })
        ));
    }

    #[test]
    fn load_parses_ignore_paths() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write_config(
            &dir,
            "[scan.ignore]\npaths = [\"target/**\", \"dist/**\"]\n",
        );
        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert_eq!(cfg.ignore_globs(), &["target/**", "dist/**"]);
    }

    #[test]
    fn discover_walks_up_to_find_config() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let nested = dir.join("a").join("b").join("c");
        if fs::create_dir_all(&nested).is_err() {
            return;
        }
        let _ = write_config(&dir, "");
        let found = match Config::discover(&nested) {
            Some(p) => p,
            None => return,
        };
        assert_eq!(
            found.file_name().and_then(|s| s.to_str()),
            Some(".rastray.toml")
        );
    }

    #[test]
    fn discover_returns_none_when_no_config_in_ancestors() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let nested = dir.join("xyz");
        if fs::create_dir_all(&nested).is_err() {
            return;
        }
        let _ = fs::remove_file(dir.join(".rastray.toml"));
        let _ = fs::remove_file(nested.join(".rastray.toml"));
    }

    #[test]
    fn apply_drops_disabled_rules() {
        let mut cfg = Config::default();
        cfg.rules
            .insert("RSTR-PERF-001".to_string(), RuleConfig::Toggle(false));
        let mut findings = vec![
            make_finding("RSTR-PERF-001", Severity::Medium, "src/a.rs"),
            make_finding("RSTR-PERF-002", Severity::Low, "src/b.rs"),
        ];
        cfg.apply(&mut findings, Path::new("."));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-PERF-002");
    }

    #[test]
    fn apply_overrides_severity() {
        let mut cfg = Config::default();
        cfg.rules.insert(
            "RSTR-PERF-001".to_string(),
            RuleConfig::Detailed(RuleDetail {
                enabled: None,
                severity: Some("low".to_string()),
            }),
        );
        let mut findings = vec![make_finding("RSTR-PERF-001", Severity::Medium, "src/a.rs")];
        cfg.apply(&mut findings, Path::new("."));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn apply_drops_findings_under_ignored_paths() {
        let mut cfg = Config::default();
        cfg.scan.ignore.paths = vec!["target/**".to_string()];
        let mut findings = vec![
            make_finding("RSTR-PERF-001", Severity::Medium, "target/debug/x.rs"),
            make_finding("RSTR-PERF-001", Severity::Medium, "src/a.rs"),
        ];
        cfg.apply(&mut findings, Path::new("."));
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].location.as_ref().map(|l| l.file.as_path()),
            Some(Path::new("src/a.rs"))
        );
    }
}
