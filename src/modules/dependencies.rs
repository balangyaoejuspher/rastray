use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::runtime::Builder;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns/";
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT: &str = concat!("rastray/", env!("CARGO_PKG_VERSION"));

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

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let lockfiles = collect_cargo_lockfiles(crawl);
        if lockfiles.is_empty() {
            return Ok(Vec::new());
        }

        let mut packages: Vec<(PathBuf, RustPackage)> = Vec::new();
        for lockfile in &lockfiles {
            if let Ok(pkgs) = read_cargo_lock(lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        if packages.is_empty() {
            return Ok(Vec::new());
        }

        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| AnalyzerError::Failed {
                name: "dependencies",
                message: format!("could not start tokio runtime: {e}"),
            })?;

        let results =
            runtime
                .block_on(query_osv_batch(&packages))
                .map_err(|e| AnalyzerError::Failed {
                    name: "dependencies",
                    message: format!("OSV query failed: {e}"),
                })?;

        let mut findings = Vec::new();
        for (idx, vulns) in results.iter().enumerate() {
            let Some((path, pkg)) = packages.get(idx) else {
                continue;
            };
            for vuln in vulns {
                findings.push(build_finding(path, pkg, vuln));
            }
        }

        Ok(findings)
    }
}

fn collect_cargo_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    crawl
        .files
        .iter()
        .filter(|f| f.kind == FileKind::Manifest)
        .filter_map(|f| {
            let name = f
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase());
            if name.as_deref() == Some("cargo.lock") {
                Some(f.path.clone())
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
struct RustPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<RustPackage>,
}

fn read_cargo_lock(path: &Path) -> Result<Vec<RustPackage>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let lock: CargoLock = toml::from_str(&contents).map_err(|e| ParseError::Toml(e.to_string()))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| {
            p.source
                .as_deref()
                .is_some_and(|s| s.starts_with("registry+"))
        })
        .collect())
}

#[derive(Debug)]
enum ParseError {
    Io(std::io::Error),
    Toml(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "io error: {e}"),
            ParseError::Toml(e) => write!(f, "toml parse error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Serialize)]
struct OsvBatchRequest<'a> {
    queries: Vec<OsvQuery<'a>>,
}

#[derive(Serialize)]
struct OsvQuery<'a> {
    package: OsvPackage<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    ecosystem: &'static str,
    name: &'a str,
}

#[derive(Deserialize, Debug, Default)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvResult>,
}

#[derive(Deserialize, Debug, Default)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVulnRef>,
}

#[derive(Deserialize, Debug, Clone)]
struct OsvVulnRef {
    id: String,
}

#[derive(Deserialize, Debug, Default, Clone)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default, rename = "database_specific")]
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Deserialize, Debug, Clone)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize, Debug, Default, Clone)]
struct OsvDatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

async fn query_osv_batch(
    packages: &[(PathBuf, RustPackage)],
) -> Result<Vec<Vec<OsvVuln>>, reqwest::Error> {
    let queries: Vec<OsvQuery> = packages
        .iter()
        .map(|(_, p)| OsvQuery {
            package: OsvPackage {
                ecosystem: "crates.io",
                name: &p.name,
            },
            version: &p.version,
        })
        .collect();

    let body = OsvBatchRequest { queries };

    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()?;

    let resp: OsvBatchResponse = client
        .post(OSV_BATCH_URL)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut hydrated = Vec::with_capacity(resp.results.len());
    for result in resp.results {
        let mut vulns = Vec::with_capacity(result.vulns.len());
        for vuln_ref in result.vulns {
            match fetch_vuln(&client, &vuln_ref.id).await {
                Ok(v) => vulns.push(v),
                Err(_) => vulns.push(OsvVuln {
                    id: vuln_ref.id,
                    ..OsvVuln::default()
                }),
            }
        }
        hydrated.push(vulns);
    }

    Ok(hydrated)
}

async fn fetch_vuln(client: &reqwest::Client, id: &str) -> Result<OsvVuln, reqwest::Error> {
    let url = format!("{OSV_VULN_URL}{id}");
    client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

fn build_finding(lockfile: &Path, pkg: &RustPackage, vuln: &OsvVuln) -> Finding {
    let summary = vuln
        .summary
        .clone()
        .or_else(|| vuln.details.clone())
        .unwrap_or_else(|| format!("advisory {} affects {} {}", vuln.id, pkg.name, pkg.version));
    let severity = pick_severity(vuln);
    Finding::new(
        format!("RSTR-DEP-{}", vuln.id),
        format!("{} {} :: {}", pkg.name, pkg.version, summary),
        severity,
        Category::Dependency,
    )
    .with_help(advisory_url(&vuln.id))
    .with_location(Location::file(lockfile.to_path_buf()))
}

fn pick_severity(vuln: &OsvVuln) -> Severity {
    let cvss_score = vuln
        .severity
        .iter()
        .find(|s| s.kind.eq_ignore_ascii_case("CVSS_V3") || s.kind.eq_ignore_ascii_case("CVSS_V4"))
        .and_then(|s| extract_cvss_score(&s.score));

    if let Some(s) = cvss_score {
        return match s {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            _ => Severity::Low,
        };
    }

    if let Some(rating) = vuln
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_ref())
    {
        return match rating.to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MODERATE" | "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Medium,
        };
    }

    Severity::Medium
}

fn extract_cvss_score(vector: &str) -> Option<f64> {
    if let Some(rest) = vector.split('/').find_map(|seg| seg.strip_prefix("BS:")) {
        if let Ok(v) = rest.parse::<f64>() {
            return Some(v);
        }
    }
    vector.parse::<f64>().ok()
}

fn advisory_url(id: &str) -> String {
    if id.starts_with("RUSTSEC-") {
        format!("https://rustsec.org/advisories/{id}")
    } else if id.starts_with("GHSA-") {
        format!("https://github.com/advisories/{id}")
    } else {
        format!("https://osv.dev/vulnerability/{id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_cargo_lock_extracts_registry_packages() {
        let body = r#"
            [[package]]
            name = "registry-pkg"
            version = "1.2.3"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "git-pkg"
            version = "0.1.0"
            source = "git+https://github.com/example/repo"

            [[package]]
            name = "local-pkg"
            version = "0.0.1"
            "#;
        let tmp = std::env::temp_dir().join(format!("rastray-test-lock-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_cargo_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "registry-pkg");
        assert_eq!(pkgs[0].version, "1.2.3");
    }

    #[test]
    fn read_cargo_lock_returns_empty_when_no_packages() {
        let tmp = std::env::temp_dir().join(format!("rastray-test-empty-{}", std::process::id()));
        let _ = std::fs::write(&tmp, "version = 4\n");
        let parsed = read_cargo_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        if let Ok(pkgs) = parsed {
            assert_eq!(pkgs.len(), 0);
        }
    }

    #[test]
    fn pick_severity_maps_critical_band() {
        let vuln = OsvVuln {
            severity: vec![OsvSeverity {
                kind: "CVSS_V3".to_string(),
                score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/BS:9.8".to_string(),
            }],
            ..OsvVuln::default()
        };
        assert_eq!(pick_severity(&vuln), Severity::Critical);
    }

    #[test]
    fn pick_severity_maps_high_band() {
        let vuln = OsvVuln {
            severity: vec![OsvSeverity {
                kind: "CVSS_V3".to_string(),
                score: "BS:7.5".to_string(),
            }],
            ..OsvVuln::default()
        };
        assert_eq!(pick_severity(&vuln), Severity::High);
    }

    #[test]
    fn pick_severity_maps_medium_band() {
        let vuln = OsvVuln {
            severity: vec![OsvSeverity {
                kind: "CVSS_V3".to_string(),
                score: "BS:5.4".to_string(),
            }],
            ..OsvVuln::default()
        };
        assert_eq!(pick_severity(&vuln), Severity::Medium);
    }

    #[test]
    fn pick_severity_maps_low_band() {
        let vuln = OsvVuln {
            severity: vec![OsvSeverity {
                kind: "CVSS_V3".to_string(),
                score: "BS:3.1".to_string(),
            }],
            ..OsvVuln::default()
        };
        assert_eq!(pick_severity(&vuln), Severity::Low);
    }

    #[test]
    fn pick_severity_falls_back_to_medium_when_no_score() {
        let vuln = OsvVuln::default();
        assert_eq!(pick_severity(&vuln), Severity::Medium);
    }

    #[test]
    fn pick_severity_uses_database_specific_rating_when_no_cvss_score() {
        let vuln = OsvVuln {
            severity: vec![OsvSeverity {
                kind: "CVSS_V4".to_string(),
                score: "CVSS:4.0/AV:N/AC:L/E:U".to_string(),
            }],
            database_specific: Some(OsvDatabaseSpecific {
                severity: Some("HIGH".to_string()),
            }),
            ..OsvVuln::default()
        };
        assert_eq!(pick_severity(&vuln), Severity::High);
    }

    #[test]
    fn pick_severity_maps_github_moderate_rating() {
        let vuln = OsvVuln {
            database_specific: Some(OsvDatabaseSpecific {
                severity: Some("MODERATE".to_string()),
            }),
            ..OsvVuln::default()
        };
        assert_eq!(pick_severity(&vuln), Severity::Medium);
    }

    #[test]
    fn pick_severity_maps_github_low_rating() {
        let vuln = OsvVuln {
            database_specific: Some(OsvDatabaseSpecific {
                severity: Some("low".to_string()),
            }),
            ..OsvVuln::default()
        };
        assert_eq!(pick_severity(&vuln), Severity::Low);
    }

    #[test]
    fn extract_cvss_score_reads_base_score_from_vector() {
        assert_eq!(
            extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/BS:9.8"),
            Some(9.8)
        );
    }

    #[test]
    fn extract_cvss_score_reads_bare_number() {
        assert_eq!(extract_cvss_score("7.5"), Some(7.5));
    }

    #[test]
    fn extract_cvss_score_returns_none_for_unparseable() {
        assert_eq!(extract_cvss_score("CRITICAL"), None);
    }

    #[test]
    fn advisory_url_routes_known_prefixes() {
        assert!(advisory_url("RUSTSEC-2024-0001").contains("rustsec.org"));
        assert!(advisory_url("GHSA-abcd-efgh-ijkl").contains("github.com/advisories"));
        assert!(advisory_url("CVE-2024-12345").contains("osv.dev"));
    }

    #[test]
    fn build_finding_uses_dependency_category_and_id_in_code() {
        let pkg = RustPackage {
            name: "demo".to_string(),
            version: "0.1.0".to_string(),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_string()),
        };
        let vuln = OsvVuln {
            id: "RUSTSEC-2024-0001".to_string(),
            summary: Some("test summary".to_string()),
            ..OsvVuln::default()
        };
        let finding = build_finding(Path::new("Cargo.lock"), &pkg, &vuln);
        assert_eq!(finding.category, Category::Dependency);
        assert!(finding.code.contains("RUSTSEC-2024-0001"));
        assert!(finding.message.contains("demo"));
        assert!(finding.message.contains("0.1.0"));
    }
}
