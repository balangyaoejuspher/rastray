use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
const CACHE_TTL_SECS: u64 = 24 * 60 * 60;
const CACHE_FILE_NAME: &str = "osv-cache.json";

#[derive(Debug, Default)]
pub struct DependenciesAnalyzer {
    offline: bool,
    no_cache: bool,
}

impl DependenciesAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(offline: bool, no_cache: bool) -> Self {
        Self { offline, no_cache }
    }
}

impl Analyzer for DependenciesAnalyzer {
    fn name(&self) -> &'static str {
        "dependencies"
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let mut packages: Vec<(PathBuf, Package)> = Vec::new();

        for lockfile in collect_cargo_lockfiles(crawl) {
            if let Ok(pkgs) = read_cargo_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_npm_lockfiles(crawl) {
            if let Ok(pkgs) = read_npm_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_python_requirements(crawl) {
            if let Ok(pkgs) = read_python_requirements(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_go_sum_files(crawl) {
            if let Ok(pkgs) = read_go_sum(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        if packages.is_empty() {
            return Ok(Vec::new());
        }

        let mut cache = if self.no_cache {
            OsvCache::default()
        } else {
            OsvCache::load_or_default()
        };

        let now_secs = current_unix_secs();
        let mut results: Vec<Vec<OsvVuln>> = Vec::with_capacity(packages.len());
        let mut uncached_indices: Vec<usize> = Vec::new();
        let mut uncached: Vec<&Package> = Vec::new();

        for (idx, (_, pkg)) in packages.iter().enumerate() {
            let key = cache_key(pkg);
            if let Some(entry) = cache.entries.get(&key) {
                if now_secs.saturating_sub(entry.fetched_at) < CACHE_TTL_SECS {
                    results.push(entry.vulns.clone());
                    continue;
                }
            }
            results.push(Vec::new());
            uncached_indices.push(idx);
            uncached.push(pkg);
        }

        if !uncached.is_empty() && !self.offline {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| AnalyzerError::Failed {
                    name: "dependencies",
                    message: format!("could not start tokio runtime: {e}"),
                })?;

            let fetched = runtime.block_on(query_osv_batch(&uncached)).map_err(|e| {
                AnalyzerError::Failed {
                    name: "dependencies",
                    message: format!("OSV query failed: {e}"),
                }
            })?;

            for (slot_idx, vulns) in uncached_indices.iter().zip(fetched) {
                if let Some((_, pkg)) = packages.get(*slot_idx) {
                    cache.entries.insert(
                        cache_key(pkg),
                        OsvCacheEntry {
                            fetched_at: now_secs,
                            vulns: vulns.clone(),
                        },
                    );
                }
                if let Some(slot) = results.get_mut(*slot_idx) {
                    *slot = vulns;
                }
            }

            if !self.no_cache {
                let _ = cache.save();
            }
        }

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
    collect_manifests_named(crawl, "cargo.lock")
}

fn collect_npm_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "package-lock.json")
}

fn collect_python_requirements(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "requirements.txt")
}

fn collect_go_sum_files(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "go.sum")
}

fn collect_manifests_named(crawl: &CrawlSummary, target_name: &str) -> Vec<PathBuf> {
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
            if name.as_deref() == Some(target_name) {
                Some(f.path.clone())
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
struct Package {
    ecosystem: &'static str,
    name: String,
    version: String,
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

fn read_cargo_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
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
        .map(|p| Package {
            ecosystem: "crates.io",
            name: p.name,
            version: p.version,
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct NpmLock {
    #[serde(default)]
    packages: std::collections::BTreeMap<String, NpmLockPackage>,
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, NpmLockLegacyDep>,
}

#[derive(Debug, Deserialize)]
struct NpmLockPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "link")]
    link: bool,
}

#[derive(Debug, Deserialize)]
struct NpmLockLegacyDep {
    #[serde(default)]
    version: Option<String>,
}

fn read_npm_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let lock: NpmLock =
        serde_json::from_str(&contents).map_err(|e| ParseError::Json(e.to_string()))?;

    let mut packages = Vec::new();

    for (key, entry) in lock.packages {
        if key.is_empty() || entry.link {
            continue;
        }
        let Some(version) = entry.version else {
            continue;
        };
        let Some(name) = entry.name.or_else(|| derive_npm_name(&key)) else {
            continue;
        };
        packages.push(Package {
            ecosystem: "npm",
            name,
            version,
        });
    }

    if packages.is_empty() {
        for (name, dep) in lock.dependencies {
            if let Some(version) = dep.version {
                packages.push(Package {
                    ecosystem: "npm",
                    name,
                    version,
                });
            }
        }
    }

    Ok(packages)
}

fn derive_npm_name(key: &str) -> Option<String> {
    let last = key.rsplit("node_modules/").next()?;
    if last.is_empty() {
        return None;
    }
    Some(last.to_string())
}

fn read_python_requirements(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let mut packages = Vec::new();
    for raw_line in contents.lines() {
        if let Some(pkg) = parse_python_requirement_line(raw_line) {
            packages.push(pkg);
        }
    }
    Ok(packages)
}

fn parse_python_requirement_line(line: &str) -> Option<Package> {
    let trimmed = strip_python_comment(line).trim();
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with("git+")
        || trimmed.starts_with("http")
    {
        return None;
    }

    let (name_part, version_part) = trimmed.split_once("==")?;
    let name = name_part.split(['[', ' ', '\t']).next()?.trim();
    if name.is_empty() {
        return None;
    }
    let version = version_part
        .split([';', ' ', '\t', '#'])
        .next()?
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    if version.is_empty() {
        return None;
    }
    Some(Package {
        ecosystem: "PyPI",
        name: name.to_string(),
        version: version.to_string(),
    })
}

fn strip_python_comment(line: &str) -> &str {
    line.split_once('#').map(|(head, _)| head).unwrap_or(line)
}

fn read_go_sum(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut packages = Vec::new();
    for raw_line in contents.lines() {
        if let Some(pkg) = parse_go_sum_line(raw_line) {
            let key = (pkg.name.clone(), pkg.version.clone());
            if seen.insert(key) {
                packages.push(pkg);
            }
        }
    }
    Ok(packages)
}

fn parse_go_sum_line(line: &str) -> Option<Package> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_ascii_whitespace();
    let name = parts.next()?;
    let version_field = parts.next()?;
    let _hash = parts.next()?;

    let version = version_field
        .strip_suffix("/go.mod")
        .unwrap_or(version_field);
    if !version.starts_with('v') {
        return None;
    }
    Some(Package {
        ecosystem: "Go",
        name: name.to_string(),
        version: version.to_string(),
    })
}

#[derive(Debug)]
enum ParseError {
    Io(std::io::Error),
    Toml(String),
    Json(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "io error: {e}"),
            ParseError::Toml(e) => write!(f, "toml parse error: {e}"),
            ParseError::Json(e) => write!(f, "json parse error: {e}"),
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

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
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

#[derive(Deserialize, Serialize, Debug, Clone)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
struct OsvDatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

async fn query_osv_batch(packages: &[&Package]) -> Result<Vec<Vec<OsvVuln>>, reqwest::Error> {
    let queries: Vec<OsvQuery> = packages
        .iter()
        .map(|p| OsvQuery {
            package: OsvPackage {
                ecosystem: p.ecosystem,
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

fn build_finding(lockfile: &Path, pkg: &Package, vuln: &OsvVuln) -> Finding {
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

fn cache_key(pkg: &Package) -> String {
    format!("{}::{}::{}", pkg.ecosystem, pkg.name, pkg.version)
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_dir() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("RASTRAY_CACHE_DIR") {
        return Some(PathBuf::from(override_path));
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return Some(PathBuf::from(local_app_data).join("rastray"));
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg).join("rastray"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join(".cache").join("rastray"));
    }
    None
}

fn cache_path() -> Option<PathBuf> {
    cache_dir().map(|d| d.join(CACHE_FILE_NAME))
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OsvCache {
    #[serde(default)]
    entries: BTreeMap<String, OsvCacheEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OsvCacheEntry {
    fetched_at: u64,
    vulns: Vec<OsvVuln>,
}

impl OsvCache {
    fn load_or_default() -> Self {
        let Some(path) = cache_path() else {
            return Self::default();
        };
        let Ok(contents) = fs::read_to_string(&path) else {
            return Self::default();
        };
        serde_json::from_str(&contents).unwrap_or_default()
    }

    fn save(&self) -> std::io::Result<()> {
        let Some(path) = cache_path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string(self).map_err(std::io::Error::other)?;
        fs::write(path, body)
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
        assert_eq!(pkgs[0].ecosystem, "crates.io");
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
        let pkg = Package {
            ecosystem: "crates.io",
            name: "demo".to_string(),
            version: "0.1.0".to_string(),
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

    #[test]
    fn read_npm_lock_v3_parses_packages_field() {
        let body = r#"{
            "name": "root",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.20" },
                "node_modules/scoped-pkg": { "name": "@scope/scoped-pkg", "version": "2.0.0" },
                "node_modules/symlinked": { "version": "1.0.0", "link": true }
            }
        }"#;
        let tmp = std::env::temp_dir().join(format!("rastray-npm-v3-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_npm_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().all(|p| p.ecosystem == "npm"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.20"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "@scope/scoped-pkg" && p.version == "2.0.0"));
    }

    #[test]
    fn read_npm_lock_v1_falls_back_to_dependencies_field() {
        let body = r#"{
            "name": "root",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "minimist": { "version": "0.0.8" },
                "qs": { "version": "6.5.1" }
            }
        }"#;
        let tmp = std::env::temp_dir().join(format!("rastray-npm-v1-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_npm_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().all(|p| p.ecosystem == "npm"));
    }

    #[test]
    fn read_npm_lock_returns_empty_for_missing_packages_and_dependencies() {
        let body = r#"{ "name": "root", "version": "1.0.0", "lockfileVersion": 3 }"#;
        let tmp = std::env::temp_dir().join(format!("rastray-npm-empty-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_npm_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        if let Ok(pkgs) = parsed {
            assert_eq!(pkgs.len(), 0);
        }
    }

    #[test]
    fn derive_npm_name_handles_root_and_scoped_paths() {
        assert_eq!(
            derive_npm_name("node_modules/lodash"),
            Some("lodash".to_string())
        );
        assert_eq!(
            derive_npm_name("node_modules/@scope/pkg"),
            Some("@scope/pkg".to_string())
        );
        assert_eq!(
            derive_npm_name("node_modules/foo/node_modules/bar"),
            Some("bar".to_string())
        );
        assert_eq!(derive_npm_name(""), None);
    }

    #[test]
    fn parse_python_requirement_line_accepts_pinned_version() {
        let pkg = parse_python_requirement_line("requests==2.31.0").unwrap_or(Package {
            ecosystem: "",
            name: String::new(),
            version: String::new(),
        });
        assert_eq!(pkg.ecosystem, "PyPI");
        assert_eq!(pkg.name, "requests");
        assert_eq!(pkg.version, "2.31.0");
    }

    #[test]
    fn parse_python_requirement_line_strips_extras_and_environment_markers() {
        let pkg =
            parse_python_requirement_line("django[postgresql]==4.2.0; python_version >= '3.8'")
                .unwrap_or(Package {
                    ecosystem: "",
                    name: String::new(),
                    version: String::new(),
                });
        assert_eq!(pkg.name, "django");
        assert_eq!(pkg.version, "4.2.0");
    }

    #[test]
    fn parse_python_requirement_line_strips_inline_comment() {
        let pkg =
            parse_python_requirement_line("flask==2.3.0  # web framework").unwrap_or(Package {
                ecosystem: "",
                name: String::new(),
                version: String::new(),
            });
        assert_eq!(pkg.name, "flask");
        assert_eq!(pkg.version, "2.3.0");
    }

    #[test]
    fn parse_python_requirement_line_rejects_non_pinned_specifiers() {
        assert!(parse_python_requirement_line("requests>=2.0").is_none());
        assert!(parse_python_requirement_line("requests~=2.0").is_none());
        assert!(parse_python_requirement_line("requests").is_none());
    }

    #[test]
    fn parse_python_requirement_line_rejects_directives_and_blanks() {
        assert!(parse_python_requirement_line("").is_none());
        assert!(parse_python_requirement_line("# a comment").is_none());
        assert!(parse_python_requirement_line("-r other.txt").is_none());
        assert!(parse_python_requirement_line("--index-url https://x").is_none());
        assert!(parse_python_requirement_line("@ git+https://example.com/repo").is_none());
        assert!(parse_python_requirement_line("https://example.com/pkg.whl").is_none());
    }

    #[test]
    fn read_python_requirements_collects_all_pinned_lines() {
        let body = "requests==2.31.0\nflask==2.3.0  # web\n# header\n-r other.txt\nnumpy>=1.0\n\n";
        let tmp = std::env::temp_dir().join(format!("rastray-py-req-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_python_requirements(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().all(|p| p.ecosystem == "PyPI"));
    }

    #[test]
    fn parse_go_sum_line_accepts_module_version() {
        let pkg = parse_go_sum_line(
            "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        )
        .unwrap_or(Package {
            ecosystem: "",
            name: String::new(),
            version: String::new(),
        });
        assert_eq!(pkg.ecosystem, "Go");
        assert_eq!(pkg.name, "github.com/pkg/errors");
        assert_eq!(pkg.version, "v0.9.1");
    }

    #[test]
    fn parse_go_sum_line_strips_go_mod_suffix() {
        let pkg = parse_go_sum_line(
            "github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=",
        )
        .unwrap_or(Package {
            ecosystem: "",
            name: String::new(),
            version: String::new(),
        });
        assert_eq!(pkg.name, "github.com/pkg/errors");
        assert_eq!(pkg.version, "v0.9.1");
    }

    #[test]
    fn parse_go_sum_line_rejects_invalid_versions() {
        assert!(parse_go_sum_line("").is_none());
        assert!(parse_go_sum_line("github.com/pkg/errors 1.0.0 h1:abc=").is_none());
        assert!(parse_go_sum_line("github.com/pkg/errors").is_none());
    }

    #[test]
    fn read_go_sum_deduplicates_pkg_and_go_mod_pairs() {
        let body = "\
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
golang.org/x/net v0.10.0 h1:X2//UzNDwYmtCLn7To6G58Wr6f5ahEAQgKNzv9Y951M=
";
        let tmp = std::env::temp_dir().join(format!("rastray-go-sum-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_go_sum(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().all(|p| p.ecosystem == "Go"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "github.com/pkg/errors" && p.version == "v0.9.1"));
    }

    #[test]
    fn cache_key_uniquely_identifies_packages() {
        let a = Package {
            ecosystem: "crates.io",
            name: "tokio".to_string(),
            version: "1.20.0".to_string(),
        };
        let b = Package {
            ecosystem: "crates.io",
            name: "tokio".to_string(),
            version: "1.21.0".to_string(),
        };
        let c = Package {
            ecosystem: "npm",
            name: "tokio".to_string(),
            version: "1.20.0".to_string(),
        };
        assert_ne!(cache_key(&a), cache_key(&b));
        assert_ne!(cache_key(&a), cache_key(&c));
        assert_eq!(cache_key(&a), cache_key(&a.clone()));
    }

    #[test]
    fn osv_cache_round_trip_via_temp_dir() {
        let tmp_dir = std::env::temp_dir().join(format!("rastray-cache-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let prev = std::env::var("RASTRAY_CACHE_DIR").ok();
        std::env::set_var("RASTRAY_CACHE_DIR", &tmp_dir);

        let mut cache = OsvCache::default();
        cache.entries.insert(
            "test::pkg::1.0.0".to_string(),
            OsvCacheEntry {
                fetched_at: 1000,
                vulns: vec![OsvVuln {
                    id: "GHSA-test".to_string(),
                    summary: Some("test".to_string()),
                    ..OsvVuln::default()
                }],
            },
        );
        assert!(cache.save().is_ok());

        let reloaded = OsvCache::load_or_default();
        assert_eq!(reloaded.entries.len(), 1);
        assert!(reloaded.entries.contains_key("test::pkg::1.0.0"));

        match prev {
            Some(v) => std::env::set_var("RASTRAY_CACHE_DIR", v),
            None => std::env::remove_var("RASTRAY_CACHE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cache_dir_uses_override_env_when_set() {
        let prev = std::env::var("RASTRAY_CACHE_DIR").ok();
        std::env::set_var("RASTRAY_CACHE_DIR", "/tmp/rastray-test-override");
        let dir = cache_dir();
        assert_eq!(
            dir,
            Some(std::path::PathBuf::from("/tmp/rastray-test-override"))
        );
        match prev {
            Some(v) => std::env::set_var("RASTRAY_CACHE_DIR", v),
            None => std::env::remove_var("RASTRAY_CACHE_DIR"),
        }
    }
}
