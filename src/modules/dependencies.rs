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
const OSV_BATCH_LIMIT: usize = 1000;
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

        for lockfile in collect_pnpm_lockfiles(crawl) {
            if let Ok(pkgs) = read_pnpm_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_yarn_lockfiles(crawl) {
            if let Ok(pkgs) = read_yarn_lock(&lockfile) {
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

        for lockfile in collect_poetry_lockfiles(crawl) {
            if let Ok(pkgs) = read_poetry_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_pipfile_lockfiles(crawl) {
            if let Ok(pkgs) = read_pipfile_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_uv_lockfiles(crawl) {
            if let Ok(pkgs) = read_uv_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_gemfile_lockfiles(crawl) {
            if let Ok(pkgs) = read_gemfile_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_composer_lockfiles(crawl) {
            if let Ok(pkgs) = read_composer_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_nuget_lockfiles(crawl) {
            if let Ok(pkgs) = read_nuget_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_swift_lockfiles(crawl) {
            if let Ok(pkgs) = read_swift_resolved(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_dart_lockfiles(crawl) {
            if let Ok(pkgs) = read_pubspec_lock(&lockfile) {
                for pkg in pkgs {
                    packages.push((lockfile.clone(), pkg));
                }
            }
        }

        for lockfile in collect_elixir_lockfiles(crawl) {
            if let Ok(pkgs) = read_mix_lock(&lockfile) {
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

#[derive(Debug, Clone)]
pub struct DiscoveredPackage {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    pub source: PathBuf,
}

pub fn collect_packages(crawl: &CrawlSummary) -> Vec<DiscoveredPackage> {
    let mut out: Vec<DiscoveredPackage> = Vec::new();

    let mut push = |lockfile: &PathBuf, pkgs: Vec<Package>| {
        for pkg in pkgs {
            out.push(DiscoveredPackage {
                ecosystem: pkg.ecosystem,
                name: pkg.name,
                version: pkg.version,
                source: lockfile.clone(),
            });
        }
    };

    for lockfile in collect_cargo_lockfiles(crawl) {
        if let Ok(pkgs) = read_cargo_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_npm_lockfiles(crawl) {
        if let Ok(pkgs) = read_npm_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_pnpm_lockfiles(crawl) {
        if let Ok(pkgs) = read_pnpm_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_yarn_lockfiles(crawl) {
        if let Ok(pkgs) = read_yarn_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_python_requirements(crawl) {
        if let Ok(pkgs) = read_python_requirements(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_poetry_lockfiles(crawl) {
        if let Ok(pkgs) = read_poetry_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_pipfile_lockfiles(crawl) {
        if let Ok(pkgs) = read_pipfile_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_uv_lockfiles(crawl) {
        if let Ok(pkgs) = read_uv_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_gemfile_lockfiles(crawl) {
        if let Ok(pkgs) = read_gemfile_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_composer_lockfiles(crawl) {
        if let Ok(pkgs) = read_composer_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_nuget_lockfiles(crawl) {
        if let Ok(pkgs) = read_nuget_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_swift_lockfiles(crawl) {
        if let Ok(pkgs) = read_swift_resolved(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_dart_lockfiles(crawl) {
        if let Ok(pkgs) = read_pubspec_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_elixir_lockfiles(crawl) {
        if let Ok(pkgs) = read_mix_lock(&lockfile) {
            push(&lockfile, pkgs);
        }
    }
    for lockfile in collect_go_sum_files(crawl) {
        if let Ok(pkgs) = read_go_sum(&lockfile) {
            push(&lockfile, pkgs);
        }
    }

    out.sort_by(|a, b| {
        a.ecosystem
            .cmp(b.ecosystem)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
    out.dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name && a.version == b.version);
    out
}

fn collect_cargo_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "cargo.lock")
}

fn collect_npm_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "package-lock.json")
}

fn collect_pnpm_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "pnpm-lock.yaml")
}

fn collect_yarn_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "yarn.lock")
}

fn collect_python_requirements(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "requirements.txt")
}

fn collect_poetry_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "poetry.lock")
}

fn collect_pipfile_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "pipfile.lock")
}

fn collect_uv_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "uv.lock")
}

fn collect_gemfile_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "gemfile.lock")
}

fn collect_composer_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "composer.lock")
}

fn collect_nuget_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "packages.lock.json")
}

fn collect_swift_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "package.resolved")
}

fn collect_dart_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "pubspec.lock")
}

fn collect_elixir_lockfiles(crawl: &CrawlSummary) -> Vec<PathBuf> {
    collect_manifests_named(crawl, "mix.lock")
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

fn read_pnpm_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let mut packages = Vec::new();
    let mut in_packages_section = false;
    let mut seen = std::collections::BTreeSet::new();

    for raw_line in contents.lines() {
        if raw_line.is_empty() {
            continue;
        }
        if !raw_line.starts_with(char::is_whitespace) {
            in_packages_section = raw_line.starts_with("packages:");
            continue;
        }

        if !in_packages_section {
            continue;
        }

        if let Some(spec) = pnpm_packages_key(raw_line) {
            if let Some((name, version)) = split_npm_spec(spec) {
                let key = format!("{name}@{version}");
                if seen.insert(key) {
                    packages.push(Package {
                        ecosystem: "npm",
                        name: name.to_string(),
                        version: version.to_string(),
                    });
                }
            }
        }
    }
    Ok(packages)
}

fn pnpm_packages_key(line: &str) -> Option<&str> {
    let trimmed_start = line.trim_start();
    let indent = line.len() - trimmed_start.len();
    if indent != 2 {
        return None;
    }
    let without_colon = trimmed_start.strip_suffix(':')?;
    let unquoted = without_colon
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| {
            without_colon
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
        })
        .unwrap_or(without_colon);
    let key = unquoted.strip_prefix('/').unwrap_or(unquoted);
    if key.contains('@') {
        Some(key)
    } else {
        None
    }
}

fn split_npm_spec(spec: &str) -> Option<(&str, &str)> {
    let cleaned = spec.split(['(', '_']).next().unwrap_or(spec);
    let at = cleaned.rfind('@')?;
    if at == 0 {
        return None;
    }
    let name = &cleaned[..at];
    let version = &cleaned[at + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    if !version
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        return None;
    }
    Some((name, version))
}

fn read_yarn_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let mut packages = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut current_name: Option<String> = None;

    for raw_line in contents.lines() {
        if raw_line.starts_with('#') || raw_line.starts_with("__metadata") {
            continue;
        }
        if !raw_line.starts_with(char::is_whitespace) && raw_line.trim_end().ends_with(':') {
            current_name = parse_yarn_header(raw_line);
            continue;
        }
        let trimmed = raw_line.trim();
        if let Some(version) = parse_yarn_version_line(trimmed) {
            if let Some(name) = current_name.as_deref() {
                let key = format!("{name}@{version}");
                if seen.insert(key) {
                    packages.push(Package {
                        ecosystem: "npm",
                        name: name.to_string(),
                        version: version.to_string(),
                    });
                }
            }
        }
    }
    Ok(packages)
}

fn parse_yarn_header(line: &str) -> Option<String> {
    let header = line.trim_end_matches(':').trim();
    let first = header.split(',').next()?.trim();
    let unquoted = first
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(first);
    let stripped = unquoted
        .strip_prefix("npm:")
        .map(|s| s.to_string())
        .unwrap_or_else(|| unquoted.to_string());
    let at = stripped.rfind('@')?;
    if at == 0 {
        return None;
    }
    let name = &stripped[..at];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn parse_yarn_version_line(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("version")?;
    let after = rest.trim_start_matches([' ', ':']).trim();
    let unquoted = after
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(after);
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted.to_string())
    }
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

#[derive(Debug, Deserialize)]
struct PythonTomlLock {
    #[serde(default)]
    package: Vec<PythonTomlLockEntry>,
}

#[derive(Debug, Deserialize)]
struct PythonTomlLockEntry {
    name: String,
    version: String,
}

fn read_poetry_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    parse_python_toml_lock(path)
}

fn read_uv_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    parse_python_toml_lock(path)
}

fn parse_python_toml_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let lock: PythonTomlLock =
        toml::from_str(&contents).map_err(|e| ParseError::Toml(e.to_string()))?;
    let mut out = Vec::with_capacity(lock.package.len());
    for entry in lock.package {
        if entry.name.is_empty() || entry.version.is_empty() {
            continue;
        }
        out.push(Package {
            ecosystem: "PyPI",
            name: entry.name,
            version: entry.version,
        });
    }
    Ok(out)
}

fn read_pipfile_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| ParseError::Json(e.to_string()))?;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        let Some(map) = value.get(section).and_then(|s| s.as_object()) else {
            continue;
        };
        for (name, info) in map {
            let raw = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let version = raw.trim().trim_start_matches("==").trim();
            if name.is_empty() || version.is_empty() {
                continue;
            }
            out.push(Package {
                ecosystem: "PyPI",
                name: name.clone(),
                version: version.to_string(),
            });
        }
    }
    Ok(out)
}

fn read_gemfile_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let mut out = Vec::new();
    let mut in_specs = false;
    for raw_line in contents.lines() {
        if raw_line.trim().is_empty() {
            in_specs = false;
            continue;
        }
        if raw_line.trim_start() == "specs:" {
            in_specs = true;
            continue;
        }
        if !raw_line.starts_with(' ') {
            in_specs = false;
            continue;
        }
        if !in_specs {
            continue;
        }
        let leading_spaces = raw_line.chars().take_while(|c| *c == ' ').count();
        if leading_spaces != 4 {
            continue;
        }
        if let Some(pkg) = parse_gemfile_spec_line(raw_line.trim_start()) {
            out.push(pkg);
        }
    }
    Ok(out)
}

fn parse_gemfile_spec_line(line: &str) -> Option<Package> {
    let open = line.find(" (")?;
    let close = line.rfind(')')?;
    if close <= open + 2 {
        return None;
    }
    let name = line[..open].trim();
    let version = line[open + 2..close].trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(Package {
        ecosystem: "RubyGems",
        name: name.to_string(),
        version: version.to_string(),
    })
}

fn read_composer_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| ParseError::Json(e.to_string()))?;
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        let Some(arr) = value.get(section).and_then(|s| s.as_array()) else {
            continue;
        };
        for entry in arr {
            let name = entry
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let version_raw = entry
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let version = version_raw.strip_prefix('v').unwrap_or(version_raw);
            if name.is_empty() || version.is_empty() {
                continue;
            }
            out.push(Package {
                ecosystem: "Packagist",
                name: name.to_string(),
                version: version.to_string(),
            });
        }
    }
    Ok(out)
}

fn read_nuget_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| ParseError::Json(e.to_string()))?;
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let Some(deps_root) = value.get("dependencies").and_then(|d| d.as_object()) else {
        return Ok(out);
    };
    for (_tfm, tfm_deps) in deps_root {
        let Some(map) = tfm_deps.as_object() else {
            continue;
        };
        for (name, info) in map {
            let resolved = info
                .get("resolved")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if name.is_empty() || resolved.is_empty() {
                continue;
            }
            let key = (name.clone(), resolved.to_string());
            if !seen.insert(key) {
                continue;
            }
            out.push(Package {
                ecosystem: "NuGet",
                name: name.clone(),
                version: resolved.to_string(),
            });
        }
    }
    Ok(out)
}

fn read_swift_resolved(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| ParseError::Json(e.to_string()))?;
    let pins = value
        .get("pins")
        .or_else(|| value.get("object").and_then(|o| o.get("pins")))
        .and_then(|p| p.as_array());
    let Some(pins) = pins else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(pins.len());
    for pin in pins {
        let location = pin
            .get("location")
            .or_else(|| pin.get("repositoryURL"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let version = pin
            .get("state")
            .and_then(|s| s.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let name = normalize_swift_location(location);
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Package {
            ecosystem: "SwiftURL",
            name,
            version: version.to_string(),
        });
    }
    Ok(out)
}

fn normalize_swift_location(url: &str) -> String {
    let stripped = url
        .trim()
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git@")
        .replace(':', "/");
    stripped.to_lowercase()
}

fn read_pubspec_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let mut out = Vec::new();
    let mut in_packages = false;
    let mut current_name: Option<String> = None;
    for raw_line in contents.lines() {
        if raw_line.trim().is_empty() || raw_line.trim_start().starts_with('#') {
            continue;
        }
        if !raw_line.starts_with(char::is_whitespace) {
            in_packages = raw_line.starts_with("packages:");
            current_name = None;
            continue;
        }
        if !in_packages {
            continue;
        }
        let leading = raw_line.chars().take_while(|c| *c == ' ').count();
        let stripped = raw_line.trim_start();
        if leading == 2 {
            if let Some(name) = stripped.strip_suffix(':') {
                let cleaned = name.trim_matches('"').trim_matches('\'').trim();
                if !cleaned.is_empty() {
                    current_name = Some(cleaned.to_string());
                }
            }
            continue;
        }
        if leading == 4 {
            if let Some(rest) = stripped.strip_prefix("version:") {
                let version_raw = rest.trim().trim_matches('"').trim_matches('\'').trim();
                let Some(name) = current_name.as_ref() else {
                    continue;
                };
                if version_raw.is_empty() {
                    continue;
                }
                out.push(Package {
                    ecosystem: "Pub",
                    name: name.clone(),
                    version: version_raw.to_string(),
                });
            }
        }
    }
    Ok(out)
}

fn read_mix_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let contents = fs::read_to_string(path).map_err(ParseError::Io)?;
    let mut out = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if !line.contains("{:hex,") {
            continue;
        }
        let quoted = extract_quoted_strings(line);
        if quoted.len() < 2 {
            continue;
        }
        let name = quoted[0].clone();
        let version = quoted[1].clone();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Package {
            ecosystem: "Hex",
            name,
            version,
        });
    }
    Ok(out)
}

fn extract_quoted_strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;
    for c in line.chars() {
        if escape {
            current.push(c);
            escape = false;
            continue;
        }
        if c == '\\' && in_string {
            escape = true;
            continue;
        }
        if c == '"' {
            if in_string {
                out.push(current.clone());
                current.clear();
                in_string = false;
            } else {
                in_string = true;
            }
        } else if in_string {
            current.push(c);
        }
    }
    out
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
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()?;

    let mut hydrated: Vec<Vec<OsvVuln>> = Vec::with_capacity(packages.len());

    for chunk in packages.chunks(OSV_BATCH_LIMIT) {
        let queries: Vec<OsvQuery> = chunk
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

        let resp: OsvBatchResponse = client
            .post(OSV_BATCH_URL)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

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
    fn split_npm_spec_parses_plain_and_scoped() {
        assert_eq!(
            split_npm_spec("lodash@4.17.21"),
            Some(("lodash", "4.17.21"))
        );
        assert_eq!(
            split_npm_spec("@types/node@20.0.0"),
            Some(("@types/node", "20.0.0"))
        );
    }

    #[test]
    fn split_npm_spec_strips_pnpm_peer_suffix() {
        assert_eq!(
            split_npm_spec("react@18.0.0(react-dom@18.0.0)"),
            Some(("react", "18.0.0"))
        );
        assert_eq!(
            split_npm_spec("babel-jest@29.7.0_@babel+core@7.0.0"),
            Some(("babel-jest", "29.7.0"))
        );
    }

    #[test]
    fn split_npm_spec_rejects_invalid_inputs() {
        assert_eq!(split_npm_spec("@scope/pkg"), None);
        assert_eq!(split_npm_spec("pkg@latest"), None);
        assert_eq!(split_npm_spec("@scope"), None);
    }

    #[test]
    fn pnpm_packages_key_extracts_v6_style_slash_prefix() {
        assert_eq!(
            pnpm_packages_key("  /lodash@4.17.21:"),
            Some("lodash@4.17.21")
        );
        assert_eq!(
            pnpm_packages_key("  '/@types/node@20.0.0':"),
            Some("@types/node@20.0.0")
        );
    }

    #[test]
    fn pnpm_packages_key_extracts_v9_style_no_prefix() {
        assert_eq!(pnpm_packages_key("  react@18.0.0:"), Some("react@18.0.0"));
    }

    #[test]
    fn pnpm_packages_key_ignores_non_two_space_indent() {
        assert_eq!(pnpm_packages_key("    resolution:"), None);
        assert_eq!(pnpm_packages_key("lodash@4.17.21:"), None);
    }

    #[test]
    fn read_pnpm_lock_parses_minimal_v9_lockfile() {
        let dir = std::env::temp_dir().join(format!(
            "rastray-pnpm-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("pnpm-lock.yaml");
        let body = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n\n  '@types/node@20.0.0':\n    resolution: {integrity: sha512-def}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n";
        if std::fs::write(&path, body).is_err() {
            return;
        }
        let pkgs = match read_pnpm_lock(&path) {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.21" && p.ecosystem == "npm"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "@types/node" && p.version == "20.0.0"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_pnpm_lock_dedupes_repeated_packages() {
        let dir = std::env::temp_dir().join(format!(
            "rastray-pnpm-dedupe-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("pnpm-lock.yaml");
        let body = "packages:\n\n  lodash@4.17.21:\n    resolution: {integrity: a}\n\n  lodash@4.17.21:\n    resolution: {integrity: b}\n";
        if std::fs::write(&path, body).is_err() {
            return;
        }
        let pkgs = match read_pnpm_lock(&path) {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_yarn_header_extracts_name_from_single_spec() {
        assert_eq!(
            parse_yarn_header("\"lodash@^4.17.0\":"),
            Some("lodash".to_string())
        );
        assert_eq!(
            parse_yarn_header("lodash@^4.17.0:"),
            Some("lodash".to_string())
        );
    }

    #[test]
    fn parse_yarn_header_extracts_name_from_compound_spec() {
        assert_eq!(
            parse_yarn_header("\"lodash@^4.17.0\", \"lodash@~4.17.5\":"),
            Some("lodash".to_string())
        );
    }

    #[test]
    fn parse_yarn_header_handles_scoped_packages() {
        assert_eq!(
            parse_yarn_header("\"@types/node@^20.0.0\":"),
            Some("@types/node".to_string())
        );
    }

    #[test]
    fn parse_yarn_header_strips_yarn_berry_npm_protocol() {
        assert_eq!(
            parse_yarn_header("\"lodash@npm:^4.17.0\":"),
            Some("lodash".to_string())
        );
    }

    #[test]
    fn parse_yarn_version_line_handles_quoted_and_unquoted() {
        assert_eq!(
            parse_yarn_version_line("version \"4.17.21\""),
            Some("4.17.21".to_string())
        );
        assert_eq!(
            parse_yarn_version_line("version: 4.17.21"),
            Some("4.17.21".to_string())
        );
    }

    #[test]
    fn parse_yarn_version_line_rejects_other_keys() {
        assert_eq!(parse_yarn_version_line("resolved \"https://...\""), None);
        assert_eq!(parse_yarn_version_line("integrity sha512-..."), None);
    }

    #[test]
    fn read_yarn_lock_parses_v1_classic_format() {
        let dir = std::env::temp_dir().join(format!(
            "rastray-yarn-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("yarn.lock");
        let body = "# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n\n\n\"lodash@^4.17.0\", \"lodash@~4.17.21\":\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n  integrity sha512-abc\n\n\"@types/node@^20.0.0\":\n  version \"20.5.0\"\n  resolved \"https://registry.yarnpkg.com/@types/node/-/node-20.5.0.tgz\"\n  integrity sha512-def\n";
        if std::fs::write(&path, body).is_err() {
            return;
        }
        let pkgs = match read_yarn_lock(&path) {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.21"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "@types/node" && p.version == "20.5.0"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_yarn_lock_parses_berry_v2_format() {
        let dir = std::env::temp_dir().join(format!(
            "rastray-yarn-berry-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("yarn.lock");
        let body = "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n  checksum: abc\n  languageName: node\n  linkType: hard\n";
        if std::fs::write(&path, body).is_err() {
            return;
        }
        let pkgs = match read_yarn_lock(&path) {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, "4.17.21");
        let _ = std::fs::remove_dir_all(&dir);
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

    #[test]
    fn read_poetry_lock_extracts_packages() {
        let body = r#"
            [[package]]
            name = "click"
            version = "8.1.7"
            description = "..."
            category = "main"

            [[package]]
            name = "requests"
            version = "2.31.0"
            "#;
        let tmp = std::env::temp_dir().join(format!("rastray-test-poetry-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_poetry_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "PyPI");
        assert_eq!(pkgs[0].name, "click");
        assert_eq!(pkgs[0].version, "8.1.7");
        assert_eq!(pkgs[1].name, "requests");
    }

    #[test]
    fn read_uv_lock_extracts_packages() {
        let body = r#"
            version = 1
            requires-python = ">=3.11"

            [[package]]
            name = "fastapi"
            version = "0.110.0"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "pydantic"
            version = "2.6.1"
            "#;
        let tmp = std::env::temp_dir().join(format!("rastray-test-uv-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_uv_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "PyPI");
        assert_eq!(pkgs[0].name, "fastapi");
        assert_eq!(pkgs[0].version, "0.110.0");
    }

    #[test]
    fn read_pipfile_lock_extracts_default_and_develop() {
        let body = r#"{
            "_meta": {"hash": {"sha256": "deadbeef"}},
            "default": {
                "click": {"version": "==8.1.7", "hashes": []},
                "requests": {"version": "==2.31.0"}
            },
            "develop": {
                "pytest": {"version": "==7.4.0"}
            }
            }"#;
        let tmp = std::env::temp_dir().join(format!("rastray-test-pipfile-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_pipfile_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 3);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"click"));
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"pytest"));
        for p in &pkgs {
            assert_eq!(p.ecosystem, "PyPI");
            assert!(!p.version.starts_with("=="));
        }
    }

    #[test]
    fn read_pipfile_lock_skips_entries_without_version() {
        let body = r#"{
            "default": {
                "broken": {"hashes": []},
                "ok": {"version": "==1.0.0"}
            }
            }"#;
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-pipfile-skip-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_pipfile_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "ok");
    }

    #[test]
    fn read_gemfile_lock_extracts_top_level_specs_only() {
        let body = "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.0.4)\n      actionview (= 7.0.4)\n      activesupport (= 7.0.4)\n    rake (13.0.6)\n    rails-html-sanitizer (1.4.4)\n      loofah (~> 2.19, >= 2.19.1)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n  rake\n";
        let tmp = std::env::temp_dir().join(format!("rastray-test-gemfile-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_gemfile_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 3);
        for p in &pkgs {
            assert_eq!(p.ecosystem, "RubyGems");
        }
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"actionpack"));
        assert!(names.contains(&"rake"));
        assert!(names.contains(&"rails-html-sanitizer"));
        assert!(!names.contains(&"actionview"));
        assert!(!names.contains(&"loofah"));
    }

    #[test]
    fn parse_gemfile_spec_line_handles_name_and_version() {
        let pkg = parse_gemfile_spec_line("rake (13.0.6)").unwrap_or(Package {
            ecosystem: "",
            name: String::new(),
            version: String::new(),
        });
        assert_eq!(pkg.name, "rake");
        assert_eq!(pkg.version, "13.0.6");
    }

    #[test]
    fn parse_gemfile_spec_line_rejects_malformed_lines() {
        assert!(parse_gemfile_spec_line("not a spec line").is_none());
        assert!(parse_gemfile_spec_line(" (1.0.0)").is_none());
        assert!(parse_gemfile_spec_line("name ()").is_none());
    }

    #[test]
    fn read_composer_lock_extracts_packages_and_packages_dev() {
        let body = r#"{
  "_readme": ["..."],
  "content-hash": "abc",
  "packages": [
    {"name": "monolog/monolog", "version": "2.9.1"},
    {"name": "symfony/console", "version": "v6.4.3"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.5.0"}
  ]
}"#;
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-composer-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_composer_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 3);
        for p in &pkgs {
            assert_eq!(p.ecosystem, "Packagist");
            assert!(!p.version.starts_with('v'));
        }
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"monolog/monolog"));
        assert!(names.contains(&"symfony/console"));
        assert!(names.contains(&"phpunit/phpunit"));
    }

    #[test]
    fn read_composer_lock_skips_entries_without_name_or_version() {
        let body = r#"{
  "packages": [
    {"name": "ok/pkg", "version": "1.0.0"},
    {"version": "no-name"},
    {"name": "no-version"}
  ]
}"#;
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-composer-skip-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_composer_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "ok/pkg");
    }

    #[test]
    fn read_nuget_lock_extracts_resolved_versions_across_tfms() {
        let body = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3"},
      "Serilog": {"type": "Transitive", "resolved": "3.1.1"}
    },
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}
    }
  }
}"#;
        let tmp = std::env::temp_dir().join(format!("rastray-test-nuget-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_nuget_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        for p in &pkgs {
            assert_eq!(p.ecosystem, "NuGet");
        }
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"Newtonsoft.Json"));
        assert!(names.contains(&"Serilog"));
    }

    #[test]
    fn read_nuget_lock_skips_entries_without_resolved() {
        let body = r#"{
  "dependencies": {
    "net8.0": {
      "Has.Resolved": {"resolved": "1.0.0"},
      "Missing.Resolved": {"requested": "[1.0.0, )"}
    }
  }
}"#;
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-nuget-skip-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_nuget_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "Has.Resolved");
    }

    #[test]
    fn read_swift_resolved_handles_v2_pins() {
        let body = r#"{
  "pins": [
    {
      "identity": "swift-syntax",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-syntax.git",
      "state": {"revision": "abc", "version": "510.0.0"}
    },
    {
      "identity": "swift-collections",
      "location": "https://github.com/apple/swift-collections.git",
      "state": {"version": "1.1.0"}
    }
  ],
  "version": 2
}"#;
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-swift-v2-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_swift_resolved(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        for p in &pkgs {
            assert_eq!(p.ecosystem, "SwiftURL");
        }
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"github.com/apple/swift-syntax"));
        assert!(names.contains(&"github.com/apple/swift-collections"));
    }

    #[test]
    fn read_swift_resolved_handles_v1_pins() {
        let body = r#"{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": {"branch": null, "revision": "abc", "version": "5.8.0"}
      }
    ]
  },
  "version": 1
}"#;
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-swift-v1-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_swift_resolved(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "github.com/alamofire/alamofire");
        assert_eq!(pkgs[0].version, "5.8.0");
    }

    #[test]
    fn read_swift_resolved_skips_pins_without_version() {
        let body = r#"{
  "pins": [
    {
      "identity": "branch-only",
      "location": "https://github.com/foo/bar.git",
      "state": {"branch": "main"}
    }
  ]
}"#;
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-swift-skip-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_swift_resolved(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pkgs.is_empty());
    }

    #[test]
    fn normalize_swift_location_strips_protocol_and_git_suffix() {
        assert_eq!(
            normalize_swift_location("https://github.com/Apple/Swift-Syntax.git"),
            "github.com/apple/swift-syntax"
        );
        assert_eq!(
            normalize_swift_location("git@github.com:apple/swift-syntax.git"),
            "github.com/apple/swift-syntax"
        );
    }

    #[test]
    fn read_pubspec_lock_extracts_packages_with_versions() {
        let body = "packages:\n  collection:\n    dependency: \"direct main\"\n    description:\n      name: collection\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.18.0\"\n  http:\n    dependency: \"direct main\"\n    description:\n      name: http\n    source: hosted\n    version: \"1.2.0\"\nsdks:\n  dart: \">=3.0.0 <4.0.0\"\n";
        let tmp = std::env::temp_dir().join(format!("rastray-test-pubspec-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_pubspec_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 2);
        for p in &pkgs {
            assert_eq!(p.ecosystem, "Pub");
        }
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"collection"));
        assert!(names.contains(&"http"));
        for p in &pkgs {
            assert!(!p.version.starts_with('"'));
        }
    }

    #[test]
    fn read_pubspec_lock_ignores_non_packages_sections() {
        let body = "sdks:\n  dart: \">=3.0.0 <4.0.0\"\n  flutter: \">=3.10.0\"\n";
        let tmp =
            std::env::temp_dir().join(format!("rastray-test-pubspec-empty-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_pubspec_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pkgs.is_empty());
    }

    #[test]
    fn read_mix_lock_extracts_hex_packages() {
        let body = "%{\n  \"phoenix\": {:hex, :phoenix, \"1.7.10\", \"abc\", [:mix], [], \"hexpm\"},\n  \"ecto\": {:hex, :ecto, \"3.11.0\", \"def\", [:mix], [], \"hexpm\"},\n  \"telemetry\": {:hex, :telemetry, \"1.2.1\", \"ghi\", [:rebar3], [], \"hexpm\"}\n}\n";
        let tmp = std::env::temp_dir().join(format!("rastray-test-mix-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_mix_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 3);
        for p in &pkgs {
            assert_eq!(p.ecosystem, "Hex");
        }
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"phoenix"));
        assert!(names.contains(&"ecto"));
        assert!(names.contains(&"telemetry"));
    }

    #[test]
    fn read_mix_lock_skips_non_hex_sources() {
        let body = "%{\n  \"phoenix\": {:hex, :phoenix, \"1.7.10\", \"abc\", [:mix], [], \"hexpm\"},\n  \"my_fork\": {:git, \"https://github.com/foo/my_fork.git\", \"abc\", []}\n}\n";
        let tmp = std::env::temp_dir().join(format!("rastray-test-mix-git-{}", std::process::id()));
        let _ = std::fs::write(&tmp, body);
        let parsed = read_mix_lock(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let pkgs = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "phoenix");
    }

    #[test]
    fn extract_quoted_strings_handles_escapes() {
        let strings = extract_quoted_strings(r#"hello "foo" world "bar\"baz" end"#);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0], "foo");
        assert_eq!(strings[1], "bar\"baz");
    }
}
