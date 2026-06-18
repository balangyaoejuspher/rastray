use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::fingerprint::Framework;
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct AxumAnalyzer;

impl AxumAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for AxumAnalyzer {
    fn name(&self) -> &'static str {
        "axum"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl.fingerprint.frameworks.contains(&Framework::Axum)
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let aux = compiled_aux_patterns()?;
        let mut findings = Vec::new();
        let project_roots: Vec<PathBuf> = crawl
            .fingerprint
            .projects
            .iter()
            .filter(|p| p.frameworks.contains(&Framework::Axum))
            .map(|p| p.root.clone())
            .collect();
        if project_roots.is_empty() {
            return Ok(findings);
        }
        for file in &crawl.files {
            if file.kind != FileKind::Source {
                continue;
            }
            let Some(ext) = file
                .path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
            else {
                continue;
            };
            if ext != "rs" {
                continue;
            }
            if !project_roots.iter().any(|root| file.path.starts_with(root)) {
                continue;
            }
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if let Some(finding) = scan_permissive_cors_with_credentials(&file.path, &contents, aux)
            {
                findings.push(finding);
            }
        }
        Ok(findings)
    }
}

struct AuxPatterns {
    allow_origin_any: Regex,
    allow_credentials_true: Regex,
}

fn compiled_aux_patterns() -> Result<&'static AuxPatterns, AnalyzerError> {
    static CACHE: OnceLock<Result<AuxPatterns, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let allow_origin_any = Regex::new(
            r"\.allow_origin\s*\(\s*(?:tower_http\s*::\s*cors\s*::\s*)?(?:cors\s*::\s*)?Any\s*\)",
        )
        .map_err(|e| format!("allow_origin_any: {e}"))?;
        let allow_credentials_true = Regex::new(r"\.allow_credentials\s*\(\s*true\s*\)")
            .map_err(|e| format!("allow_credentials_true: {e}"))?;
        Ok(AuxPatterns {
            allow_origin_any,
            allow_credentials_true,
        })
    });
    match cached {
        Ok(p) => Ok(p),
        Err(e) => Err(AnalyzerError::Failed {
            name: "axum",
            message: format!("failed to compile a builtin axum aux pattern: {e}"),
        }),
    }
}

fn scan_permissive_cors_with_credentials(
    path: &std::path::Path,
    contents: &str,
    aux: &AuxPatterns,
) -> Option<Finding> {
    let origin_match = aux.allow_origin_any.find(contents)?;
    if !aux.allow_credentials_true.is_match(contents) {
        return None;
    }
    let (line, column) = byte_offset_to_line_col(contents, origin_match.start());
    let location = Location::file(path.to_path_buf())
        .with_span(origin_match.start(), origin_match.len())
        .with_line(line, column);
    Some(
        Finding::new(
            "RSTR-AXUM-001",
            "Axum CorsLayer combines `.allow_origin(Any)` with `.allow_credentials(true)`; the wildcard-origin + credentials combination defeats CSRF protection and the CORS spec forbids it at the browser level"
                .to_string(),
            Severity::High,
            Category::Security,
        )
        .with_help(
            "pick one: either drop `.allow_credentials(true)` (no cookie / Authorization-header forwarding from cross-origin requests), or replace `Any` with an explicit allow-list (`.allow_origin([\"https://app.example.com\".parse()?])`). Browsers will block the credentials path silently when both are set; treat it as a configuration bug, not just a warning",
        )
        .with_location(location),
    )
}

fn byte_offset_to_line_col(text: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in text.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::DiscoveredFile;
    use crate::fingerprint::{DetectedProject, Ecosystem, Language, ProjectFingerprint};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn aux() -> Option<&'static AuxPatterns> {
        compiled_aux_patterns().ok()
    }

    #[test]
    fn cors_any_with_credentials_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
use tower_http::cors::{Any, CorsLayer};
let layer = CorsLayer::new()
    .allow_origin(Any)
    .allow_credentials(true)
    .allow_methods([axum::http::Method::GET]);
"#;
        let finding = scan_permissive_cors_with_credentials(&PathBuf::from("src/lib.rs"), src, a);
        assert!(finding.is_some(), "expected RSTR-AXUM-001 to fire");
        if let Some(f) = finding {
            assert_eq!(f.code, "RSTR-AXUM-001");
        }
    }

    #[test]
    fn cors_any_without_credentials_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
let layer = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods([axum::http::Method::GET]);
"#;
        assert!(
            scan_permissive_cors_with_credentials(&PathBuf::from("src/lib.rs"), src, a).is_none()
        );
    }

    #[test]
    fn cors_explicit_origin_with_credentials_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
let layer = CorsLayer::new()
    .allow_origin(["https://app.example.com".parse()?])
    .allow_credentials(true);
"#;
        assert!(
            scan_permissive_cors_with_credentials(&PathBuf::from("src/lib.rs"), src, a).is_none()
        );
    }

    #[test]
    fn cors_qualified_any_with_credentials_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
let layer = CorsLayer::new()
    .allow_origin(tower_http::cors::Any)
    .allow_credentials(true);
"#;
        assert!(
            scan_permissive_cors_with_credentials(&PathBuf::from("src/lib.rs"), src, a).is_some()
        );
    }

    fn fingerprint_with_axum(root: &str) -> ProjectFingerprint {
        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::Axum);
        let mut languages = BTreeSet::new();
        languages.insert(Language::Rust);
        let mut ecosystems = BTreeSet::new();
        ecosystems.insert(Ecosystem::Cargo);
        ProjectFingerprint {
            languages,
            ecosystems,
            frameworks,
            projects: vec![DetectedProject {
                root: PathBuf::from(root),
                manifest: PathBuf::from(format!("{root}/Cargo.toml")),
                language: Language::Rust,
                ecosystem: Some(Ecosystem::Cargo),
                frameworks: vec![Framework::Axum],
            }],
        }
    }

    #[test]
    fn wants_returns_false_when_no_axum_framework_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("src/lib.rs"),
                kind: FileKind::Source,
                size: None,
            }],
            ..Default::default()
        };
        assert!(!AxumAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_when_axum_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("services/api/src/lib.rs"),
                kind: FileKind::Source,
                size: None,
            }],
            fingerprint: fingerprint_with_axum("services/api"),
            ..Default::default()
        };
        assert!(AxumAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn analyze_emits_finding_only_inside_axum_project_root() {
        let tmp = std::env::temp_dir().join(format!("rastray-axum-{}", std::process::id()));
        let api_dir = tmp.join("services").join("api").join("src");
        let other_dir = tmp.join("services").join("other").join("src");
        let _ = std::fs::create_dir_all(&api_dir);
        let _ = std::fs::create_dir_all(&other_dir);

        let bad_src = "let layer = CorsLayer::new()\n\
                       .allow_origin(Any)\n\
                       .allow_credentials(true);\n";
        let api_file = api_dir.join("cors.rs");
        let _ = std::fs::write(&api_file, bad_src);

        let other_file = other_dir.join("cors.rs");
        let _ = std::fs::write(&other_file, bad_src);

        let api_root = tmp.join("services").join("api");
        let crawl = CrawlSummary {
            files: vec![
                DiscoveredFile {
                    path: api_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: other_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
            ],
            skipped: 0,
            errors: vec![],
            fingerprint: {
                let mut frameworks = BTreeSet::new();
                frameworks.insert(Framework::Axum);
                let mut languages = BTreeSet::new();
                languages.insert(Language::Rust);
                let mut ecosystems = BTreeSet::new();
                ecosystems.insert(Ecosystem::Cargo);
                ProjectFingerprint {
                    languages,
                    ecosystems,
                    frameworks,
                    projects: vec![DetectedProject {
                        root: api_root.clone(),
                        manifest: api_root.join("Cargo.toml"),
                        language: Language::Rust,
                        ecosystem: Some(Ecosystem::Cargo),
                        frameworks: vec![Framework::Axum],
                    }],
                }
            },
        };

        let findings = AxumAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly one finding (in apps/api/), got {findings:?}"
        );
        let f = &findings[0];
        assert_eq!(f.code, "RSTR-AXUM-001");
        assert!(
            f.location.as_ref().is_some_and(|l| l.file == api_file),
            "finding should be scoped to the Axum project root only, got {f:?}"
        );
    }
}
