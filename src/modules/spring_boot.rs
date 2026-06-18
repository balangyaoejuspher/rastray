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
pub struct SpringBootAnalyzer;

impl SpringBootAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for SpringBootAnalyzer {
    fn name(&self) -> &'static str {
        "spring-boot"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl
            .fingerprint
            .frameworks
            .contains(&Framework::SpringBoot)
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let aux = compiled_aux_patterns()?;
        let mut findings = Vec::new();
        let project_roots: Vec<PathBuf> = crawl
            .fingerprint
            .projects
            .iter()
            .filter(|p| p.frameworks.contains(&Framework::SpringBoot))
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
            if ext != "java" && ext != "kt" {
                continue;
            }
            if !project_roots.iter().any(|root| file.path.starts_with(root)) {
                continue;
            }
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if !is_spring_security_file(&contents, aux) {
                continue;
            }
            findings.extend(scan_broad_permit_all(&file.path, &contents, aux));
        }
        Ok(findings)
    }
}

struct AuxPatterns {
    spring_security_marker: Regex,
    broad_permit_all: Regex,
}

fn compiled_aux_patterns() -> Result<&'static AuxPatterns, AnalyzerError> {
    static CACHE: OnceLock<Result<AuxPatterns, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let spring_security_marker = Regex::new(
            r"(?m)^\s*import\s+org\.springframework\.security\b|@EnableWebSecurity\b|SecurityFilterChain\b|HttpSecurity\b",
        )
        .map_err(|e| format!("spring_security_marker: {e}"))?;
        let broad_permit_all = Regex::new(
            r#"\.(?:requestMatchers|antMatchers|mvcMatchers)\s*\(\s*["'](?:/\*\*|/api/\*\*|/api/v\d+/\*\*|/v\d+/\*\*|/services/\*\*|/rest/\*\*)["']\s*\)\s*\.\s*permitAll\s*\(\s*\)"#,
        )
        .map_err(|e| format!("broad_permit_all: {e}"))?;
        Ok(AuxPatterns {
            spring_security_marker,
            broad_permit_all,
        })
    });
    match cached {
        Ok(p) => Ok(p),
        Err(e) => Err(AnalyzerError::Failed {
            name: "spring-boot",
            message: format!("failed to compile a builtin spring-boot aux pattern: {e}"),
        }),
    }
}

fn is_spring_security_file(contents: &str, aux: &AuxPatterns) -> bool {
    aux.spring_security_marker.is_match(contents)
}

fn scan_broad_permit_all(
    path: &std::path::Path,
    contents: &str,
    aux: &AuxPatterns,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in aux.broad_permit_all.find_iter(contents) {
        let (line, column) = byte_offset_to_line_col(contents, m.start());
        let location = Location::file(path.to_path_buf())
            .with_span(m.start(), m.len())
            .with_line(line, column);
        out.push(
            Finding::new(
                "RSTR-SPRING-001",
                "Spring Security configuration allows unauthenticated access to a broad path pattern (`/**`, `/api/**`, `/v{n}/**`, etc.) via `permitAll()`; every endpoint under that prefix is reachable without authentication, including ones added later by other teams"
                    .to_string(),
                Severity::High,
                Category::Security,
            )
            .with_help(
                "scope `permitAll()` to specific public endpoints only: `.requestMatchers(\"/api/auth/login\", \"/api/auth/register\", \"/actuator/health\").permitAll().anyRequest().authenticated()`. The default for every other path should be `.authenticated()` or a role check. If you genuinely need a fully public API surface, document it explicitly in a `SecurityFilterChain` whose name is `publicApiSecurityFilterChain` and add a `// rastray-ignore: RSTR-SPRING-001 -- <why>` on the line",
            )
            .with_location(location),
        );
    }
    out
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
    fn broad_slash_star_permit_all_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/**").permitAll()
        );
        return http.build();
    }
}
"#;
        let findings = scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-SPRING-001");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn api_wildcard_permit_all_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
http.authorizeHttpRequests(auth -> auth.requestMatchers("/api/**").permitAll());
"#;
        assert_eq!(
            scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a).len(),
            1
        );
    }

    #[test]
    fn api_versioned_wildcard_permit_all_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
http.authorizeHttpRequests(auth -> auth.requestMatchers("/api/v1/**").permitAll());
"#;
        assert_eq!(
            scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a).len(),
            1
        );
    }

    #[test]
    fn legacy_ant_matchers_is_flagged() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
http.authorizeRequests().antMatchers("/api/**").permitAll();
"#;
        assert_eq!(
            scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a).len(),
            1
        );
    }

    #[test]
    fn specific_endpoint_permit_all_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
    .requestMatchers("/actuator/health").permitAll()
    .anyRequest().authenticated()
);
"#;
        assert!(scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a).is_empty());
    }

    #[test]
    fn broad_authenticated_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
http.authorizeHttpRequests(auth -> auth.requestMatchers("/**").authenticated());
"#;
        assert!(scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a).is_empty());
    }

    #[test]
    fn broad_has_role_is_silent() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
http.authorizeHttpRequests(auth -> auth.requestMatchers("/admin/**").hasRole("ADMIN"));
"#;
        assert!(scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a).is_empty());
    }

    #[test]
    fn sibling_permit_all_for_other_matcher_is_not_falsely_attributed() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/auth/login").permitAll()
    .requestMatchers("/api/**").authenticated()
);
"#;
        assert!(scan_broad_permit_all(&PathBuf::from("Sec.java"), src, a).is_empty());
    }

    #[test]
    fn is_spring_security_file_recognises_import() {
        let Some(a) = aux() else {
            return;
        };
        assert!(is_spring_security_file(
            "import org.springframework.security.config.annotation.web.builders.HttpSecurity;",
            a
        ));
    }

    #[test]
    fn is_spring_security_file_recognises_enable_web_security() {
        let Some(a) = aux() else {
            return;
        };
        assert!(is_spring_security_file(
            "@Configuration\n@EnableWebSecurity\nclass Sec {}",
            a
        ));
    }

    #[test]
    fn is_spring_security_file_recognises_security_filter_chain_symbol() {
        let Some(a) = aux() else {
            return;
        };
        assert!(is_spring_security_file(
            "public SecurityFilterChain filterChain(HttpSecurity http) {}",
            a
        ));
    }

    #[test]
    fn is_spring_security_file_rejects_plain_pojo() {
        let Some(a) = aux() else {
            return;
        };
        assert!(!is_spring_security_file(
            "public class UserDto { private String name; }",
            a
        ));
    }

    fn fingerprint_with_spring(root: &str) -> ProjectFingerprint {
        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::SpringBoot);
        let mut languages = BTreeSet::new();
        languages.insert(Language::Java);
        let mut ecosystems = BTreeSet::new();
        ecosystems.insert(Ecosystem::Maven);
        ProjectFingerprint {
            languages,
            ecosystems,
            frameworks,
            projects: vec![DetectedProject {
                root: PathBuf::from(root),
                manifest: PathBuf::from(format!("{root}/pom.xml")),
                language: Language::Java,
                ecosystem: Some(Ecosystem::Maven),
                frameworks: vec![Framework::SpringBoot],
            }],
        }
    }

    #[test]
    fn wants_returns_false_when_no_spring_boot_framework_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("src/main/java/Sec.java"),
                kind: FileKind::Source,
                size: None,
            }],
            ..Default::default()
        };
        assert!(!SpringBootAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_when_spring_boot_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("apps/api/src/main/java/Sec.java"),
                kind: FileKind::Source,
                size: None,
            }],
            fingerprint: fingerprint_with_spring("apps/api"),
            ..Default::default()
        };
        assert!(SpringBootAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn analyze_emits_findings_only_inside_spring_boot_project_roots() {
        let tmp = std::env::temp_dir().join(format!("rastray-spring-{}", std::process::id()));
        let api_dir = tmp
            .join("apps")
            .join("api")
            .join("src")
            .join("main")
            .join("java");
        let other_dir = tmp
            .join("apps")
            .join("other")
            .join("src")
            .join("main")
            .join("java");
        let _ = std::fs::create_dir_all(&api_dir);
        let _ = std::fs::create_dir_all(&other_dir);

        let sec_src = r#"
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/**").permitAll()
        );
        return http.build();
    }
}
"#;
        let sec_file = api_dir.join("SecurityConfig.java");
        let _ = std::fs::write(&sec_file, sec_src);

        let pojo_src = "public class UserDto { private String name; }";
        let pojo_file = api_dir.join("UserDto.java");
        let _ = std::fs::write(&pojo_file, pojo_src);

        let other_sec_file = other_dir.join("SecurityConfig.java");
        let _ = std::fs::write(&other_sec_file, sec_src);

        let api_root = tmp.join("apps").join("api");
        let crawl = CrawlSummary {
            files: vec![
                DiscoveredFile {
                    path: sec_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: pojo_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: other_sec_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
            ],
            skipped: 0,
            errors: vec![],
            fingerprint: fingerprint_with_spring(&api_root.to_string_lossy()),
        };

        let findings = SpringBootAnalyzer::new()
            .analyze(&crawl)
            .unwrap_or_default();
        let _ = std::fs::remove_dir_all(&tmp);

        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(
            codes.contains(&"RSTR-SPRING-001"),
            "expected RSTR-SPRING-001, got {codes:?}"
        );
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding (on the in-project SecurityConfig.java only), got {findings:?}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.location.as_ref().is_some_and(|l| l.file == sec_file)),
            "findings should be scoped to the Spring Boot project's SecurityConfig.java only, got {findings:?}"
        );
    }
}
