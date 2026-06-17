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
pub struct NestjsAnalyzer;

impl NestjsAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for NestjsAnalyzer {
    fn name(&self) -> &'static str {
        "nestjs"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl.fingerprint.frameworks.contains(&Framework::Nestjs)
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let patterns = compiled_patterns()?;
        let aux = compiled_aux_patterns()?;
        let mut findings = Vec::new();
        let project_roots: Vec<PathBuf> = crawl
            .fingerprint
            .projects
            .iter()
            .filter(|p| p.frameworks.contains(&Framework::Nestjs))
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
            if !TS_JS_EXTENSIONS.iter().any(|e| *e == ext) {
                continue;
            }
            if !project_roots.iter().any(|root| file.path.starts_with(root)) {
                continue;
            }
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for pattern in patterns {
                for m in pattern.regex.find_iter(&contents) {
                    let (line, column) = byte_offset_to_line_col(&contents, m.start());
                    let location = Location::file(file.path.clone())
                        .with_span(m.start(), m.len())
                        .with_line(line, column);
                    findings.push(
                        Finding::new(
                            pattern.code,
                            pattern.message.to_string(),
                            pattern.severity,
                            Category::Security,
                        )
                        .with_help(pattern.help)
                        .with_location(location),
                    );
                }
            }
            if let Some(finding) = scan_unguarded_controller(&file.path, &contents, aux) {
                findings.push(finding);
            }
        }
        Ok(findings)
    }
}

const TS_JS_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mts", "cts"];

struct PatternSpec {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
}

struct CompiledPattern {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
}

const PATTERN_SPECS: &[PatternSpec] = &[PatternSpec {
    code: "RSTR-NEST-001",
    message: "Prisma destructive call with a bare identifier as numeric id; risk of type confusion / unbounded access",
    severity: Severity::High,
    help: "wrap the param with a ParseIntPipe (`@Param('id', ParseIntPipe) id: number`) or coerce explicitly (`Number(id)` / `parseInt(id, 10)`), and validate the input belongs to the caller before destructive ops",
    pattern: r"\bprisma\s*\.\s*\w+\s*\.\s*(?:delete|update|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*[A-Za-z_$][\w$]*\s*[,}]",
}];

struct AuxPatterns {
    controller: Regex,
    mutation: Regex,
    guard: Regex,
}

fn compiled_patterns() -> Result<&'static [CompiledPattern], AnalyzerError> {
    static CACHE: OnceLock<Result<Vec<CompiledPattern>, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        PATTERN_SPECS
            .iter()
            .map(|spec| {
                Regex::new(spec.pattern)
                    .map(|regex| CompiledPattern {
                        code: spec.code,
                        message: spec.message,
                        severity: spec.severity,
                        help: spec.help,
                        regex,
                    })
                    .map_err(|e| format!("failed to compile {}: {e}", spec.code))
            })
            .collect::<Result<Vec<_>, _>>()
    });
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(AnalyzerError::Failed {
            name: "nestjs",
            message: format!("failed to compile a builtin nestjs pattern: {e}"),
        }),
    }
}

fn compiled_aux_patterns() -> Result<&'static AuxPatterns, AnalyzerError> {
    static CACHE: OnceLock<Result<AuxPatterns, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let controller =
            Regex::new(r"@Controller\s*\(").map_err(|e| format!("controller regex: {e}"))?;
        let mutation = Regex::new(r"@(?:Post|Put|Patch|Delete)\s*\(")
            .map_err(|e| format!("mutation regex: {e}"))?;
        let guard = Regex::new(r"@(?:UseGuards|Roles|Auth|Public|SkipAuth)\s*\(")
            .map_err(|e| format!("guard regex: {e}"))?;
        Ok(AuxPatterns {
            controller,
            mutation,
            guard,
        })
    });
    match cached {
        Ok(p) => Ok(p),
        Err(e) => Err(AnalyzerError::Failed {
            name: "nestjs",
            message: format!("failed to compile a builtin nestjs aux pattern: {e}"),
        }),
    }
}

fn scan_unguarded_controller(
    path: &std::path::Path,
    contents: &str,
    aux: &AuxPatterns,
) -> Option<Finding> {
    let controller_match = aux.controller.find(contents)?;
    if !aux.mutation.is_match(contents) {
        return None;
    }
    if aux.guard.is_match(contents) {
        return None;
    }
    let (line, column) = byte_offset_to_line_col(contents, controller_match.start());
    let location = Location::file(path.to_path_buf())
        .with_span(controller_match.start(), controller_match.len())
        .with_line(line, column);
    Some(
        Finding::new(
            "RSTR-NEST-002",
            "NestJS controller exposes a mutation handler (@Post/@Put/@Patch/@Delete) without any guard decorator (@UseGuards / @Roles / @Auth)".to_string(),
            Severity::High,
            Category::Security,
        )
        .with_help(
            "apply a guard at the class level (`@UseGuards(AuthGuard('jwt'))` above @Controller) or on each mutating handler; if a route is intentionally public mark it with `@Public()` so the guard runtime knows",
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

    fn nest_001_regex() -> Option<&'static Regex> {
        let p = compiled_patterns().ok()?;
        p.iter()
            .find(|c| c.code == "RSTR-NEST-001")
            .map(|c| &c.regex)
    }

    fn aux() -> Option<&'static AuxPatterns> {
        compiled_aux_patterns().ok()
    }

    #[test]
    fn nest_001_flags_bare_identifier_in_prisma_delete() {
        let Some(re) = nest_001_regex() else {
            return;
        };
        assert!(re.is_match("prisma.user.delete({ where: { id: id } })"));
        assert!(re.is_match("prisma.user.delete({ where: { id: userId, } })"));
        assert!(re.is_match("prisma.order.update({ where: { id: param } , data: {x: 1}})"));
        assert!(re.is_match(
            "prisma.user.findUniqueOrThrow({ where: { id: rawId }, include: { posts: true } })"
        ));
    }

    #[test]
    fn nest_001_ignores_coerced_or_qualified_ids() {
        let Some(re) = nest_001_regex() else {
            return;
        };
        assert!(!re.is_match("prisma.user.delete({ where: { id: Number(id) } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: parseInt(id, 10) } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: req.params.id } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: this.id } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: +id } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: BigInt(id) } })"));
    }

    #[test]
    fn nest_001_ignores_safe_reads() {
        let Some(re) = nest_001_regex() else {
            return;
        };
        assert!(!re.is_match("prisma.user.findMany({ where: { id: id } })"));
        assert!(!re.is_match("prisma.user.count({ where: { id: id } })"));
    }

    #[test]
    fn scan_unguarded_controller_flags_post_handler_without_guard() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
            @Controller('users')
            export class UsersController {
                @Post()
                create(@Body() dto: CreateUserDto) {}
            }
            "#;
        let finding = scan_unguarded_controller(&PathBuf::from("users.controller.ts"), src, a);
        assert!(finding.is_some());
        if let Some(f) = finding {
            assert_eq!(f.code, "RSTR-NEST-002");
        }
    }

    #[test]
    fn scan_unguarded_controller_silent_when_guard_present() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
            @UseGuards(AuthGuard('jwt'))
            @Controller('users')
            export class UsersController {
                @Post()
                create(@Body() dto: CreateUserDto) {}
            }
            "#;
        assert!(scan_unguarded_controller(&PathBuf::from("users.controller.ts"), src, a).is_none());
    }

    #[test]
    fn scan_unguarded_controller_silent_for_read_only_controller() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
            @Controller('health')
            export class HealthController {
                @Get()
                ping() { return { ok: true }; }
            }
            "#;
        assert!(
            scan_unguarded_controller(&PathBuf::from("health.controller.ts"), src, a).is_none()
        );
    }

    #[test]
    fn scan_unguarded_controller_silent_when_public_marker_used() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"
            @Controller('webhooks')
            export class WebhooksController {
                @Public()
                @Post()
                receive(@Body() body: any) {}
            }
            "#;
        assert!(
            scan_unguarded_controller(&PathBuf::from("webhooks.controller.ts"), src, a).is_none()
        );
    }

    fn fingerprint_with_nestjs(root: &str) -> ProjectFingerprint {
        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::Nestjs);
        let mut languages = BTreeSet::new();
        languages.insert(Language::TypeScript);
        let mut ecosystems = BTreeSet::new();
        ecosystems.insert(Ecosystem::Npm);
        ProjectFingerprint {
            languages,
            ecosystems,
            frameworks,
            projects: vec![DetectedProject {
                root: PathBuf::from(root),
                manifest: PathBuf::from(format!("{root}/package.json")),
                language: Language::TypeScript,
                ecosystem: Some(Ecosystem::Npm),
                frameworks: vec![Framework::Nestjs],
            }],
        }
    }

    #[test]
    fn wants_returns_false_when_no_nestjs_framework_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("src/app.ts"),
                kind: FileKind::Source,
                size: None,
            }],
            ..Default::default()
        };
        assert!(!NestjsAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_when_nestjs_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("apps/api/src/app.ts"),
                kind: FileKind::Source,
                size: None,
            }],
            fingerprint: fingerprint_with_nestjs("apps/api"),
            ..Default::default()
        };
        assert!(NestjsAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn analyze_emits_findings_only_for_files_inside_nestjs_project_root() {
        let tmp = std::env::temp_dir().join(format!("rastray-nest-{}", std::process::id()));
        let api_dir = tmp.join("apps").join("api").join("src");
        let web_dir = tmp.join("apps").join("web").join("src");
        let _ = std::fs::create_dir_all(&api_dir);
        let _ = std::fs::create_dir_all(&web_dir);

        let api_src = "import { Controller, Delete, Param } from '@nestjs/common';\n\
                       @Controller('users')\n\
                       export class UsersController {\n\
                         @Delete(':id')\n\
                         remove(@Param('id') id: string) {\n\
                           return prisma.user.delete({ where: { id: id } });\n\
                         }\n\
                       }\n";
        let api_file = api_dir.join("users.controller.ts");
        let _ = std::fs::write(&api_file, api_src);

        let web_src = "export default function Page() {\n\
                         return prisma.user.delete({ where: { id: id } });\n\
                       }\n";
        let web_file = web_dir.join("page.tsx");
        let _ = std::fs::write(&web_file, web_src);

        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::Nestjs);
        let mut languages = BTreeSet::new();
        languages.insert(Language::TypeScript);
        let mut ecosystems = BTreeSet::new();
        ecosystems.insert(Ecosystem::Npm);

        let api_root = tmp.join("apps").join("api");
        let crawl = CrawlSummary {
            files: vec![
                DiscoveredFile {
                    path: api_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: web_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
            ],
            skipped: 0,
            errors: vec![],
            fingerprint: ProjectFingerprint {
                languages,
                ecosystems,
                frameworks,
                projects: vec![DetectedProject {
                    root: api_root.clone(),
                    manifest: api_root.join("package.json"),
                    language: Language::TypeScript,
                    ecosystem: Some(Ecosystem::Npm),
                    frameworks: vec![Framework::Nestjs],
                }],
            },
        };

        let findings = NestjsAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&tmp);

        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(
            codes.contains(&"RSTR-NEST-001"),
            "expected RSTR-NEST-001, got {codes:?}"
        );
        assert!(
            codes.contains(&"RSTR-NEST-002"),
            "expected RSTR-NEST-002, got {codes:?}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.location.as_ref().is_some_and(|l| l.file == api_file)),
            "findings should be scoped to the NestJS project root only"
        );
    }
}
