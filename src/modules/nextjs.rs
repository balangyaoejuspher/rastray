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
pub struct NextjsAnalyzer;

impl NextjsAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for NextjsAnalyzer {
    fn name(&self) -> &'static str {
        "nextjs"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl.fingerprint.frameworks.contains(&Framework::Nextjs)
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let regex_patterns = compiled_patterns()?;
        let aux = compiled_aux_patterns()?;
        let mut findings = Vec::new();
        let project_roots: Vec<PathBuf> = crawl
            .fingerprint
            .projects
            .iter()
            .filter(|p| p.frameworks.contains(&Framework::Nextjs))
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
            for pattern in regex_patterns {
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
            if let Some(finding) = scan_unvalidated_server_action(&file.path, &contents, aux) {
                findings.push(finding);
            }
            if is_app_router_route_file(&file.path) {
                if let Some(finding) = scan_unauthed_route_handler(&file.path, &contents, aux) {
                    findings.push(finding);
                }
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
    code: "RSTR-NEXT-001",
    message: "Next.js page-data / server-side Prisma destructive call with a bare identifier as id; risk of type confusion and broken access control across tenants",
    severity: Severity::High,
    help: "in `getServerSideProps`, `getStaticProps`, server actions, and route handlers, coerce `context.query.x` / `context.params.x` explicitly (`Number(...)` / `z.coerce.number().parse(...)`) and add an ownership check (`where: { id, ownerId: session.user.id }`) before passing to Prisma",
    pattern: r"\bprisma\s*\.\s*\w+\s*\.\s*(?:delete|update|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*[A-Za-z_$][\w$]*\s*[,}]",
}];

struct AuxPatterns {
    use_server_directive: Regex,
    server_action_export: Regex,
    destructive_sink: Regex,
    input_validation: Regex,
    mutation_export: Regex,
    auth_marker: Regex,
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
            name: "nextjs",
            message: format!("failed to compile a builtin nextjs pattern: {e}"),
        }),
    }
}

fn compiled_aux_patterns() -> Result<&'static AuxPatterns, AnalyzerError> {
    static CACHE: OnceLock<Result<AuxPatterns, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| {
        let use_server_directive = Regex::new(r#"(?m)^\s*['"]use server['"]"#)
            .map_err(|e| format!("use_server: {e}"))?;
        let server_action_export = Regex::new(r"\bexport\s+(?:async\s+function|const\s+\w+\s*=\s*async)")
            .map_err(|e| format!("server_action_export: {e}"))?;
        let destructive_sink = Regex::new(
            r"\bprisma\s*\.\s*\w+\s*\.\s*(?:delete|deleteMany|update|updateMany|create|createMany|upsert)\s*\(",
        )
        .map_err(|e| format!("destructive_sink: {e}"))?;
        let input_validation =
            Regex::new(r"\b(?:zod|z\.[a-zA-Z]|yup|valibot|joi|superstruct|class-validator|safeParse|\.parse\s*\()")
                .map_err(|e| format!("input_validation: {e}"))?;
        let mutation_export = Regex::new(
            r"(?m)^\s*export\s+(?:async\s+function|const)\s+(?:POST|PUT|PATCH|DELETE)\b",
        )
        .map_err(|e| format!("mutation_export: {e}"))?;
        let auth_marker = Regex::new(
            r#"\b(?:getServerSession|getToken|currentUser|getUser|requireAuth|requireSession|verifySession|verifyToken|auth\s*\(|cookies\s*\(\s*\)\s*\.\s*get|headers\s*\(\s*\)\s*\.\s*get\s*\(\s*['"]authorization|\breq(?:uest)?\s*\.\s*cookies\s*\.\s*get\s*\(|\breq(?:uest)?\s*\.\s*headers\s*\.\s*get\s*\(\s*['"]authorization)"#,
        )
        .map_err(|e| format!("auth_marker: {e}"))?;
        Ok(AuxPatterns {
            use_server_directive,
            server_action_export,
            destructive_sink,
            input_validation,
            mutation_export,
            auth_marker,
        })
    });
    match cached {
        Ok(p) => Ok(p),
        Err(e) => Err(AnalyzerError::Failed {
            name: "nextjs",
            message: format!("failed to compile a builtin nextjs aux pattern: {e}"),
        }),
    }
}

fn scan_unvalidated_server_action(
    path: &std::path::Path,
    contents: &str,
    aux: &AuxPatterns,
) -> Option<Finding> {
    let directive = aux.use_server_directive.find(contents)?;
    if !aux.server_action_export.is_match(contents) {
        return None;
    }
    if !aux.destructive_sink.is_match(contents) {
        return None;
    }
    if aux.input_validation.is_match(contents) {
        return None;
    }
    let (line, column) = byte_offset_to_line_col(contents, directive.start());
    let location = Location::file(path.to_path_buf())
        .with_span(directive.start(), directive.len())
        .with_line(line, column);
    Some(
        Finding::new(
            "RSTR-NEXT-002",
            "Next.js server action file (`'use server'`) makes a destructive Prisma call without any input-validation library reference (zod / valibot / yup / joi / class-validator); server actions are public endpoints and must validate every parameter".to_string(),
            Severity::High,
            Category::Security,
        )
        .with_help(
            "validate every action parameter with a schema library before letting Prisma touch the database (`const body = schema.parse(input)` or `safeParse`), and add an authorization check against the caller's session",
        )
        .with_location(location),
    )
}

fn scan_unauthed_route_handler(
    path: &std::path::Path,
    contents: &str,
    aux: &AuxPatterns,
) -> Option<Finding> {
    let mutation_match = aux.mutation_export.find(contents)?;
    if aux.auth_marker.is_match(contents) {
        return None;
    }
    let (line, column) = byte_offset_to_line_col(contents, mutation_match.start());
    let location = Location::file(path.to_path_buf())
        .with_span(mutation_match.start(), mutation_match.len())
        .with_line(line, column);
    Some(
        Finding::new(
            "RSTR-NEXT-003",
            "Next.js App Router `route.ts` exports a mutation handler (POST / PUT / PATCH / DELETE) without any auth helper reference (`auth()` / `getServerSession()` / `getToken()` / `currentUser()` / `cookies().get(...)` / `headers().get('authorization')`)".to_string(),
            Severity::Medium,
            Category::Security,
        )
        .with_help(
            "call your auth helper at the top of every mutation handler (`const session = await auth(); if (!session) return new Response(null, { status: 401 });`) or document the global middleware that enforces auth for this route segment",
        )
        .with_location(location),
    )
}

fn is_app_router_route_file(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let is_route = lower == "route.ts"
        || lower == "route.tsx"
        || lower == "route.js"
        || lower == "route.jsx"
        || lower == "route.mts"
        || lower == "route.cts";
    if !is_route {
        return false;
    }
    let normalised = path.to_string_lossy().replace('\\', "/").to_lowercase();
    normalised.contains("/app/")
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

    fn next_001_regex() -> Option<&'static Regex> {
        let p = compiled_patterns().ok()?;
        p.iter()
            .find(|c| c.code == "RSTR-NEXT-001")
            .map(|c| &c.regex)
    }

    fn aux() -> Option<&'static AuxPatterns> {
        compiled_aux_patterns().ok()
    }

    #[test]
    fn next_001_flags_bare_identifier_in_prisma_destructive() {
        let Some(re) = next_001_regex() else {
            return;
        };
        assert!(re.is_match("prisma.user.delete({ where: { id: id } })"));
        assert!(re.is_match("prisma.user.update({ where: { id: userId }, data: { x: 1 } })"));
        assert!(
            re.is_match("prisma.order.findUniqueOrThrow({ where: { id: orderId }, include: {} })")
        );
    }

    #[test]
    fn next_001_ignores_coerced_or_qualified_ids() {
        let Some(re) = next_001_regex() else {
            return;
        };
        assert!(!re.is_match("prisma.user.delete({ where: { id: Number(id) } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: context.query.id } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: ctx.params.id } })"));
        assert!(!re.is_match("prisma.user.delete({ where: { id: session.user.id } })"));
        assert!(!re.is_match("prisma.user.findMany({ where: { id: id } })"));
    }

    #[test]
    fn next_002_flags_use_server_with_destructive_call_and_no_validation() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"'use server'

export async function deleteAccount(input: { id: string }) {
    return prisma.user.delete({ where: { id: input.id } });
}
"#;
        let finding = scan_unvalidated_server_action(&PathBuf::from("app/actions.ts"), src, a);
        assert!(finding.is_some());
        if let Some(f) = finding {
            assert_eq!(f.code, "RSTR-NEXT-002");
        }
    }

    #[test]
    fn next_002_silent_when_validation_library_is_used() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"'use server'
import { z } from 'zod';
const Schema = z.object({ id: z.string().uuid() });

export async function deleteAccount(input: unknown) {
    const { id } = Schema.parse(input);
    return prisma.user.delete({ where: { id } });
}
"#;
        assert!(scan_unvalidated_server_action(&PathBuf::from("app/actions.ts"), src, a).is_none());
    }

    #[test]
    fn next_002_silent_when_no_destructive_call() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"'use server'
export async function getProfile(id: string) {
    return prisma.user.findMany({ where: { id } });
}
"#;
        assert!(scan_unvalidated_server_action(&PathBuf::from("app/actions.ts"), src, a).is_none());
    }

    #[test]
    fn next_002_silent_when_no_use_server_directive() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"export async function helper(id: string) {
    return prisma.user.delete({ where: { id } });
}
"#;
        assert!(scan_unvalidated_server_action(&PathBuf::from("lib/helpers.ts"), src, a).is_none());
    }

    #[test]
    fn is_app_router_route_file_recognises_app_route_paths() {
        assert!(is_app_router_route_file(&PathBuf::from(
            "apps/web/app/api/users/route.ts"
        )));
        assert!(is_app_router_route_file(&PathBuf::from(
            "src/app/api/route.tsx"
        )));
        #[cfg(windows)]
        assert!(is_app_router_route_file(&PathBuf::from(
            r"C:\repo\app\api\route.ts"
        )));
    }

    #[test]
    fn is_app_router_route_file_rejects_non_route_files() {
        assert!(!is_app_router_route_file(&PathBuf::from(
            "apps/web/app/page.tsx"
        )));
        assert!(!is_app_router_route_file(&PathBuf::from(
            "apps/web/pages/api/users.ts"
        )));
        assert!(!is_app_router_route_file(&PathBuf::from("lib/route.ts")));
    }

    #[test]
    fn next_003_flags_post_export_without_auth_marker() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"import { NextResponse } from 'next/server';

export async function POST(req: Request) {
    const body = await req.json();
    return NextResponse.json({ ok: true });
}
"#;
        let finding = scan_unauthed_route_handler(&PathBuf::from("app/api/users/route.ts"), src, a);
        assert!(finding.is_some());
        if let Some(f) = finding {
            assert_eq!(f.code, "RSTR-NEXT-003");
        }
    }

    #[test]
    fn next_003_silent_when_auth_helper_called() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"import { auth } from '@/lib/auth';

export async function DELETE(req: Request) {
    const session = await auth();
    if (!session) return new Response(null, { status: 401 });
    return new Response(null, { status: 204 });
}
"#;
        assert!(
            scan_unauthed_route_handler(&PathBuf::from("app/api/users/route.ts"), src, a).is_none()
        );
    }

    #[test]
    fn next_003_silent_for_read_only_route() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"export async function GET() {
    return new Response('ok');
}
"#;
        assert!(
            scan_unauthed_route_handler(&PathBuf::from("app/api/health/route.ts"), src, a)
                .is_none()
        );
    }

    #[test]
    fn next_003_silent_when_req_cookies_get_is_used() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
    const accessToken = req.cookies.get('mlhcm_at')?.value;
    if (!accessToken) {
        return NextResponse.json({ error: 'UNAUTHENTICATED' }, { status: 401 });
    }
    return NextResponse.json({ ok: true });
}
"#;
        assert!(
            scan_unauthed_route_handler(&PathBuf::from("app/api/users/route.ts"), src, a).is_none()
        );
    }

    #[test]
    fn next_003_silent_when_request_cookies_get_is_used() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"export async function DELETE(request: Request) {
    const token = request.cookies.get('session')?.value;
    if (!token) return new Response(null, { status: 401 });
    return new Response(null, { status: 204 });
}
"#;
        assert!(
            scan_unauthed_route_handler(&PathBuf::from("app/api/admin/route.ts"), src, a).is_none()
        );
    }

    #[test]
    fn next_003_silent_when_req_headers_authorization_is_used() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"export async function PATCH(req: Request) {
    const bearer = req.headers.get('authorization');
    if (!bearer) return new Response(null, { status: 401 });
    return new Response(null, { status: 200 });
}
"#;
        assert!(
            scan_unauthed_route_handler(&PathBuf::from("app/api/profile/route.ts"), src, a)
                .is_none()
        );
    }

    #[test]
    fn next_003_silent_when_verify_session_helper_called() {
        let Some(a) = aux() else {
            return;
        };
        let src = r#"import { verifySession } from '@/lib/auth';

export async function PUT(req: Request) {
    const session = await verifySession(req);
    if (!session) return new Response(null, { status: 401 });
    return new Response(null, { status: 200 });
}
"#;
        assert!(
            scan_unauthed_route_handler(&PathBuf::from("app/api/users/route.ts"), src, a).is_none()
        );
    }

    fn fingerprint_with_nextjs(root: &str) -> ProjectFingerprint {
        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::Nextjs);
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
                frameworks: vec![Framework::Nextjs],
            }],
        }
    }

    #[test]
    fn wants_returns_false_when_no_nextjs_framework_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("src/app.ts"),
                kind: FileKind::Source,
                size: None,
            }],
            ..Default::default()
        };
        assert!(!NextjsAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_when_nextjs_detected() {
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: PathBuf::from("apps/web/src/app.ts"),
                kind: FileKind::Source,
                size: None,
            }],
            fingerprint: fingerprint_with_nextjs("apps/web"),
            ..Default::default()
        };
        assert!(NextjsAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn analyze_emits_findings_only_for_files_inside_nextjs_project_root() {
        let tmp = std::env::temp_dir().join(format!("rastray-next-{}", std::process::id()));
        let web_dir = tmp
            .join("apps")
            .join("web")
            .join("app")
            .join("api")
            .join("users");
        let api_dir = tmp.join("apps").join("api").join("src");
        let _ = std::fs::create_dir_all(&web_dir);
        let _ = std::fs::create_dir_all(&api_dir);

        let route_src = "export async function POST(req: Request) {\n\
                         return new Response('ok');\n\
                       }\n";
        let route_file = web_dir.join("route.ts");
        let _ = std::fs::write(&route_file, route_src);

        let prisma_src = "export async function helper(id: string) {\n\
                          return prisma.user.delete({ where: { id: id } });\n\
                        }\n";
        let prisma_file = api_dir.join("svc.ts");
        let _ = std::fs::write(&prisma_file, prisma_src);

        let mut frameworks = BTreeSet::new();
        frameworks.insert(Framework::Nextjs);
        let mut languages = BTreeSet::new();
        languages.insert(Language::TypeScript);
        let mut ecosystems = BTreeSet::new();
        ecosystems.insert(Ecosystem::Npm);

        let web_root = tmp.join("apps").join("web");
        let crawl = CrawlSummary {
            files: vec![
                DiscoveredFile {
                    path: route_file.clone(),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: prisma_file.clone(),
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
                    root: web_root.clone(),
                    manifest: web_root.join("package.json"),
                    language: Language::TypeScript,
                    ecosystem: Some(Ecosystem::Npm),
                    frameworks: vec![Framework::Nextjs],
                }],
            },
        };

        let findings = NextjsAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&tmp);

        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(
            codes.contains(&"RSTR-NEXT-003"),
            "expected RSTR-NEXT-003 on the web route, got {codes:?}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.location.as_ref().is_some_and(|l| l.file == route_file)),
            "findings should be scoped to the Next.js project root only, got {codes:?}"
        );
    }
}
