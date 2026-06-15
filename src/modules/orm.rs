use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct OrmAnalyzer;

impl OrmAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for OrmAnalyzer {
    fn name(&self) -> &'static str {
        "orm"
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let patterns = compiled_patterns()?;
        let mut findings = Vec::new();
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
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for pattern in patterns {
                if !pattern.extensions.iter().any(|e| *e == ext) {
                    continue;
                }
                for m in pattern.regex.find_iter(&contents) {
                    let matched = trim_match(m.as_str());
                    let message = format!("`{matched}` {trailer}", trailer = pattern.trailer);
                    let (line, column) = byte_offset_to_line_col(&contents, m.start());
                    let location = Location::file(file.path.clone())
                        .with_span(m.start(), m.len())
                        .with_line(line, column);
                    findings.push(
                        Finding::new(pattern.code, message, pattern.severity, Category::Security)
                            .with_help(pattern.help)
                            .with_location(location),
                    );
                }
            }
        }
        Ok(findings)
    }
}

struct PatternSpec {
    code: &'static str,
    trailer: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
    extensions: &'static [&'static str],
}

struct CompiledPattern {
    code: &'static str,
    trailer: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
    extensions: &'static [&'static str],
}

const JS_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PY_EXTENSIONS: &[&str] = &["py"];
const RB_EXTENSIONS: &[&str] = &["rb"];

const TRAILER_MASS_ASSIGN: &str =
    "spreads a request body directly into an ORM create/update — mass-assignment risk: any field name in the request (e.g. `isAdmin`, `role`, `verified`) will be written even if it was not in the form";
const TRAILER_RAW_SQL_TEMPLATE: &str =
    "interpolates user input into a raw-SQL template literal — SQL injection via string concatenation";

const HELP_NODE_ORM: &str = "use a per-route allow-list of safe fields (e.g. `lodash.pick(req.body, ['name', 'email'])`) before passing to the ORM, or validate with `zod` / `joi` / `class-validator`; never spread `req.body` directly into the data object";
const HELP_PY_ORM: &str = "validate the request body against a schema (`pydantic` / `marshmallow`) and pass only the validated allow-listed fields; for Django specifically use a `ModelForm` with an explicit `fields` allow-list rather than `Model.objects.create(**request.POST)`";
const HELP_RB_ORM: &str = "use Rails' Strong Parameters: `params.require(:user).permit(:name, :email)` before `Model.update` / `Model.create`; never call `update(params[:user])` raw";
const HELP_RAW_SQL: &str = "use parameterised queries: `db.query('SELECT * FROM users WHERE id = ?', [id])` or your ORM's parameter binding; template-literal interpolation is concatenation by another name and is SQL-injectable";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-ORM-001",
        trailer: TRAILER_MASS_ASSIGN,
        severity: Severity::High,
        help: HELP_NODE_ORM,
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*\.create\s*\(\s*req\.(?:body|query|params)\s*[,)]",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-001",
        trailer: TRAILER_MASS_ASSIGN,
        severity: Severity::High,
        help: HELP_NODE_ORM,
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*\.update\s*\(\s*req\.(?:body|query|params)\s*[,)]",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-001",
        trailer: TRAILER_MASS_ASSIGN,
        severity: Severity::High,
        help: HELP_NODE_ORM,
        pattern: r"\bprisma\.[A-Za-z_][A-Za-z0-9_]*\.(?:create|update|upsert)\s*\(\s*\{[^}]*\bdata\s*:\s*req\.(?:body|query|params)\b",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-002",
        trailer: TRAILER_MASS_ASSIGN,
        severity: Severity::High,
        help: HELP_PY_ORM,
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*\.objects\.create\s*\(\s*\*\*request\.(?:POST|GET|data|JSON)\b",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-002",
        trailer: TRAILER_MASS_ASSIGN,
        severity: Severity::High,
        help: HELP_PY_ORM,
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*\.objects\.(?:filter|get)\s*\(\s*\*\*request\.(?:POST|GET|data|JSON)\b",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-003",
        trailer: TRAILER_MASS_ASSIGN,
        severity: Severity::High,
        help: HELP_RB_ORM,
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*\.update\s*\(\s*params\[\s*:[A-Za-z_][A-Za-z0-9_]*\s*\]\s*\)",
        extensions: RB_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-003",
        trailer: TRAILER_MASS_ASSIGN,
        severity: Severity::High,
        help: HELP_RB_ORM,
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*\.create\s*\(\s*params\[\s*:[A-Za-z_][A-Za-z0-9_]*\s*\]\s*\)",
        extensions: RB_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-004",
        trailer: TRAILER_RAW_SQL_TEMPLATE,
        severity: Severity::Critical,
        help: HELP_RAW_SQL,
        pattern: r"\b(?:knex|db|sequelize)\.(?:raw|query)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-ORM-004",
        trailer: TRAILER_RAW_SQL_TEMPLATE,
        severity: Severity::Critical,
        help: HELP_RAW_SQL,
        pattern: r"\.\$queryRawUnsafe\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`",
        extensions: JS_EXTENSIONS,
    },
];

static PATTERNS: OnceLock<Result<Vec<CompiledPattern>, regex::Error>> = OnceLock::new();

fn compiled_patterns() -> Result<&'static [CompiledPattern], AnalyzerError> {
    let cached = PATTERNS.get_or_init(|| {
        PATTERN_SPECS
            .iter()
            .map(|spec| {
                Regex::new(spec.pattern).map(|regex| CompiledPattern {
                    code: spec.code,
                    trailer: spec.trailer,
                    severity: spec.severity,
                    help: spec.help,
                    regex,
                    extensions: spec.extensions,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    });
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(AnalyzerError::Failed {
            name: "orm",
            message: format!("failed to compile a builtin orm pattern: {e}"),
        }),
    }
}

fn trim_match(raw: &str) -> String {
    let trimmed = raw.trim_end_matches([',', ' ', '\t']);
    let trimmed = if let Some(stripped) = trimmed.strip_suffix(')') {
        stripped
    } else {
        trimmed
    };
    let mut out = trimmed.to_string();
    let open = out.matches('(').count();
    let close = out.matches(')').count();
    for _ in 0..open.saturating_sub(close) {
        out.push(')');
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
    use crate::crawler::{CrawlSummary, DiscoveredFile, FileKind};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir() -> Option<PathBuf> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rastray-orm-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        match std::fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn run_on(name: &str, body: &str) -> Vec<Finding> {
        let Some(dir) = tempdir() else {
            return Vec::new();
        };
        let path = dir.join(name);
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(body.as_bytes());
        }
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: path.clone(),
                kind: FileKind::Source,
                size: Some(body.len() as u64),
            }],
            skipped: 0,
            errors: vec![],
        };
        let result = OrmAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn mongoose_model_create_with_req_body_is_flagged() {
        let body = "const u = await User.create(req.body);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-001"));
    }

    #[test]
    fn sequelize_model_update_with_req_body_is_flagged() {
        let body = "await User.update(req.body, { where: { id } });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-001"));
    }

    #[test]
    fn prisma_create_with_data_req_body_is_flagged() {
        let body = "await prisma.user.create({ data: req.body });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-001"));
    }

    #[test]
    fn django_objects_create_kwargs_request_post_is_flagged() {
        let body = "user = User.objects.create(**request.POST)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-002"));
    }

    #[test]
    fn django_filter_kwargs_request_data_is_flagged() {
        let body = "qs = User.objects.filter(**request.data)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-002"));
    }

    #[test]
    fn rails_update_with_params_section_is_flagged() {
        let body = "@user.update(params[:user])";
        let findings = run_on("a.rb", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-003"));
    }

    #[test]
    fn knex_raw_with_template_literal_is_flagged_as_critical() {
        let body = "const rows = await knex.raw(`SELECT * FROM users WHERE id = ${id}`);";
        let findings = run_on("a.js", body);
        let f = findings.iter().find(|f| f.code == "RSTR-ORM-004");
        assert!(f.is_some());
        if let Some(found) = f {
            assert_eq!(found.severity, Severity::Critical);
        }
    }

    #[test]
    fn sequelize_query_with_template_literal_is_flagged() {
        let body = "await sequelize.query(`UPDATE users SET role = '${role}' WHERE id = ${id}`);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-004"));
    }

    #[test]
    fn prisma_query_raw_unsafe_template_literal_is_flagged() {
        let body = "await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-ORM-004"));
    }

    #[test]
    fn node_create_with_lodash_pick_is_not_flagged() {
        let body = "await User.create(_.pick(req.body, ['name', 'email']));";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "lodash.pick allow-list is the safe form: {findings:?}"
        );
    }

    #[test]
    fn django_create_with_explicit_kwargs_is_not_flagged() {
        let body = "user = User.objects.create(name=name, email=email)";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "explicit kwargs should not flag: {findings:?}"
        );
    }

    #[test]
    fn rails_update_with_strong_params_is_not_flagged() {
        let body = "@user.update(params.require(:user).permit(:name, :email))";
        let findings = run_on("a.rb", body);
        assert!(
            findings.is_empty(),
            "Strong Parameters are the safe form: {findings:?}"
        );
    }

    #[test]
    fn knex_with_parameter_binding_is_not_flagged() {
        let body = "await knex.raw('SELECT * FROM users WHERE id = ?', [id]);";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "parameter-binding form should not flag: {findings:?}"
        );
    }

    #[test]
    fn knex_raw_literal_template_without_interpolation_is_not_flagged() {
        let body = "await knex.raw(`SELECT * FROM users WHERE active = TRUE`);";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "template without ${{}} should not flag: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let body = "User.create(req.body)";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body = "await User.create(req.body);\nawait Post.create(req.body);";
        let findings = run_on("a.js", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("User.create(req.body)")));
        assert!(msgs.iter().any(|m| m.contains("Post.create(req.body)")));
    }

    #[test]
    fn help_text_includes_remediation_idiom() {
        let node_findings = run_on("a.js", "await User.create(req.body);");
        let node_help = node_findings
            .iter()
            .find(|f| f.code == "RSTR-ORM-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(node_help.contains("lodash.pick") || node_help.contains("allow-list"));

        let py_findings = run_on("a.py", "User.objects.create(**request.POST)");
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-ORM-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(py_help.contains("pydantic") || py_help.contains("ModelForm"));

        let rb_findings = run_on("a.rb", "@user.update(params[:user])");
        let rb_help = rb_findings
            .iter()
            .find(|f| f.code == "RSTR-ORM-003")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(rb_help.contains("Strong Parameters") || rb_help.contains("permit"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "User.create(req.body),";
        let out = trim_match(raw);
        assert_eq!(out, "User.create(req.body)");
    }
}
