use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct NosqliAnalyzer;

impl NosqliAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for NosqliAnalyzer {
    fn name(&self) -> &'static str {
        "nosqli"
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

const TRAILER_OBJECT_INJECTION: &str =
    "passes a request-body object directly into a MongoDB query — operator injection risk (an attacker submitting `{\"$gt\": \"\"}` instead of a string bypasses the filter and returns every document)";

const TRAILER_WHERE: &str =
    "uses `$where` with request input — server-side JavaScript injection in MongoDB (attacker can run arbitrary JS in the database process)";

const HELP_JS: &str = "coerce every value to its expected primitive type (`String(req.body.user)`, `Number(req.body.id)`) before placing it in a filter, or validate with a schema (`zod` / `joi` / `ajv`) so request bodies cannot smuggle `$gt` / `$ne` / `$regex` operators; never spread `req.body` / `req.query` directly into a query object";

const HELP_PY: &str = "coerce every value to its expected primitive type (`str(request.json['user'])`) or validate with a schema (`pydantic` / `marshmallow`) so request bodies cannot smuggle `$gt` / `$ne` / `$regex` operators; never spread the parsed JSON body into the filter dict";

const HELP_WHERE: &str = "never use `$where` (or `mapReduce` / `accumulator`) with values derived from request input; refactor to a structured filter expression — `$where` evaluates JavaScript in the database process and is a remote-code-execution sink";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-NOSQLI-001",
        trailer: TRAILER_OBJECT_INJECTION,
        severity: Severity::High,
        help: HELP_JS,
        pattern: r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|count|countDocuments)\s*\(\s*\{[^{}$]*?:\s*req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NOSQLI-002",
        trailer: TRAILER_WHERE,
        severity: Severity::Critical,
        help: HELP_WHERE,
        pattern: r#"\$where\s*['"]?\s*:\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*['"]\s*\+\s*req\.|req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+)"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NOSQLI-003",
        trailer: TRAILER_OBJECT_INJECTION,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r"\.(?:find|find_one|find_one_and_update|find_one_and_delete|find_one_and_replace|update_one|update_many|delete_one|delete_many|count_documents)\s*\(\s*\{[^{}$]*?:\s*request\.(?:json|args|form|values|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))",
        extensions: PY_EXTENSIONS,
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
            name: "nosqli",
            message: format!("failed to compile a builtin nosqli pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-nosqli-test-{}-{}", std::process::id(), n));
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
            fingerprint: Default::default(),
        };
        let result = NosqliAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn mongo_find_with_req_body_value_is_flagged() {
        let body = "app.post('/u', (req, res) => { users.find({ user: req.body.user }, cb); });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-001"));
    }

    #[test]
    fn mongo_findone_with_req_query_value_is_flagged() {
        let body = "users.findOne({ email: req.query.email });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-001"));
    }

    #[test]
    fn mongo_updateone_with_req_body_value_is_flagged() {
        let body = "users.updateOne({ _id: req.body.id }, { $set: { name: 'x' } });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-001"));
    }

    #[test]
    fn mongo_deleteone_with_req_params_value_is_flagged() {
        let body = "users.deleteOne({ user: req.params.user });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-001"));
    }

    #[test]
    fn mongo_where_with_template_literal_is_flagged() {
        let body = "users.find({ $where: `this.user == '${req.body.user}'` });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-002"));
    }

    #[test]
    fn mongo_where_with_direct_req_value_is_flagged() {
        let body = "users.find({ $where: req.body.predicate });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-002"));
    }

    #[test]
    fn pymongo_find_with_request_json_value_is_flagged() {
        let body = "users.find({\"user\": request.json['user']})";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-003"));
    }

    #[test]
    fn pymongo_find_one_with_request_args_get_is_flagged() {
        let body = "u = users.find_one({\"email\": request.args.get('email')})";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-NOSQLI-003"));
    }

    #[test]
    fn mongo_find_with_coerced_string_is_not_flagged() {
        let body = "users.find({ user: String(req.body.user) });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "String(...) coercion is the documented safe pattern; should not flag: {findings:?}"
        );
    }

    #[test]
    fn mongo_find_with_literal_filter_is_not_flagged() {
        let body = "users.find({ user: 'alice' });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "literal filter should not flag: {findings:?}"
        );
    }

    #[test]
    fn pymongo_find_with_str_coercion_is_not_flagged() {
        let body = "users.find({\"user\": str(request.json['user'])})";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "str(...) coercion is the documented safe pattern; should not flag: {findings:?}"
        );
    }

    #[test]
    fn intermediate_variable_is_not_flagged() {
        let body = "const u = req.body.user; users.find({ user: u });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "indirect flow is taint analysis territory, not regex: {findings:?}"
        );
    }

    #[test]
    fn non_js_extension_is_skipped_for_js_pattern() {
        let body = "users.find({ user: req.body.user });";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn where_rule_severity_is_critical() {
        let body = "users.find({ $where: req.body.predicate });";
        let findings = run_on("a.js", body);
        let where_finding = findings.iter().find(|f| f.code == "RSTR-NOSQLI-002");
        assert!(
            where_finding.is_some(),
            "where rule should fire, got {findings:?}"
        );
        if let Some(f) = where_finding {
            assert_eq!(f.severity, Severity::Critical);
        }
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body =
            "users.find({ user: req.body.user });\nusers.findOne({ email: req.query.email });";
        let findings = run_on("a.js", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("user: req.body.user")));
        assert!(msgs.iter().any(|m| m.contains("email: req.query.email")));
        let unique: std::collections::HashSet<&str> = msgs.iter().copied().collect();
        assert_eq!(
            unique.len(),
            msgs.len(),
            "each finding should have a distinct message: {msgs:?}"
        );
    }

    #[test]
    fn help_text_includes_remediation_idiom_for_language() {
        let js_findings = run_on("a.js", "users.find({ user: req.body.user });");
        let js_help = js_findings
            .iter()
            .find(|f| f.code == "RSTR-NOSQLI-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(js_help.contains("String(") || js_help.contains("zod"));

        let py_findings = run_on("a.py", "users.find({\"user\": request.json['user']})");
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-NOSQLI-003")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(py_help.contains("pydantic") || py_help.contains("str("));

        let where_findings = run_on("a.js", "users.find({ $where: req.body.p });");
        let where_help = where_findings
            .iter()
            .find(|f| f.code == "RSTR-NOSQLI-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(where_help.contains("$where") && where_help.contains("remote-code-execution"));
    }

    #[test]
    fn where_rule_does_not_double_fire_as_object_injection() {
        let body = "users.find({ $where: req.body.predicate });";
        let findings = run_on("a.js", body);
        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        assert!(
            !codes.contains(&"RSTR-NOSQLI-001"),
            "RSTR-NOSQLI-002 ($where) should not also fire as RSTR-NOSQLI-001: {codes:?}"
        );
        assert!(codes.contains(&"RSTR-NOSQLI-002"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "users.find({ user: req.body.user },";
        let out = trim_match(raw);
        assert_eq!(out, "users.find({ user: req.body.user })");
    }
}
