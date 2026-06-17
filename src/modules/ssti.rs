use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct SstiAnalyzer;

impl SstiAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for SstiAnalyzer {
    fn name(&self) -> &'static str {
        "ssti"
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

const TRAILER: &str =
    "compiles a template from request input — server-side template injection risk (frequently escalates to remote code execution via template-engine sandbox escape)";

const HELP_PY: &str = "never pass request input to `Template(...)`, `Environment.from_string(...)`, or `render_template_string(...)`; render a static template file with `render_template('name.html', value=user_input)` so the user value lands inside an auto-escaped slot, not in the template source itself";

const HELP_JS: &str = "never pass request input as the template source to `pug.render` / `pug.compile` / `handlebars.compile` / `ejs.render` / `nunjucks.renderString`; load templates from disk by name and pass user input as data, not as the template body";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-SSTI-001",
        trailer: TRAILER,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r"\b(?:jinja2\.)?Template\s*\(\s*request\.(?:args|form|values|cookies|headers|GET|POST)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))\s*\)",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSTI-001",
        trailer: TRAILER,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r"\brender_template_string\s*\(\s*request\.(?:args|form|values|cookies|headers|GET|POST)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSTI-001",
        trailer: TRAILER,
        severity: Severity::High,
        help: HELP_PY,
        pattern: r"\b[A-Za-z_][A-Za-z0-9_]*\.from_string\s*\(\s*request\.(?:args|form|values|cookies|headers|GET|POST)(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^\]]+\]|\.get\s*\([^)]+\))",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-SSTI-002",
        trailer: TRAILER,
        severity: Severity::High,
        help: HELP_JS,
        pattern: r"\b(?:pug|handlebars|Handlebars|ejs|nunjucks|Mustache|mustache)\.(?:render|compile|renderString)\s*\(\s*req\.(?:body|query|params|cookies|headers)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*[,)]",
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
            name: "ssti",
            message: format!("failed to compile a builtin ssti pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-ssti-test-{}-{}", std::process::id(), n));
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
        let result = SstiAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn jinja2_template_with_request_args_get_is_flagged() {
        let body = "from jinja2 import Template\n@app.route('/x')\ndef x():\n    return Template(request.args.get('name')).render()";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-SSTI-001"));
    }

    #[test]
    fn render_template_string_with_request_form_is_flagged() {
        let body = "from flask import request, render_template_string\n@app.route('/x', methods=['POST'])\ndef x():\n    return render_template_string(request.form['template'])";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-SSTI-001"));
    }

    #[test]
    fn jinja_environment_from_string_is_flagged() {
        let body = "env = jinja2.Environment()\nt = env.from_string(request.args.get('t'))";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-SSTI-001"));
    }

    #[test]
    fn pug_render_with_req_body_is_flagged() {
        let body = "app.post('/r', (req, res) => { res.send(pug.render(req.body.tpl)); });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-SSTI-002"));
    }

    #[test]
    fn handlebars_compile_with_req_query_is_flagged() {
        let body = "const tpl = Handlebars.compile(req.query.src);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-SSTI-002"));
    }

    #[test]
    fn ejs_render_with_req_body_is_flagged() {
        let body = "const html = ejs.render(req.body.template, data);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-SSTI-002"));
    }

    #[test]
    fn nunjucks_renderstring_with_req_params_is_flagged() {
        let body = "const out = nunjucks.renderString(req.params.t, {});";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-SSTI-002"));
    }

    #[test]
    fn static_template_file_render_is_not_flagged() {
        let body = "from flask import render_template\n@app.route('/x')\ndef x():\n    return render_template('home.html', name=request.args.get('name'))";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "render_template (not render_template_string) should not flag: {findings:?}"
        );
    }

    #[test]
    fn literal_template_string_is_not_flagged() {
        let body = "const tpl = Handlebars.compile('<h1>{{name}}</h1>');";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "literal template source should not flag: {findings:?}"
        );
    }

    #[test]
    fn pug_render_with_named_file_path_is_not_flagged() {
        let body = "const html = pug.renderFile('views/home.pug', { name: req.body.name });";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "renderFile passes data through, not template source: {findings:?}"
        );
    }

    #[test]
    fn intermediate_variable_is_not_flagged() {
        let body = "const src = req.body.tpl; const html = pug.render(src);";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "indirect flow is taint analysis territory, not regex: {findings:?}"
        );
    }

    #[test]
    fn non_py_extension_is_skipped_for_py_pattern() {
        let body = "Template(request.args.get('t'))";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body = "pug.render(req.body.tpl);\nHandlebars.compile(req.query.src);";
        let findings = run_on("a.js", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("pug.render(req.body.tpl)")));
        assert!(msgs
            .iter()
            .any(|m| m.contains("Handlebars.compile(req.query.src)")));
        let unique: std::collections::HashSet<&str> = msgs.iter().copied().collect();
        assert_eq!(
            unique.len(),
            msgs.len(),
            "each finding should have a distinct message: {msgs:?}"
        );
    }

    #[test]
    fn help_text_includes_remediation_idiom_for_language() {
        let py_findings = run_on(
            "a.py",
            "from jinja2 import Template\nt = Template(request.args.get('t'))",
        );
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-SSTI-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(py_help.contains("render_template") || py_help.contains("auto-escaped"));

        let js_findings = run_on("a.js", "pug.render(req.body.tpl);");
        let js_help = js_findings
            .iter()
            .find(|f| f.code == "RSTR-SSTI-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(js_help.contains("templates from disk") || js_help.contains("template body"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "pug.render(req.body.tpl,";
        let out = trim_match(raw);
        assert_eq!(out, "pug.render(req.body.tpl)");
    }
}
