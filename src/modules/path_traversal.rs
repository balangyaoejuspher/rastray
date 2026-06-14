use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct PathTraversalAnalyzer;

impl PathTraversalAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for PathTraversalAnalyzer {
    fn name(&self) -> &'static str {
        "path-traversal"
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
        }
        Ok(findings)
    }
}

struct PatternSpec {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
    extensions: &'static [&'static str],
}

struct CompiledPattern {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
    extensions: &'static [&'static str],
}

const PY_EXTENSIONS: &[&str] = &["py"];
const JS_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const JAVA_EXTENSIONS: &[&str] = &["java", "kt", "kts"];

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-PTH-001",
        message: "Flask send_file with user-controlled input; risk of path traversal",
        severity: Severity::High,
        help: "use send_from_directory(safe_dir, filename) with werkzeug.utils.secure_filename(filename)",
        pattern: r"\bsend_file\s*\(\s*(request\.|flask\.request\.)",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-PTH-002",
        message: "Express res.sendFile with user-controlled input; risk of path traversal",
        severity: Severity::High,
        help: "validate against path.resolve(safeBase, file).startsWith(safeBase), or use express.static",
        pattern: r"\bres\.sendFile\s*\(\s*(req\.params|req\.query|req\.body)",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-PTH-002",
        message: "fs.readFile/writeFile with user-controlled input; risk of path traversal",
        severity: Severity::High,
        help: "validate the resolved path against an allow-list directory before opening",
        pattern: r"\bfs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream)\s*\(\s*(req\.params|req\.query|req\.body)",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-PTH-003",
        message: "Java File constructor with request parameter; risk of path traversal",
        severity: Severity::High,
        help: "canonicalize the path and verify it stays inside the intended base directory",
        pattern: r"\bnew\s+File\s*\(\s*[^)]*(request\.getParameter|request\.getQueryString)",
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-PTH-004",
        message: "literal '../../' in a string; review whether the path is constructed safely",
        severity: Severity::Low,
        help: "if the traversal is intentional and safe, suppress this finding; otherwise refactor to an allow-listed path",
        pattern: r"\.\./\.\./",
        extensions: &[
            "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "go", "rs", "java", "kt", "rb", "php",
        ],
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
                    message: spec.message,
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
            name: "path-traversal",
            message: format!("failed to compile a builtin path-traversal pattern: {e}"),
        }),
    }
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

    #[test]
    fn compiled_patterns_compile_cleanly() {
        let result = compiled_patterns();
        if let Err(e) = &result {
            eprintln!("pattern compile error: {e:?}");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn flask_send_file_with_request_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-PTH-001")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("return send_file(request.args.get('file'))"));
        assert!(!re.is_match("return send_file('reports/safe.pdf')"));
    }

    #[test]
    fn express_send_file_with_req_params_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-PTH-002" && p.message.contains("sendFile"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("res.sendFile(req.params.file)"));
        assert!(re.is_match("res.sendFile(req.query.name)"));
        assert!(!re.is_match("res.sendFile(path.join(__dirname, 'safe.html'))"));
    }

    #[test]
    fn fs_with_req_input_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-PTH-002" && p.message.contains("readFile"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("fs.readFile(req.params.name, cb)"));
        assert!(re.is_match("fs.readFileSync(req.query.filename)"));
        assert!(!re.is_match("fs.readFile('./data.txt', cb)"));
    }

    #[test]
    fn literal_double_traversal_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-PTH-004")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match(r#"path = "../../etc/passwd""#));
        assert!(!re.is_match(r#"path = "./subdir/file""#));
    }
}
