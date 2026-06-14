use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct InjectionAnalyzer;

impl InjectionAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for InjectionAnalyzer {
    fn name(&self) -> &'static str {
        "injection"
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

const JS_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PY_EXTENSIONS: &[&str] = &["py"];
const GO_EXTENSIONS: &[&str] = &["go"];
const PHP_EXTENSIONS: &[&str] = &["php"];

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-INJ-001",
        message: "SQL query built with an f-string; high risk of SQL injection",
        severity: Severity::High,
        help: "use parameterized queries (e.g. cursor.execute(query, params)) instead",
        pattern: r#"(?i)\b(execute|executemany|raw)\s*\(\s*f["']"#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-001",
        message: "SQL query built with .format(); high risk of SQL injection",
        severity: Severity::High,
        help: "use parameterized queries (cursor.execute(query, params)) instead",
        pattern: r#"(?i)\b(execute|executemany|raw)\s*\(\s*["'][^"']*\{[^}]*\}[^"']*["']\s*\.\s*format\s*\("#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-001",
        message: "SQL query built with a template literal; risk of SQL injection",
        severity: Severity::High,
        help: "use a parameterized query API (e.g. ?-placeholders + parameters array)",
        pattern: r"(?i)\b(query|execute|raw)\s*\(\s*`[^`]*\$\{",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-002",
        message: "subprocess called with shell=True; risk of shell injection if input is untrusted",
        severity: Severity::High,
        help: "avoid shell=True; pass a list of arguments (e.g. ['ls', path]) so the shell never parses them",
        pattern: r"(?i)\b(subprocess\.(call|run|Popen|check_call|check_output)|os\.popen)\s*\([^)]*shell\s*=\s*True",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-002",
        message: "os.system() executes via the shell; risk of shell injection",
        severity: Severity::High,
        help: "use subprocess.run([...]) without shell=True instead",
        pattern: r#"\bos\.system\s*\(\s*f?["']"#,
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-003",
        message: "eval() can execute arbitrary code; never call on user-influenced input",
        severity: Severity::Critical,
        help: "remove eval; if you need to parse data, use json.loads or a proper parser",
        pattern: r"\beval\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-003",
        message: "exec() can execute arbitrary Python; never call on user-influenced input",
        severity: Severity::Critical,
        help: "remove exec; refactor to avoid dynamic code execution",
        pattern: r"\bexec\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-003",
        message: "eval() executes arbitrary JS; never call on user-influenced input",
        severity: Severity::Critical,
        help: "remove eval; if parsing JSON use JSON.parse, otherwise refactor",
        pattern: r"\beval\s*\(",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-003",
        message: "new Function() compiles arbitrary JS at runtime; risk of code injection",
        severity: Severity::High,
        help: "avoid runtime code generation; refactor to use first-class functions or a parser",
        pattern: r"\bnew\s+Function\s*\(",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-003",
        message: "PHP eval() executes arbitrary code; never call on user-influenced input",
        severity: Severity::Critical,
        help: "remove eval; refactor to avoid dynamic code execution",
        pattern: r"\beval\s*\(",
        extensions: PHP_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-004",
        message: "child_process.exec with template literal; risk of shell injection",
        severity: Severity::High,
        help: "use execFile([...]) or spawn(cmd, [...]) with an arg array instead",
        pattern: r"\b(exec|execSync|execFileSync)\s*\(\s*`[^`]*\$\{",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-004",
        message: "child_process.exec with string concatenation; risk of shell injection",
        severity: Severity::High,
        help: "use execFile([...]) or spawn(cmd, [...]) with an arg array instead",
        pattern: r#"\b(exec|execSync)\s*\(\s*["'][^"']*["']\s*\+\s*\w"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-005",
        message: "exec.Command with sh -c is shell-interpreted; risk of shell injection",
        severity: Severity::High,
        help: "drop the shell wrapper; call exec.Command(cmd, arg1, arg2, ...) directly",
        pattern: r#"exec\.Command\s*\(\s*"(sh|bash|cmd)"\s*,\s*"-c""#,
        extensions: GO_EXTENSIONS,
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
            name: "injection",
            message: format!("failed to compile a builtin injection pattern: {e}"),
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
        assert!(result.is_ok());
    }

    #[test]
    fn sql_fstring_python_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-001" && p.extensions.contains(&"py"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match(r#"cursor.execute(f"SELECT * FROM t WHERE id = {uid}")"#));
        assert!(re.is_match(r#"cur.executemany(f'INSERT INTO t VALUES ({val})')"#));
        assert!(!re.is_match(r#"cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))"#));
    }

    #[test]
    fn shell_true_python_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-002" && p.extensions.contains(&"py"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("subprocess.run(cmd, shell=True)"));
        assert!(re.is_match("subprocess.Popen(args, shell = True)"));
        assert!(re.is_match("subprocess.call(c, capture_output=True, shell=True)"));
        assert!(!re.is_match("subprocess.run(['ls', '-la'])"));
    }

    #[test]
    fn eval_python_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-003" && p.extensions.contains(&"py"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("result = eval(user_input)"));
        assert!(re.is_match("eval( expr )"));
    }

    #[test]
    fn child_process_template_literal_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-004" && p.extensions.contains(&"js"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("exec(`git clone ${repoUrl}`)"));
        assert!(re.is_match("execSync(`ls ${path}`)"));
        assert!(!re.is_match("execFile('git', ['clone', repoUrl])"));
    }

    #[test]
    fn go_sh_dash_c_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-005")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match(r#"exec.Command("sh", "-c", userCmd)"#));
        assert!(re.is_match(r#"exec.Command("bash", "-c", c)"#));
        assert!(!re.is_match(r#"exec.Command("git", "clone", url)"#));
    }
}
