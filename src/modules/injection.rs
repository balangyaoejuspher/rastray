use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::fingerprint::Framework;
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
        let frameworks = &crawl.fingerprint.frameworks;
        let rails_active = frameworks.contains(&Framework::Rails);
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
                if !rails_active && RAILS_GATED_CODES.contains(&pattern.code) {
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
const RB_EXTENSIONS: &[&str] = &["rb"];
const JAVA_EXTENSIONS: &[&str] = &["java", "kt", "kts"];

const RAILS_GATED_CODES: &[&str] = &["RSTR-INJ-008", "RSTR-INJ-009", "RSTR-INJ-010"];

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
    PatternSpec {
        code: "RSTR-INJ-006",
        message: "SQL query built by interpolating a request superglobal; SQL-injection risk",
        severity: Severity::Critical,
        help: "use a prepared statement: mysqli_prepare($db, '... WHERE id = ?') + bind_param('i', $id), or PDO with named placeholders",
        pattern: r#"(?i)\b(?:mysqli_query|mysql_query|pg_query|pg_query_params|sqlite_query|sqlsrv_query|odbc_exec)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\b"#,
        extensions: PHP_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-006",
        message: "SQL query passed to ->query()/->exec() with a request superglobal; SQL-injection risk",
        severity: Severity::Critical,
        help: "use ->prepare() with placeholders and ->execute([...]) instead of ->query() with concatenated input",
        pattern: r#"(?i)->\s*(?:query|exec|unbufferedQuery)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\b"#,
        extensions: PHP_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-007",
        message: "PHP command exec on request input; command-injection risk",
        severity: Severity::Critical,
        help: "validate input against an allow-list and pass arguments via escapeshellarg(...); better yet, use a dedicated library instead of shelling out",
        pattern: r#"(?i)\b(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\b"#,
        extensions: PHP_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-007",
        message: "PHP backtick operator on request input; command-injection risk",
        severity: Severity::Critical,
        help: "remove backticks (`...`) and refactor to a vetted API; if you must shell out, use escapeshellarg(...)",
        pattern: r#"`[^`]*\$_(GET|POST|REQUEST|COOKIE)\b[^`]*`"#,
        extensions: PHP_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-008",
        message: "Rails ActiveRecord .where with string interpolation of params; SQL-injection risk",
        severity: Severity::Critical,
        help: "use parameterised form: Model.where('id = ?', params[:id]) or hash form Model.where(id: params[:id]) which both delegate to prepared statements",
        pattern: r#"\.(?:where|find_by_sql|exists\?|update_all|delete_all|joins|having|order|group|select|from)\s*\(\s*"[^"]*#\{[^}]*params\b"#,
        extensions: RB_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-009",
        message: "Rails .constantize / .classify / .safe_constantize on request params; arbitrary class instantiation risk",
        severity: Severity::High,
        help: "validate against an allow-list of expected class names (e.g. {'user' => User, 'admin' => AdminUser}.fetch(params[:kind])) before resolving; constantize on attacker input has historically led to RCE via gadget chains",
        pattern: r"\bparams\[\s*:?[A-Za-z_][A-Za-z0-9_]*\s*\]\s*\.\s*(?:constantize|classify|safe_constantize)\b",
        extensions: RB_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-010",
        message: "Rails render with inline:/text:/inline_template: containing params; server-side template injection risk",
        severity: Severity::Critical,
        help: "render fixed templates and pass user input as locals: render :show, locals: { name: params[:name] }; never let user input become the template source",
        pattern: r#"\brender\s*\(?\s*(?:inline|text|inline_template)\s*:\s*[^,)]*#\{[^}]*params\b"#,
        extensions: RB_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-012",
        message: "Java Runtime.exec / ProcessBuilder built from a concatenated string; command-injection risk if any segment is user-controlled",
        severity: Severity::Critical,
        help: "pass arguments as a String[] array (no shell), e.g. new ProcessBuilder(\"git\", \"log\", branch). Never let request input join a shell command line via `+`. If you absolutely must use a shell, allow-list the input first",
        pattern: r#"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*"[^"]*"\s*\+\s*[A-Za-z_]"#,
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-INJ-012",
        message: "Java new ProcessBuilder built from a concatenated string; command-injection risk if any segment is user-controlled",
        severity: Severity::Critical,
        help: "split the command into a String[] array: new ProcessBuilder(\"cmd\", arg1, arg2). The first form (single concatenated string) goes through the shell",
        pattern: r#"\bnew\s+ProcessBuilder\s*\(\s*"[^"]*"\s*\+\s*[A-Za-z_]"#,
        extensions: JAVA_EXTENSIONS,
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

    #[test]
    fn php_sqli_mysqli_query_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let regexes: Vec<_> = patterns
            .iter()
            .filter(|p| p.code == "RSTR-INJ-006" && p.extensions.contains(&"php"))
            .map(|p| &p.regex)
            .collect();
        assert!(!regexes.is_empty());
        assert!(regexes.iter().any(|re| re
            .is_match(r#"mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET['id'])"#)));
        assert!(regexes.iter().any(|re| re.is_match(
            r#"$pdo->query("SELECT * FROM users WHERE name = '" . $_POST['name'] . "'")"#
        )));
        assert!(regexes
            .iter()
            .any(|re| re
                .is_match(r#"pg_query($conn, "SELECT * FROM t WHERE id = " . $_REQUEST['id'])"#)));
        assert!(!regexes
            .iter()
            .any(|re| re.is_match(r#"mysqli_query($db, "SELECT * FROM users WHERE id = 42")"#)));
    }

    #[test]
    fn php_cmd_exec_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let regexes: Vec<_> = patterns
            .iter()
            .filter(|p| p.code == "RSTR-INJ-007" && p.extensions.contains(&"php"))
            .map(|p| &p.regex)
            .collect();
        assert!(!regexes.is_empty());
        assert!(regexes
            .iter()
            .any(|re| re.is_match(r#"exec("ping -c 4 " . $_GET['host'])"#)));
        assert!(regexes
            .iter()
            .any(|re| re.is_match(r#"system("ls " . $_POST['dir'])"#)));
        assert!(regexes.iter().any(
            |re| re.is_match(r#"shell_exec("grep " . $_REQUEST['pat'] . " /var/log/syslog")"#)
        ));
        assert!(regexes
            .iter()
            .any(|re| re.is_match(r#"$out = `ls -la $_GET[d]`;"#)));
        assert!(!regexes
            .iter()
            .any(|re| re.is_match(r#"exec("/usr/bin/uptime")"#)));
    }

    #[test]
    fn rails_where_interpolation_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-008")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match(r#"User.where("id = '#{params[:user][:id]}'")"#));
        assert!(re.is_match(r#"User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")"#));
        assert!(!re.is_match(r#"User.where(id: params[:id])"#));
        assert!(!re.is_match(r#"User.where("id = ?", params[:id])"#));
    }

    #[test]
    fn rails_constantize_on_params_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-009")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match(r#"model = params[:class].constantize"#));
        assert!(re.is_match(r#"klass = params[:kind].safe_constantize"#));
        assert!(re.is_match(r#"model = params[:class].classify"#));
        assert!(!re.is_match(r#"klass = ALLOWED_CLASSES.fetch(params[:kind])"#));
    }

    #[test]
    fn rails_render_inline_with_params_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-INJ-010")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match(r#"render inline: "<h1>Hi #{params[:name]}</h1>""#));
        assert!(re.is_match(r#"render(text: "Hello #{params[:name]}")"#));
        assert!(!re.is_match(r#"render :show, locals: { name: params[:name] }"#));
    }

    #[test]
    fn java_runtime_exec_with_concat_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let res: Vec<_> = patterns
            .iter()
            .filter(|p| p.code == "RSTR-INJ-012")
            .map(|p| &p.regex)
            .collect();
        if res.is_empty() {
            return;
        }
        let any = |s: &str| res.iter().any(|r| r.is_match(s));
        assert!(any(r#"Runtime.getRuntime().exec("ping " + host);"#));
        assert!(any(r#"new ProcessBuilder("git log " + branch);"#));
        assert!(!any(
            r#"Runtime.getRuntime().exec(new String[] {"ping", host});"#
        ));
        assert!(!any(r#"new ProcessBuilder("git", "log", branch);"#));
    }

    fn run_analyze_with_framework(
        name: &str,
        body: &str,
        framework: Option<Framework>,
    ) -> Vec<Finding> {
        use crate::crawler::DiscoveredFile;
        let dir = std::env::temp_dir().join(format!(
            "rastray-inj-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        let _ = std::fs::write(&path, body);
        let mut fingerprint = crate::fingerprint::ProjectFingerprint::default();
        if let Some(fw) = framework {
            fingerprint.frameworks.insert(fw);
        }
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: path.clone(),
                kind: FileKind::Source,
                size: Some(body.len() as u64),
            }],
            skipped: 0,
            errors: vec![],
            fingerprint,
        };
        let result = InjectionAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn rails_inj_rules_fire_when_rails_fingerprint_present() {
        let body = r#"User.where("id = '#{params[:user][:id]}'")"#;
        let findings = run_analyze_with_framework("a.rb", body, Some(Framework::Rails));
        assert!(
            findings.iter().any(|f| f.code == "RSTR-INJ-008"),
            "expected RSTR-INJ-008 with Rails fingerprint, got {findings:?}"
        );
    }

    #[test]
    fn rails_inj_rules_silenced_without_rails_fingerprint() {
        let body = r#"User.where("id = '#{params[:user][:id]}'")"#;
        let findings = run_analyze_with_framework("a.rb", body, None);
        assert!(
            !findings.iter().any(|f| f.code == "RSTR-INJ-008"),
            "expected RSTR-INJ-008 silenced without Rails fingerprint, got {findings:?}"
        );
    }

    #[test]
    fn rails_inj_009_silenced_without_rails_fingerprint() {
        let body = r#"model = params[:class].constantize"#;
        let findings = run_analyze_with_framework("a.rb", body, None);
        assert!(
            !findings.iter().any(|f| f.code == "RSTR-INJ-009"),
            "expected RSTR-INJ-009 silenced without Rails fingerprint, got {findings:?}"
        );
    }

    #[test]
    fn non_rails_inj_rules_unaffected_by_rails_gate() {
        let body = r#"const result = await db.query(`SELECT * FROM x WHERE id = ${id}`);"#;
        let findings = run_analyze_with_framework("a.js", body, None);
        assert!(
            findings.iter().any(|f| f.code == "RSTR-INJ-001"),
            "expected RSTR-INJ-001 to fire regardless of fingerprint, got {findings:?}"
        );
    }
}
