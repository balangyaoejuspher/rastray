use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::{Confidence, Severity};
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct MemoryAnalyzer;

impl MemoryAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for MemoryAnalyzer {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl.files.iter().any(|f| {
            if f.kind != FileKind::Source {
                return false;
            }
            f.path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .is_some_and(|ext| C_EXTENSIONS.iter().any(|e| *e == ext))
        })
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
            if !C_EXTENSIONS.iter().any(|e| *e == ext) {
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
                    let snippet = trim_match(m.as_str());
                    let message = format!("`{snippet}` {}", pattern.trailer);
                    findings.push(
                        Finding::new(pattern.code, message, pattern.severity, Category::Security)
                            .with_help(pattern.help)
                            .with_location(location)
                            .with_confidence(pattern.confidence),
                    );
                }
            }
        }
        Ok(findings)
    }
}

const C_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "h", "hpp", "hh", "hxx"];

struct PatternSpec {
    code: &'static str,
    trailer: &'static str,
    severity: Severity,
    confidence: Confidence,
    help: &'static str,
    pattern: &'static str,
}

struct CompiledPattern {
    code: &'static str,
    trailer: &'static str,
    severity: Severity,
    confidence: Confidence,
    help: &'static str,
    regex: Regex,
}

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-MEM-001",
        trailer: "is a banned, unbounded buffer-overflow surface",
        severity: Severity::Critical,
        confidence: Confidence::High,
        help: "use the bounded variant: `strncpy` (size-limited) and pad-terminate, `strncat`, `snprintf`, or `fgets`. Better: use a tested string library (StringView, std::string, abseil's strings) that owns its bounds",
        pattern: r"\b(?:std::)?(?:strcpy|strcat|gets|sprintf|vsprintf)\s*\(",
    },
    PatternSpec {
        code: "RSTR-MEM-002",
        trailer: "uses an unbounded `%s` in a scanf-family format — the destination buffer can be overflowed by long input",
        severity: Severity::High,
        confidence: Confidence::High,
        help: "always specify a width: `%99s` for a 100-byte buffer, `%127s` for 128, etc. Or switch to `fgets` for line input. Note the width is one less than the destination size, leaving room for the null terminator",
        pattern: r#"\b(?:std::)?(?:scanf|fscanf|sscanf|vscanf|vfscanf|vsscanf)\s*\([^;]*"[^"]*%s"#,
    },
    PatternSpec {
        code: "RSTR-MEM-003",
        trailer: "uses `alloca` — allocations beyond the page guard crash the process; on attacker-controlled sizes this becomes a stack-pivot primitive",
        severity: Severity::High,
        confidence: Confidence::High,
        help: "replace with a heap allocation (`malloc` + `free` paired, or RAII-managed `std::vector` / `std::unique_ptr`). If a stack array is genuinely required, use a `constexpr` size with a compile-time bound check",
        pattern: r"\balloca\s*\(",
    },
    PatternSpec {
        code: "RSTR-MEM-004",
        trailer: "is a `memcpy`/`memmove` whose length comes from `strlen(...)` — almost always an off-by-one: `strlen` returns the count without the null terminator, so the destination loses its terminator",
        severity: Severity::Medium,
        confidence: Confidence::High,
        help: "either copy `strlen(src) + 1` to include the null byte, or use `strcpy` *with* a destination size check, or use `snprintf(dst, dst_size, \"%s\", src)` which always null-terminates",
        pattern: r"\b(?:memcpy|memmove)\s*\([^;]*\bstrlen\s*\([^)]+\)\s*\)",
    },
    PatternSpec {
        code: "RSTR-MEM-005",
        trailer: "uses raw `new` for heap allocation — ownership is implicit and a missed `delete` (or an exception between allocation and storage) leaks memory",
        severity: Severity::Medium,
        confidence: Confidence::Low,
        help: "prefer `std::make_unique<T>(args)` (or `std::make_shared<T>(args)` for shared ownership). The smart-pointer wrapper releases the allocation when it goes out of scope, even on exception, and makes ownership visible at every call site. Suppress with `--min-confidence high` if your codebase has audited raw-`new` patterns",
        pattern: r"\bnew\s+[a-zA-Z_][a-zA-Z0-9_:<>]*\s*[\(\{\[]",
    },
    PatternSpec {
        code: "RSTR-INJ-011",
        trailer: "passes a non-literal argument to a shell-spawning function — if any part of the argument is user-controlled, this is command injection",
        severity: Severity::Critical,
        confidence: Confidence::High,
        help: "for fixed commands, keep the string literal at the call site. For variable input, switch to `execve`/`execvp` with a fixed argv array (no shell, no metacharacter parsing). Reject input containing `;`, `|`, `&`, backticks, `$()`, `<`, `>` before passing it to any spawn function",
        pattern: r"\b(?:std::)?(?:system|popen|execlp?|execvp?|execve)\s*\(\s*[A-Za-z_][A-Za-z_0-9]",
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
                    confidence: spec.confidence,
                    help: spec.help,
                    regex,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    });
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(AnalyzerError::Failed {
            name: "memory",
            message: format!("failed to compile a builtin memory pattern: {e}"),
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

fn trim_match(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() > 80 {
        format!("{}...", &trimmed[..80])
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_or_skip() -> Option<&'static [CompiledPattern]> {
        compiled_patterns().ok()
    }

    fn regex_for(code: &str) -> Option<&'static Regex> {
        let p = compile_or_skip()?;
        p.iter().find(|c| c.code == code).map(|c| &c.regex)
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn mem_001_flags_strcpy_and_friends() {
        let re = match regex_for("RSTR-MEM-001") {
            Some(r) => r,
            None => return,
        };
        assert!(re.is_match("strcpy(dst, src);"));
        assert!(re.is_match("strcat(buf, more);"));
        assert!(re.is_match("gets(buf);"));
        assert!(re.is_match("sprintf(out, \"%s\", x);"));
        assert!(re.is_match("vsprintf(out, fmt, ap);"));
        assert!(re.is_match("std::strcpy(dst, src);"));
        assert!(re.is_match("std::sprintf(out, \"%d\", n);"));
        assert!(!re.is_match("strncpy(dst, src, 16);"));
        assert!(!re.is_match("snprintf(out, sizeof(out), \"%s\", x);"));
        assert!(!re.is_match("fgets(buf, sizeof(buf), stdin);"));
    }

    #[test]
    fn mem_002_flags_unbounded_scanf_percent_s() {
        let re = match regex_for("RSTR-MEM-002") {
            Some(r) => r,
            None => return,
        };
        assert!(re.is_match("scanf(\"%s\", buf);"));
        assert!(re.is_match("sscanf(input, \"%d %s\", &n, name);"));
        assert!(re.is_match("fscanf(fp, \"%s\", line);"));
        assert!(re.is_match("std::scanf(\"%s\", buf);"));
        assert!(!re.is_match("printf(\"%s\\n\", x);"));
        assert!(!re.is_match("scanf(\"%d\", &n);"));
    }

    #[test]
    fn mem_003_flags_alloca() {
        let re = match regex_for("RSTR-MEM-003") {
            Some(r) => r,
            None => return,
        };
        assert!(re.is_match("char *p = alloca(size);"));
        assert!(re.is_match("alloca(n * 4);"));
        assert!(!re.is_match("malloc(n);"));
        assert!(!re.is_match("// alloca is risky"));
    }

    #[test]
    fn mem_004_flags_memcpy_with_strlen() {
        let re = match regex_for("RSTR-MEM-004") {
            Some(r) => r,
            None => return,
        };
        assert!(re.is_match("memcpy(dst, src, strlen(src));"));
        assert!(re.is_match("memmove(out, in, strlen(in));"));
        assert!(!re.is_match("memcpy(dst, src, strlen(src) + 1);"));
        assert!(!re.is_match("memcpy(dst, src, sizeof(buf));"));
    }

    #[test]
    fn inj_011_flags_system_with_identifier_argument() {
        let re = match regex_for("RSTR-INJ-011") {
            Some(r) => r,
            None => return,
        };
        assert!(re.is_match("system(buf);"));
        assert!(re.is_match("system(cmd);"));
        assert!(re.is_match("popen(query, \"r\");"));
        assert!(re.is_match("execlp(prog, prog, NULL);"));
        assert!(re.is_match("std::system(buf);"));
        assert!(!re.is_match("system(\"ls -la\");"));
        assert!(!re.is_match("popen(\"/bin/cat /etc/hostname\", \"r\");"));
    }

    #[test]
    fn mem_005_flags_raw_new_with_typename() {
        let re = match regex_for("RSTR-MEM-005") {
            Some(r) => r,
            None => return,
        };
        assert!(re.is_match("auto p = new Widget(args);"));
        assert!(re.is_match("return new Foo{};"));
        assert!(re.is_match("new std::string(\"abc\");"));
        assert!(re.is_match("new Buffer[size];"));
        assert!(!re.is_match("auto p = std::make_unique<Widget>(args);"));
        assert!(!re.is_match("auto p = std::make_shared<Foo>();"));
        assert!(!re.is_match("// see new feature flag"));
    }

    #[test]
    fn mem_005_uses_low_confidence() {
        let p = compile_or_skip().unwrap_or(&[]);
        let entry = match p.iter().find(|c| c.code == "RSTR-MEM-005") {
            Some(e) => e,
            None => return,
        };
        assert_eq!(entry.confidence, Confidence::Low);
    }

    #[test]
    fn trim_match_caps_long_snippets() {
        let long = "a".repeat(120);
        let trimmed = trim_match(&long);
        assert!(trimmed.ends_with("..."));
        assert!(trimmed.len() <= 83);
    }

    fn crawl_with(files: Vec<(std::path::PathBuf, FileKind)>) -> CrawlSummary {
        CrawlSummary {
            files: files
                .into_iter()
                .map(|(p, k)| crate::crawler::DiscoveredFile {
                    path: p,
                    kind: k,
                    size: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn wants_returns_false_when_no_c_or_cpp_source() {
        let crawl = crawl_with(vec![
            ("src/lib.rs".into(), FileKind::Source),
            ("package.json".into(), FileKind::Manifest),
        ]);
        assert!(!MemoryAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_for_c_or_cpp_source() {
        let crawl = crawl_with(vec![
            ("src/lib.rs".into(), FileKind::Source),
            ("native/buf.cpp".into(), FileKind::Source),
        ]);
        assert!(MemoryAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_false_when_c_extension_is_not_source_kind() {
        let crawl = crawl_with(vec![("docs/example.c".into(), FileKind::Other)]);
        assert!(!MemoryAnalyzer::new().wants(&crawl));
    }
}
