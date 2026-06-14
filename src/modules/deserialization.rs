use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct DeserializationAnalyzer;

impl DeserializationAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for DeserializationAnalyzer {
    fn name(&self) -> &'static str {
        "deserialization"
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
const RB_EXTENSIONS: &[&str] = &["rb"];
const JAVA_EXTENSIONS: &[&str] = &["java", "kt", "kts"];
const PHP_EXTENSIONS: &[&str] = &["php"];

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-DES-001",
        message: "pickle.loads on untrusted input is remote code execution",
        severity: Severity::Critical,
        help: "never deserialize untrusted pickle; switch to JSON or a schema-validated format",
        pattern: r"\bpickle\.(loads?|Unpickler)\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-DES-002",
        message: "yaml.load without an explicit SafeLoader can execute arbitrary Python",
        severity: Severity::High,
        help: "use yaml.safe_load(...) or yaml.load(stream, Loader=yaml.SafeLoader)",
        pattern: r"\byaml\.load\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-DES-003",
        message: "marshal.loads on untrusted input is remote code execution",
        severity: Severity::Critical,
        help: "never deserialize untrusted marshal data; switch to JSON",
        pattern: r"\bmarshal\.loads?\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-DES-004",
        message: "node-serialize unserialize() is documented to allow RCE; do not use",
        severity: Severity::Critical,
        help: "remove node-serialize; use JSON.parse for trusted data, or a schema-validated parser",
        pattern: r#"\bserialize\.unserialize\s*\(|require\s*\(\s*['"]node-serialize['"]"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-DES-005",
        message: "Ruby Marshal.load on untrusted input is remote code execution",
        severity: Severity::Critical,
        help: "never deserialize untrusted Marshal data; use JSON instead",
        pattern: r"\bMarshal\.(load|restore)\s*\(",
        extensions: RB_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-DES-006",
        message: "ObjectInputStream readObject on untrusted input is a known RCE vector (e.g. CVE-2015-7501)",
        severity: Severity::Critical,
        help: "avoid native Java deserialization; use JSON or a schema-validated format",
        pattern: r"\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)",
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-DES-007",
        message: "PHP unserialize() on untrusted input is a known RCE vector",
        severity: Severity::Critical,
        help: "avoid unserialize; use json_decode for trusted data or a typed schema parser",
        pattern: r"\bunserialize\s*\(",
        extensions: PHP_EXTENSIONS,
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
            name: "deserialization",
            message: format!("failed to compile a builtin deserialization pattern: {e}"),
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
    fn pickle_loads_python_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-DES-001")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("obj = pickle.loads(data)"));
        assert!(re.is_match("obj = pickle.load(f)"));
        assert!(re.is_match("u = pickle.Unpickler(f)"));
    }

    #[test]
    fn yaml_load_python_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-DES-002")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("cfg = yaml.load(open('config.yml'))"));
        assert!(!re.is_match("cfg = yaml.safe_load(open('config.yml'))"));
    }

    #[test]
    fn marshal_ruby_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-DES-005")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("Marshal.load(data)"));
        assert!(re.is_match("Marshal.restore(data)"));
        assert!(!re.is_match("JSON.parse(data)"));
    }

    #[test]
    fn java_readobject_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-DES-006")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("ObjectInputStream ois = new ObjectInputStream(s);"));
        assert!(re.is_match("Object o = ois.readObject();"));
    }

    #[test]
    fn php_unserialize_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-DES-007")
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("$obj = unserialize($data);"));
        assert!(!re.is_match("$obj = json_decode($data);"));
    }
}
