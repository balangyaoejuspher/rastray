use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct NetworkAnalyzer;

impl NetworkAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for NetworkAnalyzer {
    fn name(&self) -> &'static str {
        "network"
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

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-NET-001",
        message: "TLS certificate verification disabled (verify=False); traffic is vulnerable to MITM",
        severity: Severity::High,
        help: "remove verify=False; if a custom CA is needed, pass its bundle path instead",
        pattern: r"\bverify\s*=\s*False\b",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NET-001",
        message: "TLS certificate verification disabled (rejectUnauthorized: false); traffic is vulnerable to MITM",
        severity: Severity::High,
        help: "remove rejectUnauthorized: false; if a custom CA is needed, pass ca: [pem]",
        pattern: r"\brejectUnauthorized\s*:\s*false\b",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NET-001",
        message: "TLS certificate verification disabled (InsecureSkipVerify: true); MITM vulnerable",
        severity: Severity::High,
        help: "remove InsecureSkipVerify; use a proper CA bundle (or RootCAs field) instead",
        pattern: r"\bInsecureSkipVerify\s*:\s*true\b",
        extensions: GO_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NET-002",
        message: "SSL context with disabled hostname checking; MITM vulnerable",
        severity: Severity::High,
        help: "do not set ctx.check_hostname = False; let it default to True",
        pattern: r"\.check_hostname\s*=\s*False\b",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NET-002",
        message: "SSL context with CERT_NONE; certificate validation disabled",
        severity: Severity::High,
        help: "use ssl.CERT_REQUIRED with the system or a custom CA bundle",
        pattern: r"\bssl\.CERT_NONE\b|\bverify_mode\s*=\s*ssl\.CERT_NONE\b",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NET-003",
        message: "Express CORS wildcard combined with credentials: true; browsers will reject and the configuration is a misconfiguration",
        severity: Severity::High,
        help: "list explicit origins; never combine '*' with credentials: true",
        pattern: r#"origin\s*:\s*['"]\*['"][^}]*credentials\s*:\s*true"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NET-003",
        message: "Access-Control-Allow-Origin set to *; ensure no credentials are sent on this endpoint",
        severity: Severity::Medium,
        help: "list explicit allowed origins instead of '*' for any endpoint that may receive cookies or auth headers",
        pattern: r#"['"]Access-Control-Allow-Origin['"][^,)]*['"]\*['"]"#,
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-NET-004",
        message: "cookie option httpOnly: false; cookie will be readable from client-side JavaScript",
        severity: Severity::Medium,
        help: "set httpOnly: true (or omit the option) so the cookie is not exposed to JS",
        pattern: r"\bhttpOnly\s*:\s*false\b",
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
            name: "network",
            message: format!("failed to compile a builtin network pattern: {e}"),
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
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn verify_false_python_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-NET-001" && p.extensions.contains(&"py"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("requests.get(url, verify=False)"));
        assert!(re.is_match("requests.post(u, verify = False)"));
        assert!(!re.is_match("requests.get(url, verify=True)"));
    }

    #[test]
    fn reject_unauthorized_false_js_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-NET-001" && p.extensions.contains(&"js"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("const agent = new https.Agent({ rejectUnauthorized: false })"));
        assert!(!re.is_match("{ rejectUnauthorized: true }"));
    }

    #[test]
    fn insecure_skip_verify_go_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-NET-001" && p.extensions.contains(&"go"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match("tls.Config{InsecureSkipVerify: true}"));
        assert!(re.is_match("InsecureSkipVerify : true,"));
        assert!(!re.is_match("InsecureSkipVerify: false"));
    }

    #[test]
    fn cors_wildcard_with_credentials_matches() {
        let patterns = match compiled_patterns() {
            Ok(p) => p,
            Err(_) => return,
        };
        let re = patterns
            .iter()
            .find(|p| p.code == "RSTR-NET-003" && p.message.contains("wildcard with credentials"))
            .map(|p| &p.regex);
        let Some(re) = re else { return };
        assert!(re.is_match(r#"cors({ origin: "*", credentials: true })"#));
        assert!(!re.is_match(r#"cors({ origin: "https://app.example.com", credentials: true })"#));
    }
}
