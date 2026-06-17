use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::{CrawlSummary, FileKind};
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct XxeAnalyzer;

impl XxeAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for XxeAnalyzer {
    fn name(&self) -> &'static str {
        "xxe"
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
const JAVA_EXTENSIONS: &[&str] = &["java"];

const TRAILER_PY_STDLIB: &str =
    "parses XML with stdlib xml.etree / xml.sax / xml.dom — external-entity expansion is enabled by default and can read local files or trigger SSRF (use defusedxml.ElementTree instead)";

const TRAILER_PY_LXML: &str =
    "parses XML with lxml using a parser that resolves external entities — XXE risk (pass `resolve_entities=False, no_network=True` to lxml.etree.XMLParser, or use defusedxml.lxml)";

const TRAILER_JS_LIBXML_NOENT: &str =
    "parses XML with libxmljs and explicit `noent: true` — external-entity expansion is enabled, allowing local-file disclosure and SSRF";

const TRAILER_JS_XML2JS: &str =
    "parses XML with xml2js and `explicitArray: false` is the only safety toggle — entity expansion is still on; set `explicitCharkey: true` and validate inputs, or switch to a defused parser";

const TRAILER_JAVA: &str =
    "constructs a DocumentBuilder / SAXParser / XMLReader without disabling external entities — XXE risk (set `disallow-doctype-decl` to true and `external-general-entities` / `external-parameter-entities` to false on the factory)";

const HELP_PY_STDLIB: &str = "switch to `defusedxml.ElementTree.fromstring(...)` / `defusedxml.ElementTree.parse(...)`; the stdlib `xml.etree.ElementTree` resolves external entities by default and is documented by Python's docs as not secure against maliciously constructed data";

const HELP_PY_LXML: &str = "construct the parser as `lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)` and pass it explicitly: `lxml.etree.fromstring(data, parser=parser)`; or use `defusedxml.lxml.fromstring(...)`";

const HELP_JS_LIBXML: &str = "remove `noent: true`; libxmljs defaults are reasonable when entity expansion is left off — explicitly enabling it on untrusted input is the bug";

const HELP_JS_XML2JS: &str = "validate XML inputs against a schema before parsing, prefer a dedicated XML schema validator, or switch to a parser that has DTD/entity expansion disabled at the engine level (e.g. `fast-xml-parser` with default options)";

const HELP_JAVA: &str = "on the factory, call: `setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`, `setFeature(\"http://xml.org/sax/features/external-general-entities\", false)`, `setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false)`, and `setXIncludeAware(false); setExpandEntityReferences(false)`. See OWASP \"XXE Prevention Cheat Sheet\" for the full hardened factory snippet.";

const PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-XXE-001",
        trailer: TRAILER_PY_STDLIB,
        severity: Severity::High,
        help: HELP_PY_STDLIB,
        pattern: r"\bxml\.etree\.ElementTree\.(?:fromstring|parse|XMLParser|iterparse)\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-001",
        trailer: TRAILER_PY_STDLIB,
        severity: Severity::High,
        help: HELP_PY_STDLIB,
        pattern: r"\bxml\.sax\.(?:parse|parseString|make_parser)\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-001",
        trailer: TRAILER_PY_STDLIB,
        severity: Severity::High,
        help: HELP_PY_STDLIB,
        pattern: r"\bxml\.dom\.minidom\.(?:parse|parseString)\s*\(",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-002",
        trailer: TRAILER_PY_LXML,
        severity: Severity::High,
        help: HELP_PY_LXML,
        pattern: r"\blxml\.etree\.XMLParser\s*\([^)]*resolve_entities\s*=\s*True[^)]*\)",
        extensions: PY_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-003",
        trailer: TRAILER_JS_LIBXML_NOENT,
        severity: Severity::High,
        help: HELP_JS_LIBXML,
        pattern: r"\b(?:libxmljs|libxml)\.parseXml(?:String)?\s*\([^)]*noent\s*:\s*true",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-004",
        trailer: TRAILER_JS_XML2JS,
        severity: Severity::Medium,
        help: HELP_JS_XML2JS,
        pattern: r"\bnew\s+xml2js\.Parser\s*\(\s*\{[^}]*\}\s*\)\s*\.\s*parseString\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,",
        extensions: JS_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-005",
        trailer: TRAILER_JAVA,
        severity: Severity::High,
        help: HELP_JAVA,
        pattern: r"\bDocumentBuilderFactory\.newInstance\s*\(\s*\)",
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-005",
        trailer: TRAILER_JAVA,
        severity: Severity::High,
        help: HELP_JAVA,
        pattern: r"\bSAXParserFactory\.newInstance\s*\(\s*\)",
        extensions: JAVA_EXTENSIONS,
    },
    PatternSpec {
        code: "RSTR-XXE-005",
        trailer: TRAILER_JAVA,
        severity: Severity::High,
        help: HELP_JAVA,
        pattern: r"\bXMLInputFactory\.newInstance\s*\(\s*\)",
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
            name: "xxe",
            message: format!("failed to compile a builtin xxe pattern: {e}"),
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
            std::env::temp_dir().join(format!("rastray-xxe-test-{}-{}", std::process::id(), n));
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
        let result = XxeAnalyzer::new().analyze(&crawl).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_patterns().is_ok());
    }

    #[test]
    fn xml_etree_fromstring_is_flagged() {
        let body =
            "import xml.etree.ElementTree as ET\ntree = xml.etree.ElementTree.fromstring(data)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-001"));
    }

    #[test]
    fn xml_etree_parse_is_flagged() {
        let body = "tree = xml.etree.ElementTree.parse('user.xml')";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-001"));
    }

    #[test]
    fn xml_sax_parsestring_is_flagged() {
        let body = "xml.sax.parseString(payload, handler)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-001"));
    }

    #[test]
    fn xml_dom_minidom_parsestring_is_flagged() {
        let body = "doc = xml.dom.minidom.parseString(data)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-001"));
    }

    #[test]
    fn lxml_xmlparser_with_resolve_entities_true_is_flagged() {
        let body = "parser = lxml.etree.XMLParser(resolve_entities=True)";
        let findings = run_on("a.py", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-002"));
    }

    #[test]
    fn libxmljs_parsexml_with_noent_true_is_flagged() {
        let body = "const doc = libxmljs.parseXml(xml, { noent: true });";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-003"));
    }

    #[test]
    fn xml2js_parser_parsestring_is_flagged() {
        let body = "new xml2js.Parser({ explicitArray: false }).parseString(input, cb);";
        let findings = run_on("a.js", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-004"));
    }

    #[test]
    fn java_document_builder_factory_is_flagged() {
        let body = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();";
        let findings = run_on("a.java", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-005"));
    }

    #[test]
    fn java_sax_parser_factory_is_flagged() {
        let body = "SAXParserFactory spf = SAXParserFactory.newInstance();";
        let findings = run_on("a.java", body);
        assert!(findings.iter().any(|f| f.code == "RSTR-XXE-005"));
    }

    #[test]
    fn defusedxml_fromstring_is_not_flagged() {
        let body = "import defusedxml.ElementTree as ET\ntree = ET.fromstring(data)";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "defusedxml is the safe alternative and should not flag: {findings:?}"
        );
    }

    #[test]
    fn lxml_xmlparser_with_resolve_entities_false_is_not_flagged() {
        let body = "parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)";
        let findings = run_on("a.py", body);
        assert!(
            findings.is_empty(),
            "hardened lxml parser should not flag: {findings:?}"
        );
    }

    #[test]
    fn libxmljs_parsexml_without_noent_is_not_flagged() {
        let body = "const doc = libxmljs.parseXml(xml);";
        let findings = run_on("a.js", body);
        assert!(
            findings.is_empty(),
            "default libxmljs (no noent) should not flag: {findings:?}"
        );
    }

    #[test]
    fn non_xml_extension_is_skipped_for_py_pattern() {
        let body = "xml.etree.ElementTree.fromstring(data)";
        let findings = run_on("a.txt", body);
        assert!(findings.is_empty(), "txt should be ignored: {findings:?}");
    }

    #[test]
    fn messages_for_same_rule_differ_by_captured_call_site() {
        let body =
            "xml.etree.ElementTree.fromstring(a)\nxml.etree.ElementTree.parse('b.xml')\nxml.dom.minidom.parseString(c)";
        let findings = run_on("a.py", body);
        let msgs: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("fromstring")));
        assert!(msgs.iter().any(|m| m.contains("parse")));
        assert!(msgs.iter().any(|m| m.contains("parseString")));
        let unique: std::collections::HashSet<&str> = msgs.iter().copied().collect();
        assert_eq!(
            unique.len(),
            msgs.len(),
            "each finding should have a distinct message: {msgs:?}"
        );
    }

    #[test]
    fn help_text_includes_remediation_idiom_for_language() {
        let py_findings = run_on("a.py", "xml.etree.ElementTree.fromstring(data)");
        let py_help = py_findings
            .iter()
            .find(|f| f.code == "RSTR-XXE-001")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(py_help.contains("defusedxml"));

        let lxml_findings = run_on("a.py", "p = lxml.etree.XMLParser(resolve_entities=True)");
        let lxml_help = lxml_findings
            .iter()
            .find(|f| f.code == "RSTR-XXE-002")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(
            lxml_help.contains("resolve_entities=False") || lxml_help.contains("defusedxml.lxml")
        );

        let java_findings = run_on(
            "a.java",
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
        );
        let java_help = java_findings
            .iter()
            .find(|f| f.code == "RSTR-XXE-005")
            .and_then(|f| f.help.as_deref())
            .unwrap_or_default();
        assert!(java_help.contains("disallow-doctype-decl"));
    }

    #[test]
    fn trim_match_balances_parens() {
        let raw = "xml.etree.ElementTree.fromstring(data,";
        let out = trim_match(raw);
        assert_eq!(out, "xml.etree.ElementTree.fromstring(data)");
    }
}
