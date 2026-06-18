use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Parser, Query, QueryCursor};

use crate::cli::Severity;
use crate::reporter::{Category, Finding, Location};

const HELP: &str = "use `.textContent` instead of `.innerHTML`, or sanitize with DOMPurify before assignment; never feed `location.*` / `window.name` / `document.URL` / `document.cookie` / `document.referrer` into `innerHTML` / `outerHTML` / `document.write`";
const TRAILER: &str =
    "assigns location/document data into innerHTML/outerHTML — DOM-based XSS risk";

pub fn analyze_inner_html_dom_xss(path: &Path, source: &str) -> Vec<Finding> {
    let language = pick_language(path);
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let root = tree.root_node();
    let bytes = source.as_bytes();

    let query_src = r#"
(assignment_expression
  left: (member_expression
    property: (property_identifier) @prop)
  right: (_) @rhs) @assign
"#;
    let query = match Query::new(&language, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let prop_idx = match query.capture_index_for_name("prop") {
        Some(i) => i,
        None => return Vec::new(),
    };
    let rhs_idx = match query.capture_index_for_name("rhs") {
        Some(i) => i,
        None => return Vec::new(),
    };
    let assign_idx = match query.capture_index_for_name("assign") {
        Some(i) => i,
        None => return Vec::new(),
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, bytes);
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        let mut prop_node: Option<Node> = None;
        let mut rhs_node: Option<Node> = None;
        let mut assign_node: Option<Node> = None;
        for cap in m.captures {
            if cap.index == prop_idx {
                prop_node = Some(cap.node);
            } else if cap.index == rhs_idx {
                rhs_node = Some(cap.node);
            } else if cap.index == assign_idx {
                assign_node = Some(cap.node);
            }
        }
        let (Some(prop), Some(rhs), Some(assign)) = (prop_node, rhs_node, assign_node) else {
            continue;
        };
        let prop_text = match prop.utf8_text(bytes) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if prop_text != "innerHTML" && prop_text != "outerHTML" {
            continue;
        }
        if !rhs_chain_rooted_at_dom_source(rhs, bytes) {
            continue;
        }
        findings.push(make_finding(path, source, assign, bytes));
    }
    findings
}

fn pick_language(path: &Path) -> tree_sitter::Language {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("ts") => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Some("tsx") => tree_sitter_typescript::LANGUAGE_TSX.into(),
        _ => tree_sitter_javascript::LANGUAGE.into(),
    }
}

fn rhs_chain_rooted_at_dom_source(node: Node, bytes: &[u8]) -> bool {
    if is_dom_source_atom(node, bytes) {
        return true;
    }
    match node.kind() {
        "member_expression" => {
            if let Some(obj) = node.child_by_field_name("object") {
                return rhs_chain_rooted_at_dom_source(obj, bytes);
            }
        }
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                return rhs_chain_rooted_at_dom_source(func, bytes);
            }
        }
        _ => {}
    }
    false
}

fn is_dom_source_atom(node: Node, bytes: &[u8]) -> bool {
    if node.kind() == "identifier" {
        return matches!(node.utf8_text(bytes).ok(), Some("location"));
    }
    if node.kind() == "member_expression" {
        let obj = node
            .child_by_field_name("object")
            .and_then(|n| n.utf8_text(bytes).ok());
        let prop = node
            .child_by_field_name("property")
            .and_then(|n| n.utf8_text(bytes).ok());
        if obj == Some("window") && prop == Some("name") {
            return true;
        }
        if obj == Some("document")
            && matches!(
                prop,
                Some("URL")
                    | Some("cookie")
                    | Some("referrer")
                    | Some("baseURI")
                    | Some("documentURI")
            )
        {
            return true;
        }
    }
    false
}

fn make_finding(path: &Path, source: &str, node: Node, bytes: &[u8]) -> Finding {
    let start = node.start_byte();
    let end = node.end_byte();
    let length = end.saturating_sub(start);
    let (line, column) = byte_offset_to_line_col(source, start);
    let snippet = snippet_for_display(node.utf8_text(bytes).unwrap_or(""));
    let message = format!("`{snippet}` {TRAILER}");
    let location = Location::file(path.to_path_buf())
        .with_span(start, length)
        .with_line(line, column);
    Finding::new("RSTR-XSS-002", message, Severity::High, Category::Security)
        .with_help(HELP)
        .with_location(location)
}

fn snippet_for_display(text: &str) -> String {
    let single_line: String = text
        .chars()
        .take_while(|c| *c != '\n' && *c != '\r')
        .collect();
    if single_line.chars().count() > 120 {
        let truncated: String = single_line.chars().take(117).collect();
        format!("{truncated}...")
    } else {
        single_line
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
    use std::path::PathBuf;

    fn run_js(src: &str) -> Vec<Finding> {
        analyze_inner_html_dom_xss(&PathBuf::from("a.js"), src)
    }

    fn run_ts(src: &str) -> Vec<Finding> {
        analyze_inner_html_dom_xss(&PathBuf::from("a.ts"), src)
    }

    fn run_tsx(src: &str) -> Vec<Finding> {
        analyze_inner_html_dom_xss(&PathBuf::from("a.tsx"), src)
    }

    #[test]
    fn empty_source_produces_no_findings() {
        assert!(run_js("").is_empty());
    }

    #[test]
    fn inner_html_assigned_from_location_hash_is_flagged() {
        let findings = run_js("document.getElementById('x').innerHTML = location.hash;");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-XSS-002");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn outer_html_assigned_from_document_cookie_is_flagged() {
        let findings = run_js("el.outerHTML = document.cookie;");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-XSS-002");
    }

    #[test]
    fn inner_html_assigned_from_window_name_is_flagged() {
        let findings = run_js("el.innerHTML = window.name;");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn inner_html_assigned_from_document_referrer_is_flagged() {
        let findings = run_js("el.innerHTML = document.referrer;");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn inner_html_assigned_from_bare_location_is_flagged() {
        let findings = run_js("el.innerHTML = location;");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn inner_html_assigned_from_location_chain_is_flagged() {
        let findings = run_js("el.innerHTML = location.search.toLowerCase();");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn inner_html_with_constant_string_is_silent() {
        let findings = run_js("el.innerHTML = '<b>hi</b>';");
        assert!(findings.is_empty());
    }

    #[test]
    fn inner_html_with_template_literal_is_silent() {
        let findings = run_js("el.innerHTML = `<b>${userName}</b>`;");
        assert!(findings.is_empty());
    }

    #[test]
    fn inner_html_with_sanitised_value_is_silent() {
        let findings = run_js("el.innerHTML = DOMPurify.sanitize(input);");
        assert!(findings.is_empty());
    }

    #[test]
    fn inner_html_assigned_from_user_state_is_silent() {
        let findings = run_js("el.innerHTML = state.html;");
        assert!(findings.is_empty());
    }

    #[test]
    fn inner_html_in_comment_is_silent() {
        let findings = run_js("// el.innerHTML = location.hash;\nconsole.log('ok');");
        assert!(
            findings.is_empty(),
            "comments must never produce findings, got {findings:?}"
        );
    }

    #[test]
    fn inner_html_in_string_literal_is_silent() {
        let findings = run_js("const docs = 'el.innerHTML = location.hash';");
        assert!(
            findings.is_empty(),
            "string literals must never produce findings, got {findings:?}"
        );
    }

    #[test]
    fn inner_html_in_template_literal_is_silent() {
        let findings = run_js("const docs = `el.innerHTML = location.hash`;");
        assert!(
            findings.is_empty(),
            "template literals must never produce findings, got {findings:?}"
        );
    }

    #[test]
    fn react_dangerously_set_inner_html_prop_is_silent() {
        let src = r#"const el = <div dangerouslySetInnerHTML={{ __html: location.hash }} />;"#;
        let findings = run_tsx(src);
        assert!(
            findings.is_empty(),
            "JSX attribute is not an assignment_expression, got {findings:?}"
        );
    }

    #[test]
    fn inner_html_via_window_dot_location_is_silent_by_design() {
        let findings = run_js("el.innerHTML = window.location.hash;");
        assert!(
            findings.is_empty(),
            "matches regex semantics: chain rooted in `window`, not `location`"
        );
    }

    #[test]
    fn typescript_typed_assignment_is_flagged() {
        let src = "const el = document.getElementById('x') as HTMLElement;\nel.innerHTML = location.hash;";
        let findings = run_ts(src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn multiple_assignments_each_produce_one_finding() {
        let src = r#"
el.innerHTML = location.hash;
other.outerHTML = document.cookie;
safe.innerHTML = "ok";
        "#;
        let findings = run_js(src);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn syntax_error_returns_no_findings_safely() {
        let findings = run_js("function broken(  {");
        assert!(findings.is_empty());
    }

    #[test]
    fn message_includes_inner_html_substring() {
        let findings = run_js("el.innerHTML = location.hash;");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("innerHTML"),
            "message should reference the sink: {}",
            findings[0].message
        );
    }
}
