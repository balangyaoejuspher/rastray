use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Parser, Query, QueryCursor};

use crate::cli::Severity;
use crate::reporter::Finding;

use super::shared::build_finding;

pub fn analyze(path: &Path, source: &str) -> Vec<Finding> {
    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let root = tree.root_node();
    let bytes = source.as_bytes();

    let mut findings = Vec::new();
    findings.extend(find_format_in_loops(path, &language, root, source, bytes));
    findings.extend(find_clone_in_for_iter(path, &language, root, source, bytes));
    findings
}

fn find_format_in_loops(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = "(macro_invocation macro: (identifier) @macro_name)";
    let query = match Query::new(language, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, bytes);
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        for cap in m.captures {
            let Ok(name) = cap.node.utf8_text(bytes) else {
                continue;
            };
            if name != "format" {
                continue;
            }
            let Some(macro_node) = cap.node.parent() else {
                continue;
            };
            if !has_loop_ancestor_within_fn(macro_node) {
                continue;
            }
            if !is_string_accumulator_use(macro_node, bytes) {
                continue;
            }
            findings.push(build_finding(
                path,
                source,
                cap.node,
                "RSTR-PERF-001",
                "format! used to extend a String inside a loop allocates a temporary per iteration",
                Severity::Medium,
                "write directly into the existing String with write!(&mut s, ...) (from std::fmt::Write) to avoid the intermediate allocation",
            ));
        }
    }
    findings
}

fn is_string_accumulator_use(macro_node: Node, bytes: &[u8]) -> bool {
    let unwrapped = macro_node
        .parent()
        .filter(|p| p.kind() == "reference_expression")
        .unwrap_or(macro_node);
    let Some(parent) = unwrapped.parent() else {
        return false;
    };
    match parent.kind() {
        "compound_assignment_expr" => {
            let rhs_match = parent
                .child_by_field_name("right")
                .is_some_and(|n| n.id() == unwrapped.id());
            let op_match = parent
                .child_by_field_name("operator")
                .and_then(|op| op.utf8_text(bytes).ok())
                .is_some_and(|s| s == "+=");
            rhs_match && op_match
        }
        "arguments" => {
            let Some(call) = parent.parent() else {
                return false;
            };
            if call.kind() != "call_expression" {
                return false;
            }
            let Some(func) = call.child_by_field_name("function") else {
                return false;
            };
            if func.kind() != "field_expression" {
                return false;
            }
            func.child_by_field_name("field")
                .and_then(|f| f.utf8_text(bytes).ok())
                .is_some_and(|s| s == "push_str")
        }
        _ => false,
    }
}

fn find_clone_in_for_iter(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = r#"
        (for_expression
        value: (call_expression
            function: (field_expression
            field: (field_identifier) @method)) @call)
        "#;
    let query = match Query::new(language, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let method_idx = query.capture_index_for_name("method");
    let call_idx = query.capture_index_for_name("call");
    let (Some(method_idx), Some(call_idx)) = (method_idx, call_idx) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, bytes);
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        let mut method_node: Option<Node> = None;
        let mut call_node: Option<Node> = None;
        for cap in m.captures {
            if cap.index == method_idx {
                method_node = Some(cap.node);
            } else if cap.index == call_idx {
                call_node = Some(cap.node);
            }
        }
        let (Some(method), Some(call)) = (method_node, call_node) else {
            continue;
        };
        let Ok(method_name) = method.utf8_text(bytes) else {
            continue;
        };
        if method_name != "clone" {
            continue;
        }
        findings.push(build_finding(
            path,
            source,
            call,
            "RSTR-PERF-002",
            "for-loop iterates over a .clone() of the collection",
            Severity::Low,
            "cloning a whole collection only to iterate it is wasteful; iterate by reference (e.g. `&xs`) instead",
        ));
    }
    findings
}

fn has_loop_ancestor_within_fn(start: Node) -> bool {
    let mut current = start.parent();
    while let Some(node) = current {
        match node.kind() {
            "for_expression" | "while_expression" | "loop_expression" => return true,
            "function_item" | "closure_expression" | "function_signature_item" => return false,
            _ => current = node.parent(),
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(source: &str) -> Vec<Finding> {
        analyze(&PathBuf::from("test.rs"), source)
    }

    #[test]
    fn empty_source_produces_no_findings() {
        assert_eq!(run("").len(), 0);
    }

    #[test]
    fn format_macro_outside_loop_is_not_flagged() {
        let src = r#"
            fn main() {
                let s = format!("hello {}", 1);
                println!("{s}");
            }
        "#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn format_inside_for_loop_is_flagged() {
        let src = r#"
            fn build() -> String {
                let mut s = String::new();
                for i in 0..10 {
                    s.push_str(&format!("item {i}\n"));
                }
                s
            }
        "#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-PERF-001");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn format_inside_while_loop_with_push_str_is_flagged() {
        let src = r#"
            fn run_it() -> String {
                let mut s = String::new();
                let mut i = 0;
                while i < 10 {
                    s.push_str(&format!("{i}"));
                    i += 1;
                }
                s
            }
        "#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-PERF-001");
    }

    #[test]
    fn format_inside_loop_keyword_with_push_str_is_flagged() {
        let src = r#"
            fn run_it() -> String {
                let mut s = String::new();
                let mut i = 0;
                loop {
                    s.push_str(&format!("{i}"));
                    i += 1;
                    if i > 5 { break; }
                }
                s
            }
        "#;
        let findings = run(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-PERF-001");
    }

    #[test]
    fn format_inside_loop_as_let_binding_is_not_flagged() {
        let src = r#"
            fn run_it() {
                for i in 0..10 {
                    let _ = format!("{i}");
                }
            }
        "#;
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-001")
                .count(),
            0,
            "a discarded format! result is a one-off allocation, not a string accumulator"
        );
    }

    #[test]
    fn format_inside_loop_as_function_argument_is_not_flagged() {
        let src = r#"
            fn log(s: String) {}
            fn run_it() {
                for i in 0..10 {
                    log(format!("{i}"));
                }
            }
        "#;
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-001")
                .count(),
            0,
            "format! handed to a function is one allocation per call, not a string accumulator"
        );
    }

    #[test]
    fn format_inside_loop_as_struct_field_is_not_flagged() {
        let src = r#"
            struct Item { name: String }
            fn run_it() -> Vec<Item> {
                let mut out = Vec::new();
                for i in 0..10 {
                    out.push(Item { name: format!("name {i}") });
                }
                out
            }
        "#;
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-001")
                .count(),
            0,
            "format! constructing a struct field is one allocation, not a string accumulator"
        );
    }

    #[test]
    fn format_inside_loop_with_compound_add_assign_is_flagged() {
        let src = r#"
            fn run_it() -> String {
                let mut s = String::new();
                for i in 0..10 {
                    s += &format!("{i}");
                }
                s
            }
        "#;
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-001")
                .count(),
            1
        );
    }

    #[test]
    fn format_inside_closure_inside_loop_does_not_cross_fn_boundary() {
        let src = r#"
            fn run_it() {
                for _ in 0..3 {
                    let make = || format!("inside closure");
                    let _ = make();
                }
            }
        "#;
        let findings = run(src);
        let format_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-001")
            .collect();
        assert_eq!(format_findings.len(), 0);
    }

    #[test]
    fn for_loop_with_clone_iterable_is_flagged() {
        let src = r#"
            fn process(xs: Vec<i32>) {
                for x in xs.clone() {
                    let _ = x;
                }
            }
        "#;
        let findings = run(src);
        let clone_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-002")
            .collect();
        assert_eq!(clone_findings.len(), 1);
        assert_eq!(clone_findings[0].severity, Severity::Low);
    }

    #[test]
    fn for_loop_over_borrow_is_not_flagged() {
        let src = r#"
            fn process(xs: Vec<i32>) {
                for x in &xs {
                    let _ = x;
                }
            }
        "#;
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-002")
                .count(),
            0
        );
    }

    #[test]
    fn for_loop_with_iter_method_is_not_flagged() {
        let src = r#"
            fn process(xs: Vec<i32>) {
                for x in xs.iter() {
                    let _ = x;
                }
            }
        "#;
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-002")
                .count(),
            0
        );
    }

    #[test]
    fn invalid_syntax_does_not_panic() {
        let src = "fn broken( { let x = ";
        let _ = run(src);
    }
}
