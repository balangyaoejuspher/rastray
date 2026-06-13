use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Parser, Query, QueryCursor};

use crate::cli::Severity;
use crate::reporter::Finding;

use super::shared::build_finding;

pub fn analyze(path: &Path, source: &str) -> Vec<Finding> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
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
    findings.extend(find_string_plus_assign_in_loops(
        path, &language, root, source, bytes,
    ));
    findings.extend(find_time_sleep_in_async(
        path, &language, root, source, bytes,
    ));
    findings
}

fn find_string_plus_assign_in_loops(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = r#"
(augmented_assignment
  left: (identifier)
  operator: "+=") @stmt
"#;
    let query = match Query::new(language, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, bytes);
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if !in_loop_body_within_fn(cap.node) {
                continue;
            }
            if !augmented_assign_right_might_be_string(cap.node) {
                continue;
            }
            findings.push(build_finding(
                path,
                source,
                cap.node,
                "RSTR-PERF-201",
                "string += inside a loop allocates a new string every iteration",
                Severity::Medium,
                "build a list and use ''.join(parts) once at the end",
            ));
        }
    }
    findings
}

fn augmented_assign_right_might_be_string(stmt: Node) -> bool {
    let Some(right) = stmt.child_by_field_name("right") else {
        return false;
    };
    node_might_be_string(right)
}

fn node_might_be_string(node: Node) -> bool {
    match node.kind() {
        "string" | "concatenated_string" | "string_literal" => true,
        "binary_operator" => {
            let Some(left) = node.child_by_field_name("left") else {
                return false;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return false;
            };
            node_might_be_string(left) || node_might_be_string(right)
        }
        "parenthesized_expression" => {
            let mut walker = node.walk();
            for child in node.children(&mut walker) {
                if node_might_be_string(child) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn find_time_sleep_in_async(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = "(call function: (attribute) @attr) @call";
    let query = match Query::new(language, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let attr_idx = query.capture_index_for_name("attr");
    let call_idx = query.capture_index_for_name("call");
    let (Some(attr_idx), Some(call_idx)) = (attr_idx, call_idx) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, bytes);
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        let mut attr_node: Option<Node> = None;
        let mut call_node: Option<Node> = None;
        for cap in m.captures {
            if cap.index == attr_idx {
                attr_node = Some(cap.node);
            } else if cap.index == call_idx {
                call_node = Some(cap.node);
            }
        }
        let (Some(attr), Some(call)) = (attr_node, call_node) else {
            continue;
        };
        let Ok(attr_text) = attr.utf8_text(bytes) else {
            continue;
        };
        if attr_text != "time.sleep" {
            continue;
        }
        if !in_async_function(call) {
            continue;
        }
        findings.push(build_finding(
            path,
            source,
            call,
            "RSTR-PERF-202",
            "time.sleep() inside an async function blocks the event loop",
            Severity::High,
            "use `await asyncio.sleep(...)` instead",
        ));
    }
    findings
}

fn in_loop_body_within_fn(start: Node) -> bool {
    let mut current = start.parent();
    while let Some(node) = current {
        match node.kind() {
            "for_statement" | "while_statement" => return true,
            "function_definition" | "lambda" => return false,
            _ => current = node.parent(),
        }
    }
    false
}

fn in_async_function(start: Node) -> bool {
    let mut current = start.parent();
    while let Some(node) = current {
        if node.kind() == "function_definition" {
            let mut walker = node.walk();
            for child in node.children(&mut walker) {
                if child.kind() == "async" {
                    return true;
                }
            }
            return false;
        }
        if node.kind() == "lambda" {
            return false;
        }
        current = node.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(source: &str) -> Vec<Finding> {
        analyze(&PathBuf::from("test.py"), source)
    }

    #[test]
    fn empty_source_produces_no_findings() {
        assert_eq!(run("").len(), 0);
    }

    #[test]
    fn string_plus_assign_inside_for_loop_is_flagged() {
        let src = "\
def build():
    out = ''
    for i in range(10):
        out += 'x'
    return out
";
        let findings = run(src);
        let found: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-201")
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn string_plus_assign_with_concat_expression_is_flagged() {
        let src = "\
def build(items):
    out = ''
    for item in items:
        out += item + '\\n'
    return out
";
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-201")
                .count(),
            1
        );
    }

    #[test]
    fn string_plus_assign_inside_while_loop_is_flagged() {
        let src = "\
def build():
    out = ''
    i = 0
    while i < 10:
        out += 'x'
        i += 1
    return out
";
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-201")
                .count(),
            1
        );
    }

    #[test]
    fn string_plus_assign_outside_loop_is_not_flagged() {
        let src = "\
def hello():
    s = 'hi'
    s += ' world'
    return s
";
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn integer_plus_assign_inside_loop_is_not_flagged() {
        let src = "\
def count():
    n = 0
    for _ in range(10):
        n += 1
    return n
";
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn time_sleep_in_sync_function_is_not_flagged() {
        let src = "\
import time

def wait():
    time.sleep(1)
";
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn time_sleep_in_async_function_is_flagged() {
        let src = "\
import time

async def wait():
    time.sleep(1)
";
        let findings = run(src);
        let found: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-202")
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::High);
    }

    #[test]
    fn time_sleep_in_nested_sync_function_inside_async_is_not_flagged() {
        let src = "\
import time

async def outer():
    def inner():
        time.sleep(1)
    inner()
";
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-202")
                .count(),
            0
        );
    }

    #[test]
    fn asyncio_sleep_in_async_is_not_flagged() {
        let src = "\
import asyncio

async def wait():
    await asyncio.sleep(1)
";
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn invalid_python_syntax_does_not_panic() {
        let _ = run("def broken(:\n");
    }
}
