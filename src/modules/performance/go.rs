use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Parser, Query, QueryCursor};

use crate::cli::Severity;
use crate::reporter::Finding;

use super::shared::build_finding;

pub fn analyze(path: &Path, source: &str) -> Vec<Finding> {
    let mut parser = Parser::new();
    let language = tree_sitter_go::LANGUAGE.into();
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
    findings.extend(find_defer_in_loops(path, &language, root, source, bytes));
    findings.extend(find_sprintf_in_loops(path, &language, root, source, bytes));
    findings
}

fn find_defer_in_loops(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = "(defer_statement) @stmt";
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
            findings.push(build_finding(
                path,
                source,
                cap.node,
                "RSTR-PERF-301",
                "defer inside a loop accumulates and only fires on function return",
                Severity::Medium,
                "wrap the loop body in a function and defer there, or call the cleanup explicitly each iteration",
            ));
        }
    }
    findings
}

fn find_sprintf_in_loops(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = "(call_expression function: (selector_expression) @selector) @call";
    let query = match Query::new(language, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let selector_idx = query.capture_index_for_name("selector");
    let call_idx = query.capture_index_for_name("call");
    let (Some(selector_idx), Some(call_idx)) = (selector_idx, call_idx) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, bytes);
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        let mut selector_node: Option<Node> = None;
        let mut call_node: Option<Node> = None;
        for cap in m.captures {
            if cap.index == selector_idx {
                selector_node = Some(cap.node);
            } else if cap.index == call_idx {
                call_node = Some(cap.node);
            }
        }
        let (Some(selector), Some(call)) = (selector_node, call_node) else {
            continue;
        };
        let Ok(selector_text) = selector.utf8_text(bytes) else {
            continue;
        };
        if selector_text != "fmt.Sprintf" {
            continue;
        }
        if !in_loop_body_within_fn(call) {
            continue;
        }
        findings.push(build_finding(
            path,
            source,
            call,
            "RSTR-PERF-302",
            "fmt.Sprintf inside a loop allocates a new string every iteration",
            Severity::Low,
            "use strings.Builder and fmt.Fprintf(&b, ...) to amortize allocations",
        ));
    }
    findings
}

fn in_loop_body_within_fn(start: Node) -> bool {
    let mut current = start.parent();
    while let Some(node) = current {
        match node.kind() {
            "for_statement" => return true,
            "function_declaration" | "method_declaration" | "func_literal" => return false,
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
        analyze(&PathBuf::from("test.go"), source)
    }

    #[test]
    fn empty_source_produces_no_findings() {
        assert_eq!(run("").len(), 0);
    }

    #[test]
    fn defer_outside_loop_is_not_flagged() {
        let src = "\
package main

import \"os\"

func work() {
    f, _ := os.Open(\"x\")
    defer f.Close()
}
";
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn defer_inside_for_loop_is_flagged() {
        let src = "\
package main

import \"os\"

func work(paths []string) {
    for _, p := range paths {
        f, _ := os.Open(p)
        defer f.Close()
    }
}
";
        let findings = run(src);
        let found: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-301")
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn defer_inside_for_loop_with_classic_form_is_flagged() {
        let src = "\
package main

func work(n int) {
    for i := 0; i < n; i++ {
        defer cleanup(i)
    }
}

func cleanup(i int) {}
";
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-301")
                .count(),
            1
        );
    }

    #[test]
    fn defer_inside_func_literal_inside_loop_is_not_flagged() {
        let src = "\
package main

func work(n int) {
    for i := 0; i < n; i++ {
        func() {
            defer cleanup(i)
        }()
    }
}

func cleanup(i int) {}
";
        let findings = run(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-301")
                .count(),
            0
        );
    }

    #[test]
    fn sprintf_outside_loop_is_not_flagged() {
        let src = "\
package main

import \"fmt\"

func greet(name string) string {
    return fmt.Sprintf(\"hello %s\", name)
}
";
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn sprintf_inside_for_loop_is_flagged() {
        let src = "\
package main

import \"fmt\"

func build(items []string) string {
    var out string
    for _, it := range items {
        out = out + fmt.Sprintf(\"- %s\\n\", it)
    }
    return out
}
";
        let findings = run(src);
        let found: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-302")
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Low);
    }

    #[test]
    fn unrelated_selector_in_loop_is_not_flagged() {
        let src = "\
package main

import \"strings\"

func work(items []string) {
    for _, it := range items {
        _ = strings.ToLower(it)
    }
}
";
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn invalid_go_syntax_does_not_panic() {
        let _ = run("package main\nfunc broken( {\n");
    }
}
