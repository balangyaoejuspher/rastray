use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Parser, Query, QueryCursor};

use crate::cli::Severity;
use crate::reporter::Finding;

use super::shared::build_finding;

pub fn analyze(path: &Path, source: &str) -> Vec<Finding> {
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

    let mut findings = Vec::new();
    findings.extend(find_await_in_loops(path, &language, root, source, bytes));
    findings.extend(find_new_date_in_loops(path, &language, root, source, bytes));
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

fn find_await_in_loops(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = "(await_expression) @await";
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
                "RSTR-PERF-101",
                "await inside a loop serializes async work",
                Severity::Medium,
                "consider collecting promises and using Promise.all() to parallelize",
            ));
        }
    }
    findings
}

fn find_new_date_in_loops(
    path: &Path,
    language: &tree_sitter::Language,
    root: Node,
    source: &str,
    bytes: &[u8],
) -> Vec<Finding> {
    let query_src = r#"
(new_expression
  constructor: (identifier) @ctor) @call
"#;
    let query = match Query::new(language, query_src) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let ctor_idx = query.capture_index_for_name("ctor");
    let call_idx = query.capture_index_for_name("call");
    let (Some(ctor_idx), Some(call_idx)) = (ctor_idx, call_idx) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, bytes);
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        let mut ctor_node: Option<Node> = None;
        let mut call_node: Option<Node> = None;
        for cap in m.captures {
            if cap.index == ctor_idx {
                ctor_node = Some(cap.node);
            } else if cap.index == call_idx {
                call_node = Some(cap.node);
            }
        }
        let (Some(ctor), Some(call)) = (ctor_node, call_node) else {
            continue;
        };
        let Ok(ctor_name) = ctor.utf8_text(bytes) else {
            continue;
        };
        if ctor_name != "Date" {
            continue;
        }
        if !in_loop_body_within_fn(call) {
            continue;
        }
        findings.push(build_finding(
            path,
            source,
            call,
            "RSTR-PERF-102",
            "new Date() inside a loop allocates an object per iteration",
            Severity::Low,
            "use Date.now() when you only need the timestamp, or hoist the Date out of the loop",
        ));
    }
    findings
}

fn in_loop_body_within_fn(start: Node) -> bool {
    let mut prev = start;
    let mut current = start.parent();
    while let Some(node) = current {
        match node.kind() {
            "for_statement" | "for_in_statement" | "for_of_statement" => {
                if let Some(body) = node.child_by_field_name("body") {
                    if prev.id() == body.id() {
                        return true;
                    }
                }
            }
            "while_statement" | "do_statement" => return true,
            "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "generator_function"
            | "generator_function_declaration" => return false,
            _ => {}
        }
        prev = node;
        current = node.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run_js(source: &str) -> Vec<Finding> {
        analyze(&PathBuf::from("test.js"), source)
    }

    fn run_ts(source: &str) -> Vec<Finding> {
        analyze(&PathBuf::from("test.ts"), source)
    }

    #[test]
    fn empty_source_produces_no_findings() {
        assert_eq!(run_js("").len(), 0);
        assert_eq!(run_ts("").len(), 0);
    }

    #[test]
    fn await_outside_loop_is_not_flagged() {
        let src = r#"
            async function load() {
                const x = await fetch("/x");
                return x;
            }
        "#;
        assert_eq!(run_js(src).len(), 0);
    }

    #[test]
    fn await_inside_for_loop_is_flagged() {
        let src = r#"
            async function loadAll(urls) {
                const out = [];
                for (const u of urls) {
                    out.push(await fetch(u));
                }
                return out;
            }
        "#;
        let findings = run_js(src);
        let await_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-101")
            .collect();
        assert_eq!(await_findings.len(), 1);
        assert_eq!(await_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn await_inside_while_loop_is_flagged() {
        let src = r#"
            async function poll(check) {
                let done = false;
                while (!done) {
                    done = await check();
                }
            }
        "#;
        let findings = run_js(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-101")
                .count(),
            1
        );
    }

    #[test]
    fn await_inside_nested_function_does_not_count_outer_loop() {
        let src = r#"
            async function outer(urls) {
                for (const u of urls) {
                    const inner = async () => await fetch(u);
                    inner();
                }
            }
        "#;
        let findings = run_js(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-101")
                .count(),
            0
        );
    }

    #[test]
    fn new_date_inside_loop_is_flagged() {
        let src = r#"
            function timestamps(n) {
                const out = [];
                for (let i = 0; i < n; i++) {
                    out.push(new Date());
                }
                return out;
            }
        "#;
        let findings = run_js(src);
        let date_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "RSTR-PERF-102")
            .collect();
        assert_eq!(date_findings.len(), 1);
        assert_eq!(date_findings[0].severity, Severity::Low);
    }

    #[test]
    fn new_date_outside_loop_is_not_flagged() {
        let src = r#"
            function now() {
                return new Date();
            }
        "#;
        assert_eq!(run_js(src).len(), 0);
    }

    #[test]
    fn await_inside_for_of_in_typescript_is_flagged() {
        let src = r#"
            async function loadAll(urls: string[]): Promise<Response[]> {
                const out: Response[] = [];
                for (const u of urls) {
                    out.push(await fetch(u));
                }
                return out;
            }
        "#;
        let findings = run_ts(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-101")
                .count(),
            1
        );
    }

    #[test]
    fn invalid_js_syntax_does_not_panic() {
        let _ = run_js("function broken( { return ");
    }

    #[test]
    fn new_date_in_for_initializer_is_not_flagged() {
        let src = r#"
            function walk(end) {
                for (let d = new Date(end); d < end; d.setDate(d.getDate() + 1)) {
                    console.log(d);
                }
            }
        "#;
        let findings = run_js(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-102")
                .count(),
            0,
            "new Date() in for-init runs once, not per iteration"
        );
    }

    #[test]
    fn new_date_in_for_of_iterable_is_not_flagged() {
        let src = r#"
            function dump() {
                for (const k of new Map()) {
                    console.log(k);
                }
            }
        "#;
        let findings = run_js(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-102")
                .count(),
            0,
            "new Map() in for-of iterable runs once, not per iteration"
        );
    }

    #[test]
    fn new_date_in_while_condition_is_flagged() {
        let src = r#"
            function poll() {
                while (new Date().getTime() < deadline) {
                    spin();
                }
            }
        "#;
        let findings = run_js(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-102")
                .count(),
            1,
            "while condition is re-evaluated each iteration"
        );
    }

    #[test]
    fn await_in_for_of_iterable_is_not_flagged() {
        let src = r#"
            async function each() {
                for (const u of await getUrls()) {
                    process(u);
                }
            }
        "#;
        let findings = run_js(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "RSTR-PERF-101")
                .count(),
            0,
            "await in for-of iterable runs once, not per iteration"
        );
    }
}
