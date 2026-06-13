use std::path::Path;

use tree_sitter::Node;

use crate::cli::Severity;
use crate::reporter::{Category, Finding, Location};

pub fn build_finding(
    path: &Path,
    source: &str,
    node: Node,
    code: &str,
    message: &str,
    severity: Severity,
    help: &str,
) -> Finding {
    let start = node.start_byte();
    let end = node.end_byte();
    let length = end.saturating_sub(start);
    let (line, column) = byte_offset_to_line_col(source, start);
    let location = Location::file(path.to_path_buf())
        .with_span(start, length)
        .with_line(line, column);
    Finding::new(code, message, severity, Category::Performance)
        .with_help(help)
        .with_location(location)
}

pub fn byte_offset_to_line_col(text: &str, offset: usize) -> (usize, usize) {
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
    fn byte_offset_to_line_col_handles_multiline_offsets() {
        let text = "a\nbb\nccc";
        assert_eq!(byte_offset_to_line_col(text, 0), (1, 1));
        assert_eq!(byte_offset_to_line_col(text, 2), (2, 1));
        assert_eq!(byte_offset_to_line_col(text, 5), (3, 1));
    }
}
