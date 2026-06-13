use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use crate::reporter::Finding;

const WILDCARD: &str = "*";

#[derive(Debug, Default)]
struct FileSuppressions {
    whole_file: HashSet<String>,
    by_line: HashMap<usize, HashSet<String>>,
}

#[derive(Debug, Default)]
pub struct Suppressions {
    files: HashMap<PathBuf, FileSuppressions>,
}

static DIRECTIVE_RE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();

fn directive_regex() -> Option<&'static Regex> {
    let cached =
        DIRECTIVE_RE.get_or_init(|| Regex::new(r"rastray-ignore(?:-(line|file))?\s*:\s*([^/\n]*)"));
    cached.as_ref().ok()
}

impl Suppressions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, findings: &mut Vec<Finding>) {
        let paths: HashSet<PathBuf> = findings
            .iter()
            .filter_map(|f| f.location.as_ref().map(|l| l.file.clone()))
            .collect();
        for path in paths {
            self.load(&path);
        }
        findings.retain(|f| !self.is_suppressed(f));
    }

    fn is_suppressed(&self, finding: &Finding) -> bool {
        let loc = match &finding.location {
            Some(l) => l,
            None => return false,
        };
        let file = match self.files.get(&loc.file) {
            Some(fs) => fs,
            None => return false,
        };
        if matches_code(&file.whole_file, &finding.code) {
            return true;
        }
        if let Some(line) = loc.line {
            if let Some(codes) = file.by_line.get(&line) {
                if matches_code(codes, &finding.code) {
                    return true;
                }
            }
        }
        false
    }

    fn load(&mut self, path: &Path) {
        if self.files.contains_key(path) {
            return;
        }
        let parsed = parse_file(path).unwrap_or_default();
        self.files.insert(path.to_path_buf(), parsed);
    }
}

fn matches_code(codes: &HashSet<String>, code: &str) -> bool {
    codes.contains(WILDCARD) || codes.contains(code)
}

fn parse_file(path: &Path) -> Option<FileSuppressions> {
    let file = std::fs::File::open(path).ok()?;
    let reader = BufReader::new(file);
    let re = directive_regex()?;

    let mut out = FileSuppressions::default();
    for (idx, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let one_based = idx + 1;
        for cap in re.captures_iter(&line) {
            let suffix = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let codes = match cap.get(2) {
                Some(m) => parse_codes(m.as_str()),
                None => continue,
            };
            if codes.is_empty() {
                continue;
            }
            match suffix {
                "file" => out.whole_file.extend(codes),
                "line" => out.by_line.entry(one_based).or_default().extend(codes),
                _ => out.by_line.entry(one_based + 1).or_default().extend(codes),
            }
        }
    }
    Some(out)
}

fn parse_codes(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .filter(|s| is_valid_code_token(s))
        .map(|s| s.to_string())
        .collect()
}

fn is_valid_code_token(s: &str) -> bool {
    if s == WILDCARD {
        return true;
    }
    if !s.starts_with("RSTR-") || s.len() < 7 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Severity;
    use crate::reporter::{Category, Finding, Location};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir() -> Option<PathBuf> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rastray-supp-test-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        match fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        let _ = fs::write(&path, contents);
        path
    }

    fn finding_at(code: &str, file: &Path, line: usize) -> Finding {
        let mut f = Finding::new(code, "msg", Severity::Medium, Category::Performance);
        f.location = Some(Location {
            file: file.to_path_buf(),
            byte_offset: None,
            byte_length: None,
            line: Some(line),
            column: None,
        });
        f
    }

    #[test]
    fn parse_codes_keeps_valid_tokens_only() {
        assert_eq!(
            parse_codes("RSTR-PERF-001, RSTR-SEC-002"),
            vec!["RSTR-PERF-001", "RSTR-SEC-002"]
        );
        assert_eq!(
            parse_codes("RSTR-PERF-001 because reason"),
            vec!["RSTR-PERF-001"]
        );
        assert_eq!(parse_codes(""), Vec::<String>::new());
        assert_eq!(parse_codes("not a code"), Vec::<String>::new());
    }

    #[test]
    fn parse_codes_accepts_wildcard() {
        assert_eq!(parse_codes("*"), vec!["*"]);
    }

    #[test]
    fn is_valid_code_token_rejects_lowercase_and_short() {
        assert!(!is_valid_code_token("rstr-perf-001"));
        assert!(!is_valid_code_token("RSTR-"));
        assert!(!is_valid_code_token("FOO-PERF-001"));
        assert!(is_valid_code_token("RSTR-PERF-001"));
    }

    #[test]
    fn next_line_directive_suppresses_following_line() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write(
            &dir,
            "a.rs",
            "fn main() {\n    // rastray-ignore: RSTR-PERF-001\n    bad();\n}\n",
        );
        let mut s = Suppressions::new();
        let mut findings = vec![finding_at("RSTR-PERF-001", &path, 3)];
        s.apply(&mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn line_directive_suppresses_same_line() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write(
            &dir,
            "a.rs",
            "fn main() {\n    bad(); // rastray-ignore-line: RSTR-PERF-001\n}\n",
        );
        let mut s = Suppressions::new();
        let mut findings = vec![finding_at("RSTR-PERF-001", &path, 2)];
        s.apply(&mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn file_directive_suppresses_all_matching_in_file() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write(
            &dir,
            "a.rs",
            "// rastray-ignore-file: RSTR-PERF-001\nfn a() {}\nfn b() {}\n",
        );
        let mut s = Suppressions::new();
        let mut findings = vec![
            finding_at("RSTR-PERF-001", &path, 2),
            finding_at("RSTR-PERF-001", &path, 3),
            finding_at("RSTR-PERF-002", &path, 2),
        ];
        s.apply(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-PERF-002");
    }

    #[test]
    fn wildcard_suppresses_any_code() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write(&dir, "a.rs", "// rastray-ignore-file: *\nfn a() {}\n");
        let mut s = Suppressions::new();
        let mut findings = vec![
            finding_at("RSTR-PERF-001", &path, 2),
            finding_at("RSTR-SEC-009", &path, 2),
        ];
        s.apply(&mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn directive_for_other_code_does_not_suppress() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write(
            &dir,
            "a.rs",
            "// rastray-ignore: RSTR-PERF-999\n    bad();\n",
        );
        let mut s = Suppressions::new();
        let mut findings = vec![finding_at("RSTR-PERF-001", &path, 2)];
        s.apply(&mut findings);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn finding_without_location_is_never_suppressed() {
        let mut f = Finding::new("RSTR-INT-001", "msg", Severity::Medium, Category::Internal);
        f.location = None;
        let mut s = Suppressions::new();
        let mut findings = vec![f];
        s.apply(&mut findings);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn python_hash_comments_are_supported() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write(
            &dir,
            "a.py",
            "def f():\n    # rastray-ignore-line: RSTR-PERF-201\n    sleep(1)\n",
        );
        let mut s = Suppressions::new();
        let mut findings = vec![finding_at("RSTR-PERF-201", &path, 2)];
        s.apply(&mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn comma_separated_codes_all_suppress() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let path = write(
            &dir,
            "a.rs",
            "// rastray-ignore: RSTR-PERF-001, RSTR-SEC-002\n    bad();\n",
        );
        let mut s = Suppressions::new();
        let mut findings = vec![
            finding_at("RSTR-PERF-001", &path, 2),
            finding_at("RSTR-SEC-002", &path, 2),
            finding_at("RSTR-PERF-002", &path, 2),
        ];
        s.apply(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RSTR-PERF-002");
    }

    #[test]
    fn directives_in_one_file_do_not_affect_another() {
        let dir = match tempdir() {
            Some(d) => d,
            None => return,
        };
        let a = write(&dir, "a.rs", "// rastray-ignore-file: RSTR-PERF-001\n");
        let b = write(&dir, "b.rs", "fn main() {}\n");
        let mut s = Suppressions::new();
        let mut findings = vec![
            finding_at("RSTR-PERF-001", &a, 1),
            finding_at("RSTR-PERF-001", &b, 1),
        ];
        s.apply(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].location.as_ref().map(|l| l.file.as_path()),
            Some(b.as_path())
        );
    }

    #[test]
    fn missing_file_silently_keeps_findings() {
        let mut s = Suppressions::new();
        let phantom = PathBuf::from("/definitely/does/not/exist/rastray-test-xyz.rs");
        let mut findings = vec![finding_at("RSTR-PERF-001", &phantom, 1)];
        s.apply(&mut findings);
        assert_eq!(findings.len(), 1);
    }
}
