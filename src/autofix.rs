use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::reporter::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoFix {
    pub from: &'static str,
    pub to: &'static str,
}

impl AutoFix {
    pub const fn new(from: &'static str, to: &'static str) -> Self {
        Self { from, to }
    }
}

#[derive(Debug, Error)]
pub enum AutoFixError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Default, Clone)]
pub struct AutoFixOutcome {
    pub planned: usize,
    pub applied: usize,
    pub skipped_no_match: usize,
    pub skipped_already_fixed: usize,
    pub previews: Vec<FixPreview>,
}

#[derive(Debug, Clone)]
pub struct FixPreview {
    pub path: PathBuf,
    pub line: usize,
    pub code: String,
    pub before: String,
    pub after: String,
}

pub fn lookup(code: &str, message: &str) -> Option<AutoFix> {
    match code {
        "RSTR-DES-002" => Some(AutoFix::new("yaml.load(", "yaml.safe_load(")),
        "RSTR-CRY-001" => match_md5(message),
        "RSTR-CRY-002" => match_sha1(message),
        _ => None,
    }
}

fn match_md5(message: &str) -> Option<AutoFix> {
    let _ = message;
    Some(AutoFix::new("MD5", "SHA-256"))
}

fn match_sha1(message: &str) -> Option<AutoFix> {
    let _ = message;
    Some(AutoFix::new("SHA-1", "SHA-256"))
}

pub fn rewrite_line(line: &str, code: &str) -> Option<String> {
    let mut out = line.to_string();
    let mut changed = false;
    for substitution in substitutions_for(code) {
        if out.contains(substitution.from) {
            out = out.replace(substitution.from, substitution.to);
            changed = true;
        }
    }
    if changed {
        Some(out)
    } else {
        None
    }
}

const SUBS_DES_002: &[AutoFix] = &[AutoFix::new("yaml.load(", "yaml.safe_load(")];

const SUBS_CRY_001: &[AutoFix] = &[
    AutoFix::new("hashlib.md5(", "hashlib.sha256("),
    AutoFix::new("createHash('md5')", "createHash('sha256')"),
    AutoFix::new("createHash(\"md5\")", "createHash(\"sha256\")"),
    AutoFix::new(
        "MessageDigest.getInstance(\"MD5\"",
        "MessageDigest.getInstance(\"SHA-256\"",
    ),
    AutoFix::new("md5.New()", "sha256.New()"),
    AutoFix::new("\"crypto/md5\"", "\"crypto/sha256\""),
    AutoFix::new("import \"crypto/md5\"", "import \"crypto/sha256\""),
];

const SUBS_CRY_002: &[AutoFix] = &[
    AutoFix::new("hashlib.sha1(", "hashlib.sha256("),
    AutoFix::new("createHash('sha1')", "createHash('sha256')"),
    AutoFix::new("createHash(\"sha1\")", "createHash(\"sha256\")"),
    AutoFix::new(
        "MessageDigest.getInstance(\"SHA-1\"",
        "MessageDigest.getInstance(\"SHA-256\"",
    ),
    AutoFix::new(
        "MessageDigest.getInstance(\"SHA1\"",
        "MessageDigest.getInstance(\"SHA-256\"",
    ),
    AutoFix::new("sha1.New()", "sha256.New()"),
    AutoFix::new("\"crypto/sha1\"", "\"crypto/sha256\""),
];

fn substitutions_for(code: &str) -> &'static [AutoFix] {
    match code {
        "RSTR-DES-002" => SUBS_DES_002,
        "RSTR-CRY-001" => SUBS_CRY_001,
        "RSTR-CRY-002" => SUBS_CRY_002,
        _ => &[],
    }
}

pub fn plan_and_apply(
    findings: &[Finding],
    workspace_root: &Path,
    apply: bool,
) -> Result<AutoFixOutcome, AutoFixError> {
    let mut by_file: BTreeMap<PathBuf, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        let Some(location) = &finding.location else {
            continue;
        };
        if substitutions_for(&finding.code).is_empty() {
            continue;
        }
        by_file
            .entry(location.file.clone())
            .or_default()
            .push(finding);
    }

    let mut outcome = AutoFixOutcome::default();

    for (file_path, file_findings) in by_file {
        let absolute = if file_path.is_absolute() {
            file_path.clone()
        } else {
            workspace_root.join(&file_path)
        };
        let original = match fs::read_to_string(&absolute) {
            Ok(text) => text,
            Err(source) => {
                return Err(AutoFixError::Read {
                    path: absolute,
                    source,
                });
            }
        };

        let mut lines: Vec<String> = original.split_inclusive('\n').map(String::from).collect();
        let mut file_changed = false;

        let mut sorted = file_findings.clone();
        sorted.sort_by_key(|f| f.location.as_ref().and_then(|l| l.line).unwrap_or(0));

        for finding in sorted {
            outcome.planned += 1;
            let Some(line_number) = finding
                .location
                .as_ref()
                .and_then(|loc| loc.line)
                .filter(|n| *n > 0)
            else {
                outcome.skipped_no_match += 1;
                continue;
            };
            let index = line_number - 1;
            if index >= lines.len() {
                outcome.skipped_no_match += 1;
                continue;
            }
            let before_line = lines[index].clone();
            let Some(after_line) = rewrite_line(&before_line, &finding.code) else {
                outcome.skipped_no_match += 1;
                continue;
            };
            if before_line == after_line {
                outcome.skipped_already_fixed += 1;
                continue;
            }
            outcome.previews.push(FixPreview {
                path: absolute.clone(),
                line: line_number,
                code: finding.code.clone(),
                before: before_line.trim_end_matches('\n').to_string(),
                after: after_line.trim_end_matches('\n').to_string(),
            });
            lines[index] = after_line;
            outcome.applied += 1;
            file_changed = true;
        }

        if apply && file_changed {
            let rewritten: String = lines.concat();
            fs::write(&absolute, rewritten).map_err(|source| AutoFixError::Write {
                path: absolute.clone(),
                source,
            })?;
        }
    }

    Ok(outcome)
}

pub fn print_previews(outcome: &AutoFixOutcome, applied: bool) {
    if outcome.previews.is_empty() {
        if applied {
            println!("[autofix] no fixable findings");
        } else {
            println!("[autofix] no fixable findings (run with --fix --yes to apply)");
        }
        return;
    }
    let verb = if applied { "applied" } else { "previewing" };
    println!("[autofix] {verb} {} fix(es)", outcome.previews.len());
    for preview in &outcome.previews {
        println!();
        println!(
            "{} {}:{} [{}]",
            if applied { "fixed" } else { "would fix" },
            preview.path.display(),
            preview.line,
            preview.code
        );
        println!("- {}", preview.before);
        println!("+ {}", preview.after);
    }
    if !applied {
        println!();
        println!("[autofix] re-run with --fix --yes to apply, or --fix --yes --baseline rastray.baseline.json to apply and re-baseline");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Severity;
    use crate::reporter::{Category, Location};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir() -> Option<PathBuf> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rastray-fix-test-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        match fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(_) => None,
        }
    }

    fn write_file(dir: &Path, name: &str, body: &str) -> Option<PathBuf> {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).ok()?;
        f.write_all(body.as_bytes()).ok()?;
        Some(path)
    }

    fn finding(code: &str, message: &str, path: &Path, line: usize) -> Finding {
        Finding::new(code, message, Severity::High, Category::Security)
            .with_location(Location::file(path.to_path_buf()).with_line(line, 1))
    }

    #[test]
    fn rewrites_yaml_load_to_safe_load() {
        let out = rewrite_line("cfg = yaml.load(open('a.yml'))\n", "RSTR-DES-002");
        assert_eq!(
            out.as_deref(),
            Some("cfg = yaml.safe_load(open('a.yml'))\n")
        );
    }

    #[test]
    fn rewrites_hashlib_md5_to_sha256() {
        let out = rewrite_line("h = hashlib.md5(payload).hexdigest()\n", "RSTR-CRY-001");
        assert_eq!(
            out.as_deref(),
            Some("h = hashlib.sha256(payload).hexdigest()\n")
        );
    }

    #[test]
    fn rewrites_node_create_hash_md5_to_sha256() {
        let out = rewrite_line(
            "const h = crypto.createHash('md5').update(buf).digest('hex')\n",
            "RSTR-CRY-001",
        );
        assert_eq!(
            out.as_deref(),
            Some("const h = crypto.createHash('sha256').update(buf).digest('hex')\n")
        );
    }

    #[test]
    fn rewrites_hashlib_sha1_to_sha256() {
        let out = rewrite_line("h = hashlib.sha1(data).digest()\n", "RSTR-CRY-002");
        assert_eq!(out.as_deref(), Some("h = hashlib.sha256(data).digest()\n"));
    }

    #[test]
    fn rewrites_java_md5_message_digest() {
        let out = rewrite_line(
            "MessageDigest md = MessageDigest.getInstance(\"MD5\");\n",
            "RSTR-CRY-001",
        );
        assert_eq!(
            out.as_deref(),
            Some("MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n")
        );
    }

    #[test]
    fn returns_none_when_no_match_in_line() {
        let out = rewrite_line("print('hello')\n", "RSTR-DES-002");
        assert!(out.is_none());
    }

    #[test]
    fn returns_none_for_unknown_code() {
        let out = rewrite_line("yaml.load('x')\n", "RSTR-UNKNOWN-999");
        assert!(out.is_none());
    }

    #[test]
    fn lookup_returns_some_for_supported_codes() {
        assert!(lookup("RSTR-DES-002", "").is_some());
        assert!(lookup("RSTR-CRY-001", "").is_some());
        assert!(lookup("RSTR-CRY-002", "").is_some());
        assert!(lookup("RSTR-XSS-001", "").is_none());
    }

    #[test]
    fn plan_and_apply_dry_run_does_not_modify_file() {
        let Some(dir) = tempdir() else {
            return;
        };
        let Some(path) = write_file(&dir, "a.py", "h = hashlib.md5(x)\n") else {
            let _ = fs::remove_dir_all(&dir);
            return;
        };
        let findings = vec![finding("RSTR-CRY-001", "MD5 used for hashing", &path, 1)];
        let outcome = match plan_and_apply(&findings, &dir, false) {
            Ok(o) => o,
            Err(_) => {
                let _ = fs::remove_dir_all(&dir);
                return;
            }
        };
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.previews.len(), 1);
        let after = fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(after, "h = hashlib.md5(x)\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_and_apply_with_apply_true_writes_file() {
        let Some(dir) = tempdir() else {
            return;
        };
        let Some(path) = write_file(&dir, "a.py", "h = hashlib.md5(x)\n") else {
            let _ = fs::remove_dir_all(&dir);
            return;
        };
        let findings = vec![finding("RSTR-CRY-001", "MD5 used for hashing", &path, 1)];
        let outcome = match plan_and_apply(&findings, &dir, true) {
            Ok(o) => o,
            Err(_) => {
                let _ = fs::remove_dir_all(&dir);
                return;
            }
        };
        assert_eq!(outcome.applied, 1);
        let after = fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(after, "h = hashlib.sha256(x)\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_and_apply_handles_multiple_findings_per_file() {
        let Some(dir) = tempdir() else {
            return;
        };
        let body = "import hashlib\nh1 = hashlib.md5(x)\nh2 = hashlib.sha1(y)\n";
        let Some(path) = write_file(&dir, "a.py", body) else {
            let _ = fs::remove_dir_all(&dir);
            return;
        };
        let findings = vec![
            finding("RSTR-CRY-001", "MD5", &path, 2),
            finding("RSTR-CRY-002", "SHA-1", &path, 3),
        ];
        let outcome = match plan_and_apply(&findings, &dir, true) {
            Ok(o) => o,
            Err(_) => {
                let _ = fs::remove_dir_all(&dir);
                return;
            }
        };
        assert_eq!(outcome.applied, 2);
        let after = fs::read_to_string(&path).unwrap_or_default();
        assert!(after.contains("hashlib.sha256(x)"));
        assert!(after.contains("hashlib.sha256(y)"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_and_apply_skips_findings_without_location() {
        let Some(dir) = tempdir() else {
            return;
        };
        let findings = vec![Finding::new(
            "RSTR-CRY-001",
            "MD5",
            Severity::High,
            Category::Security,
        )];
        let outcome = match plan_and_apply(&findings, &dir, false) {
            Ok(o) => o,
            Err(_) => {
                let _ = fs::remove_dir_all(&dir);
                return;
            }
        };
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.planned, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_and_apply_skips_unsupported_rule_codes() {
        let Some(dir) = tempdir() else {
            return;
        };
        let Some(path) = write_file(&dir, "a.py", "fetch(req.body.url)\n") else {
            let _ = fs::remove_dir_all(&dir);
            return;
        };
        let findings = vec![finding("RSTR-SSRF-001", "SSRF", &path, 1)];
        let outcome = match plan_and_apply(&findings, &dir, false) {
            Ok(o) => o,
            Err(_) => {
                let _ = fs::remove_dir_all(&dir);
                return;
            }
        };
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.planned, 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
