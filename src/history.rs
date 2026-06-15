use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::modules::secrets::scan_text_for_secrets;
use crate::modules::AnalyzerError;
use crate::reporter::Finding;

#[derive(Debug, Error)]
pub enum HistoryScanError {
    #[error("git command not found on PATH; install git to use --history")]
    GitNotFound,

    #[error("scan path '{path}' is not inside a git repository")]
    NotARepo { path: PathBuf },

    #[error("git command failed: {stderr}")]
    GitFailed { stderr: String },

    #[error("secret pattern compilation failed: {0}")]
    Analyzer(#[from] AnalyzerError),
}

#[derive(Debug, Default, Clone)]
pub struct HistoryScanOptions {
    pub since: Option<String>,
    pub max_commits: Option<usize>,
}

#[derive(Debug, Default)]
pub struct HistoryScanStats {
    pub commits_walked: usize,
    pub blobs_scanned: usize,
}

pub struct HistoryScanResult {
    pub findings: Vec<Finding>,
    pub stats: HistoryScanStats,
}

pub fn scan_history(
    scan_root: &Path,
    opts: &HistoryScanOptions,
) -> Result<HistoryScanResult, HistoryScanError> {
    let canonical_root =
        std::fs::canonicalize(scan_root).unwrap_or_else(|_| scan_root.to_path_buf());
    let repo_root = locate_repo_root(&canonical_root)?;

    let commits = list_commits(&repo_root, opts)?;
    let mut findings = Vec::new();
    let mut blobs_scanned = 0usize;
    let mut seen_blob_paths: HashSet<(String, String)> = HashSet::new();

    for commit in &commits {
        let changed = changed_paths_in_commit(&repo_root, &commit.sha)?;
        for path in changed {
            let key = (commit.sha.clone(), path.clone());
            if !seen_blob_paths.insert(key) {
                continue;
            }
            let contents = match read_blob(&repo_root, &commit.sha, &path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if contents.is_empty() {
                continue;
            }
            blobs_scanned += 1;
            let synthetic = synthetic_history_path(&path, &commit.sha);
            let mut blob_findings = scan_text_for_secrets(&contents, synthetic)?;
            for f in &mut blob_findings {
                f.message = format!(
                    "{} (in {} @ {} by {})",
                    f.message,
                    path,
                    short_sha(&commit.sha),
                    commit.author
                );
            }
            findings.extend(blob_findings);
        }
    }

    Ok(HistoryScanResult {
        findings,
        stats: HistoryScanStats {
            commits_walked: commits.len(),
            blobs_scanned,
        },
    })
}

fn synthetic_history_path(blob_path: &str, sha: &str) -> PathBuf {
    PathBuf::from(format!("{blob_path}@{}", short_sha(sha)))
}

fn short_sha(sha: &str) -> &str {
    if sha.len() >= 7 {
        &sha[..7]
    } else {
        sha
    }
}

struct CommitMeta {
    sha: String,
    author: String,
}

fn list_commits(
    repo_root: &Path,
    opts: &HistoryScanOptions,
) -> Result<Vec<CommitMeta>, HistoryScanError> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_root)
        .arg("log")
        .arg("--no-merges")
        .arg("--pretty=format:%H%x1f%an");
    if let Some(n) = opts.max_commits {
        cmd.arg(format!("--max-count={n}"));
    }
    if let Some(since) = &opts.since {
        cmd.arg(format!("{since}..HEAD"));
    }

    let output = run_git(cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut commits = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '\u{1f}');
        let sha = match parts.next() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let author = parts.next().unwrap_or("unknown").to_string();
        commits.push(CommitMeta { sha, author });
    }
    Ok(commits)
}

fn changed_paths_in_commit(repo_root: &Path, sha: &str) -> Result<Vec<String>, HistoryScanError> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_root)
        .arg("diff-tree")
        .arg("--no-commit-id")
        .arg("--name-only")
        .arg("-r")
        .arg("--diff-filter=AM")
        .arg(sha);
    let output = run_git(cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut paths = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            paths.push(trimmed.to_string());
        }
    }
    Ok(paths)
}

fn read_blob(repo_root: &Path, sha: &str, path: &str) -> Result<String, HistoryScanError> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_root)
        .arg("show")
        .arg(format!("{sha}:{path}"));
    let output = run_git(cmd)?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_git(mut cmd: Command) -> Result<std::process::Output, HistoryScanError> {
    let output = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            HistoryScanError::GitNotFound
        } else {
            HistoryScanError::GitFailed {
                stderr: err.to_string(),
            }
        }
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(HistoryScanError::GitFailed { stderr });
    }
    Ok(output)
}

fn locate_repo_root(start: &Path) -> Result<PathBuf, HistoryScanError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(start)
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                HistoryScanError::GitNotFound
            } else {
                HistoryScanError::GitFailed {
                    stderr: err.to_string(),
                }
            }
        })?;

    if !output.status.success() {
        return Err(HistoryScanError::NotARepo {
            path: start.to_path_buf(),
        });
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return Err(HistoryScanError::NotARepo {
            path: start.to_path_buf(),
        });
    }
    Ok(PathBuf::from(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_sha_truncates_to_seven_chars() {
        assert_eq!(short_sha("abcdef1234567890"), "abcdef1");
    }

    #[test]
    fn short_sha_keeps_short_input_intact() {
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn synthetic_history_path_includes_short_sha() {
        let p = synthetic_history_path("config/keys.env", "abcdef1234567890");
        assert_eq!(p.to_string_lossy(), "config/keys.env@abcdef1");
    }
}
