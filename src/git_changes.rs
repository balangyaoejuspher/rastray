use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitChangesError {
    #[error("git command not found on PATH; install git or drop --since/--changed-only")]
    GitNotFound,

    #[error("git diff failed for ref '{reference}': {stderr}")]
    GitFailed { reference: String, stderr: String },

    #[error("scan path '{path}' is not inside a git repository")]
    NotARepo { path: PathBuf },
}

pub fn changed_files_since(
    scan_root: &Path,
    reference: &str,
) -> Result<HashSet<PathBuf>, GitChangesError> {
    let canonical_root =
        std::fs::canonicalize(scan_root).unwrap_or_else(|_| scan_root.to_path_buf());

    let repo_root = locate_repo_root(&canonical_root)?;

    let output = Command::new("git")
        .arg("-C")
        .arg(&repo_root)
        .arg("diff")
        .arg("--name-only")
        .arg("--diff-filter=AMRT")
        .arg(reference)
        .arg("HEAD")
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                GitChangesError::GitNotFound
            } else {
                GitChangesError::GitFailed {
                    reference: reference.to_string(),
                    stderr: err.to_string(),
                }
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(GitChangesError::GitFailed {
            reference: reference.to_string(),
            stderr,
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut paths = HashSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let absolute = repo_root.join(trimmed);
        let normalized = std::fs::canonicalize(&absolute).unwrap_or(absolute);
        paths.insert(normalized);
    }
    Ok(paths)
}

fn locate_repo_root(start: &Path) -> Result<PathBuf, GitChangesError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(start)
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                GitChangesError::GitNotFound
            } else {
                GitChangesError::GitFailed {
                    reference: "rev-parse".to_string(),
                    stderr: err.to_string(),
                }
            }
        })?;

    if !output.status.success() {
        return Err(GitChangesError::NotARepo {
            path: start.to_path_buf(),
        });
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return Err(GitChangesError::NotARepo {
            path: start.to_path_buf(),
        });
    }
    Ok(PathBuf::from(raw))
}

pub fn resolve_reference(since: Option<&str>, changed_only: bool) -> Option<String> {
    if let Some(reference) = since {
        return Some(reference.to_string());
    }
    if changed_only {
        return Some("HEAD~1".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_reference_prefers_explicit_since() {
        assert_eq!(
            resolve_reference(Some("origin/main"), true),
            Some("origin/main".to_string())
        );
    }

    #[test]
    fn resolve_reference_defaults_to_head_minus_one_for_changed_only() {
        assert_eq!(resolve_reference(None, true), Some("HEAD~1".to_string()));
    }

    #[test]
    fn resolve_reference_is_none_when_nothing_set() {
        assert_eq!(resolve_reference(None, false), None);
    }

    #[test]
    fn resolve_reference_passes_through_short_refs() {
        assert_eq!(
            resolve_reference(Some("abc1234"), false),
            Some("abc1234".to_string())
        );
    }
}
