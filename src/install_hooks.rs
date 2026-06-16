use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum InstallHooksError {
    #[error("git command not found on PATH; install git to run install-hooks")]
    GitNotFound,

    #[error("scan path '{path}' is not inside a git repository")]
    NotARepo { path: PathBuf },

    #[error("git command failed: {stderr}")]
    GitFailed { stderr: String },

    #[error(
        "{path} already exists; pass --force to overwrite (current contents are not\
         clobbered without explicit consent)"
    )]
    HookAlreadyExists { path: PathBuf },

    #[error("failed to write hook file '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub struct InstallHooksOutcome {
    pub hook_path: PathBuf,
    pub hooks_dir: PathBuf,
    pub repo_root: PathBuf,
    pub overwrote: bool,
}

const HOOK_BODY: &str = "#!/bin/sh
# rastray pre-commit hook (managed by `rastray install-hooks`).
# Blocks the commit on any High or Critical finding in the changed files.
# Override per-commit with `git commit --no-verify` if you must.

if ! command -v rastray >/dev/null 2>&1; then
    echo \"rastray not found on PATH; install via https://github.com/balangyaoejuspher/rastray#installation\" >&2
    exit 1
fi

exec rastray --changed-only --fail-on high
";

pub fn install_hooks(
    scan_path: &Path,
    force: bool,
) -> Result<InstallHooksOutcome, InstallHooksError> {
    let canonical = std::fs::canonicalize(scan_path).unwrap_or_else(|_| scan_path.to_path_buf());
    let repo_root = locate_repo_root(&canonical)?;
    let hooks_dir = repo_root.join(".githooks");
    let hook_path = hooks_dir.join("pre-commit");

    let already_exists = hook_path.exists();
    if already_exists && !force {
        return Err(InstallHooksError::HookAlreadyExists { path: hook_path });
    }

    std::fs::create_dir_all(&hooks_dir).map_err(|source| InstallHooksError::Io {
        path: hooks_dir.clone(),
        source,
    })?;
    std::fs::write(&hook_path, HOOK_BODY).map_err(|source| InstallHooksError::Io {
        path: hook_path.clone(),
        source,
    })?;
    set_executable_unix(&hook_path)?;

    set_core_hooks_path(&repo_root)?;

    Ok(InstallHooksOutcome {
        hook_path,
        hooks_dir,
        repo_root,
        overwrote: already_exists,
    })
}

#[cfg(unix)]
fn set_executable_unix(path: &Path) -> Result<(), InstallHooksError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|source| InstallHooksError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).map_err(|source| InstallHooksError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable_unix(_path: &Path) -> Result<(), InstallHooksError> {
    Ok(())
}

fn set_core_hooks_path(repo_root: &Path) -> Result<(), InstallHooksError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("config")
        .arg("core.hooksPath")
        .arg(".githooks")
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                InstallHooksError::GitNotFound
            } else {
                InstallHooksError::GitFailed {
                    stderr: err.to_string(),
                }
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(InstallHooksError::GitFailed { stderr });
    }
    Ok(())
}

fn locate_repo_root(start: &Path) -> Result<PathBuf, InstallHooksError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(start)
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                InstallHooksError::GitNotFound
            } else {
                InstallHooksError::GitFailed {
                    stderr: err.to_string(),
                }
            }
        })?;

    if !output.status.success() {
        return Err(InstallHooksError::NotARepo {
            path: start.to_path_buf(),
        });
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return Err(InstallHooksError::NotARepo {
            path: start.to_path_buf(),
        });
    }
    Ok(PathBuf::from(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_body_starts_with_shebang() {
        assert!(HOOK_BODY.starts_with("#!/bin/sh"));
    }

    #[test]
    fn hook_body_invokes_rastray_with_correct_flags() {
        assert!(HOOK_BODY.contains("rastray --changed-only --fail-on high"));
    }

    #[test]
    fn hook_body_falls_back_with_clear_message_when_rastray_missing() {
        assert!(HOOK_BODY.contains("rastray not found on PATH"));
        assert!(HOOK_BODY.contains("exit 1"));
    }
}
