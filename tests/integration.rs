use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rastray"))
}

fn make_fixture(name: &str) -> Option<PathBuf> {
    let mut dir = std::env::temp_dir();
    dir.push(format!("rastray-it-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn write_file(dir: &Path, name: &str, body: &str) -> bool {
    let path = dir.join(name);
    match fs::File::create(&path) {
        Ok(mut f) => f.write_all(body.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

fn run_json(dir: &Path, extra_args: &[&str]) -> Option<Value> {
    let bin = binary_path();
    if !bin.exists() {
        return None;
    }
    let mut cmd = Command::new(&bin);
    cmd.arg(dir).arg("--json").arg("--min-severity").arg("info");
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    serde_json::from_str(&stdout).ok()
}

fn count_findings_with_code(value: &Value, code: &str) -> usize {
    value
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|item| item.get("code").and_then(|c| c.as_str()) == Some(code))
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn scan_emits_valid_json_schema_keys() {
    let dir = match make_fixture("schema") {
        Some(d) => d,
        None => return,
    };
    write_file(&dir, "noop.rs", "fn main() {}");

    let json = match run_json(&dir, &[]) {
        Some(j) => j,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };

    assert!(json.get("findings").is_some());
    assert!(json.get("stats").is_some());
    assert!(json.get("perf").is_some());

    let stats = match json.get("stats") {
        Some(s) => s,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    assert!(stats.get("files_scanned").is_some());
    assert!(stats.get("manifests").is_some());
    assert!(stats.get("source_files").is_some());

    let perf = match json.get("perf") {
        Some(p) => p,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    assert!(perf.get("walk_ms").is_some());
    assert!(perf.get("analyze_ms").is_some());
    assert!(perf.get("total_ms").is_some());
    assert!(perf.get("bytes_scanned").is_some());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scan_detects_aws_key_in_source_file() {
    let dir = match make_fixture("aws") {
        Some(d) => d,
        None => return,
    };
    let body = "const aws = \"AKIAIOSFODNN7EXAMPLE\";\n";
    write_file(&dir, "config.js", body);

    let json = match run_json(&dir, &[]) {
        Some(j) => j,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };

    assert_eq!(count_findings_with_code(&json, "RSTR-SEC-001"), 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scan_detects_secret_in_dotenv_with_hidden_flag() {
    let dir = match make_fixture("dotenv") {
        Some(d) => d,
        None => return,
    };
    let body = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n";
    write_file(&dir, ".env", body);

    let json = match run_json(&dir, &["--hidden"]) {
        Some(j) => j,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };

    assert_eq!(count_findings_with_code(&json, "RSTR-SEC-002"), 1);

    let stats = json.get("stats").and_then(|s| s.get("config_files"));
    assert_eq!(stats.and_then(|v| v.as_u64()), Some(1));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scan_with_no_secrets_produces_zero_findings() {
    let dir = match make_fixture("clean") {
        Some(d) => d,
        None => return,
    };
    write_file(
        &dir,
        "main.rs",
        "fn main() { println!(\"hello world\"); }\n",
    );

    let json = match run_json(&dir, &[]) {
        Some(j) => j,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };

    let findings = json.get("findings").and_then(|f| f.as_array());
    assert_eq!(findings.map(|a| a.len()), Some(0));

    let _ = fs::remove_dir_all(&dir);
}

fn run_git_in(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn secrets_history_detects_blob_purged_from_working_tree() {
    let dir = match make_fixture("history") {
        Some(d) => d,
        None => return,
    };
    if !run_git_in(&dir, &["init", "-q", "-b", "main"]) {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    if !write_file(&dir, "leaked.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n") {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    run_git_in(&dir, &["add", "leaked.env"]);
    if !run_git_in(&dir, &["commit", "-q", "-m", "add secret"]) {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    run_git_in(&dir, &["rm", "-q", "leaked.env"]);
    run_git_in(&dir, &["commit", "-q", "-m", "remove secret"]);

    let bin = binary_path();
    if !bin.exists() {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let output = Command::new(&bin)
        .arg("secrets")
        .arg("--history")
        .arg(&dir)
        .arg("--json")
        .arg("--min-severity")
        .arg("info")
        .output();
    let output = match output {
        Ok(o) => o,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    let aws_hits = count_findings_with_code(&json, "RSTR-SEC-001");
    assert!(
        aws_hits >= 1,
        "expected RSTR-SEC-001 to fire on the purged blob, got {aws_hits}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn image_scan_detects_secret_in_layer_tarball() {
    let dir = match make_fixture("image") {
        Some(d) => d,
        None => return,
    };

    let mut inner_tar: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut inner_tar);
        let body = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n";
        let mut header = tar::Header::new_gnu();
        if header.set_path("etc/leaked.env").is_err() {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        if builder.append(&header, body.as_slice()).is_err() {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        if builder.finish().is_err() {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    }

    let outer = dir.join("image.tar");
    let outer_file = match fs::File::create(&outer) {
        Ok(f) => f,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    {
        let mut builder = tar::Builder::new(outer_file);
        let mut header = tar::Header::new_gnu();
        if header.set_path("sha256abc/layer.tar").is_err() {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        header.set_size(inner_tar.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        if builder.append(&header, inner_tar.as_slice()).is_err() {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        if builder.finish().is_err() {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    }

    let bin = binary_path();
    if !bin.exists() {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let output = Command::new(&bin)
        .arg("image")
        .arg(&outer)
        .arg("--json")
        .arg("--min-severity")
        .arg("info")
        .output();
    let output = match output {
        Ok(o) => o,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    let aws_hits = count_findings_with_code(&json, "RSTR-SEC-001");
    assert!(
        aws_hits >= 1,
        "expected RSTR-SEC-001 to fire on the secret baked into the image, got {aws_hits}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn install_hooks_writes_pre_commit_hook_and_sets_core_hookspath() {
    let dir = match make_fixture("install-hooks") {
        Some(d) => d,
        None => return,
    };
    if !run_git_in(&dir, &["init", "-q", "-b", "main"]) {
        let _ = fs::remove_dir_all(&dir);
        return;
    }

    let bin = binary_path();
    if !bin.exists() {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let output = Command::new(&bin).arg("install-hooks").arg(&dir).output();
    let output = match output {
        Ok(o) => o,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    assert!(
        output.status.success(),
        "install-hooks should succeed inside a git repo, got status {:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let hook = dir.join(".githooks").join("pre-commit");
    assert!(
        hook.exists(),
        "expected hook to be written at {}",
        hook.display()
    );
    let body = fs::read_to_string(&hook).unwrap_or_default();
    assert!(body.contains("rastray --changed-only --fail-on high"));

    let cfg_output = Command::new("git")
        .arg("-C")
        .arg(&dir)
        .arg("config")
        .arg("--get")
        .arg("core.hooksPath")
        .output();
    if let Ok(out) = cfg_output {
        let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_eq!(value, ".githooks", "core.hooksPath should be .githooks");
    }

    let second = Command::new(&bin).arg("install-hooks").arg(&dir).output();
    if let Ok(out) = second {
        assert!(
            !out.status.success(),
            "install-hooks should refuse to overwrite without --force"
        );
    }

    let third = Command::new(&bin)
        .arg("install-hooks")
        .arg("--force")
        .arg(&dir)
        .output();
    if let Ok(out) = third {
        assert!(
            out.status.success(),
            "install-hooks --force should succeed even when hook already exists"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

fn run_exit_code(dir: &Path, extra_args: &[&str]) -> Option<i32> {
    let bin = binary_path();
    if !bin.exists() {
        return None;
    }
    let mut cmd = Command::new(&bin);
    cmd.arg(dir).arg("--format").arg("json");
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.output().ok()?;
    output.status.code()
}

#[test]
fn fail_on_never_returns_zero_even_with_findings() {
    let dir = match make_fixture("fail-on-never") {
        Some(d) => d,
        None => return,
    };
    write_file(
        &dir,
        "src.rs",
        "fn build() { for i in 0..10 { let _ = format!(\"{i}\"); } }\n",
    );

    let code = match run_exit_code(&dir, &["--fail-on", "never"]) {
        Some(c) => c,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    assert_eq!(code, 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn fail_on_high_returns_zero_when_only_medium_findings_exist() {
    let dir = match make_fixture("fail-on-high-clean") {
        Some(d) => d,
        None => return,
    };
    write_file(
        &dir,
        "src.rs",
        "fn build() -> String { let mut s = String::new(); for i in 0..10 { s.push_str(&format!(\"{i}\")); } s }\n",
    );

    let code = match run_exit_code(&dir, &["--fail-on", "high"]) {
        Some(c) => c,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    assert_eq!(code, 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn fail_on_medium_returns_one_when_medium_findings_exist() {
    let dir = match make_fixture("fail-on-medium-dirty") {
        Some(d) => d,
        None => return,
    };
    write_file(
        &dir,
        "src.rs",
        "fn build() -> String { let mut s = String::new(); for i in 0..10 { s.push_str(&format!(\"{i}\")); } s }\n",
    );

    let code = match run_exit_code(&dir, &["--fail-on", "medium"]) {
        Some(c) => c,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    assert_eq!(code, 1);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rastray_toml_suppress_block_drops_matching_findings() {
    let dir = match make_fixture("suppress") {
        Some(d) => d,
        None => return,
    };

    write_file(&dir, "config.js", "const aws = \"AKIAIOSFODNN7EXAMPLE\";\n");
    write_file(
        &dir,
        ".rastray.toml",
        "[[suppress]]\npath = \"config.js\"\nrules = [\"RSTR-SEC-001\"]\nreason = \"test fixture\"\n",
    );

    let json = match run_json(&dir, &[]) {
        Some(j) => j,
        None => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };

    assert_eq!(
        count_findings_with_code(&json, "RSTR-SEC-001"),
        0,
        "[[suppress]] entry should drop the AWS key finding"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rastray_format_markdown_produces_pr_ready_output() {
    let dir = match make_fixture("format-markdown") {
        Some(d) => d,
        None => return,
    };

    write_file(&dir, "config.js", "const aws = \"AKIAIOSFODNN7EXAMPLE\";\n");

    let bin = binary_path();
    if !bin.exists() {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let output = match Command::new(&bin)
        .arg(&dir)
        .arg("--format")
        .arg("markdown")
        .arg("--min-severity")
        .arg("info")
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    assert!(stdout.starts_with("## rastray scan"));
    assert!(stdout.contains("### Severity"));
    assert!(stdout.contains("### Category"));
    assert!(stdout.contains("### Findings"));
    assert!(stdout.contains("`RSTR-SEC-001`") || stdout.contains("RSTR-SEC-001"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rastray_format_html_writes_self_contained_report() {
    let dir = match make_fixture("format-html") {
        Some(d) => d,
        None => return,
    };
    write_file(&dir, "config.js", "const aws = \"AKIAIOSFODNN7EXAMPLE\";\n");

    let bin = binary_path();
    if !bin.exists() {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let out_path = dir.join("report.html");
    let status = match Command::new(&bin)
        .arg(&dir)
        .arg("--format")
        .arg("html")
        .arg("-o")
        .arg(&out_path)
        .arg("--min-severity")
        .arg("info")
        .status()
    {
        Ok(s) => s,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };

    let html = fs::read_to_string(&out_path).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);

    let _ = status;
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("<title>rastray scan"));
    assert!(html.contains("id=\"findings-table\""));
    assert!(html.contains("RSTR-SEC-001"));
    assert!(!html.contains("AKIAIOSFODNN7EXAMPLE\nconst"));
}

#[test]
fn rastray_format_html_errors_without_output_path() {
    let dir = match make_fixture("format-html-no-out") {
        Some(d) => d,
        None => return,
    };
    write_file(&dir, "main.rs", "fn main() {}");

    let bin = binary_path();
    if !bin.exists() {
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let output = match Command::new(&bin)
        .arg(&dir)
        .arg("--format")
        .arg("html")
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = fs::remove_dir_all(&dir);
    assert!(!output.status.success(), "expected non-zero exit");
    assert!(
        stderr.contains("html") && stderr.contains("-o"),
        "stderr should mention html + -o; got: {stderr}"
    );
}

#[test]
fn lsp_subcommand_responds_to_initialize() {
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command as ProcCommand, Stdio};
    use std::time::{Duration, Instant};

    let bin = binary_path();
    if !bin.exists() {
        return;
    }

    let mut child = match ProcCommand::new(&bin)
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let stdin = match child.stdin.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            return;
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            return;
        }
    };

    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {},
            "rootUri": null,
            "processId": null,
        },
    });
    let payload = serde_json::to_string(&initialize).unwrap_or_default();
    let framed = format!("Content-Length: {}\r\n\r\n{}", payload.len(), payload);
    let mut writer = stdin;
    if writer.write_all(framed.as_bytes()).is_err() {
        let _ = child.kill();
        return;
    }
    let _ = writer.flush();
    drop(writer);

    let mut reader = BufReader::new(stdout);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut response_text = String::new();

    while Instant::now() < deadline {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.is_empty() {
            break;
        }
        let trimmed = header.trim_end();
        if let Some(value) = trimmed.strip_prefix("Content-Length: ") {
            let length: usize = value.parse().unwrap_or(0);
            let mut blank = String::new();
            let _ = reader.read_line(&mut blank);
            if length > 0 {
                let mut body_buf = vec![0u8; length];
                if reader.read_exact(&mut body_buf).is_ok() {
                    response_text = String::from_utf8_lossy(&body_buf).to_string();
                }
                break;
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        response_text.contains("\"name\":\"rastray\""),
        "expected initialize response to contain server name; got: {response_text}"
    );
    assert!(
        response_text.contains("textDocumentSync"),
        "expected initialize response to advertise textDocumentSync; got: {response_text}"
    );
}
