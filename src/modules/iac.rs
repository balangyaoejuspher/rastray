use std::fs;
use std::sync::OnceLock;

use regex::Regex;

use crate::cli::Severity;
use crate::crawler::CrawlSummary;
use crate::reporter::{Category, Finding, Location};

use super::{Analyzer, AnalyzerError};

#[derive(Debug, Default)]
pub struct IacAnalyzer;

impl IacAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for IacAnalyzer {
    fn name(&self) -> &'static str {
        "iac"
    }

    fn wants(&self, crawl: &CrawlSummary) -> bool {
        crawl.files.iter().any(|f| {
            if is_dockerfile(&f.path) || is_terraform_file(&f.path) {
                return true;
            }
            f.path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
    }

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
        let docker_patterns = compiled_docker_patterns()?;
        let k8s_patterns = compiled_k8s_patterns()?;
        let tf_patterns = compiled_tf_patterns()?;
        let mut findings = Vec::new();
        for file in &crawl.files {
            let contents = match fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let target_patterns: &[CompiledPattern] = if is_dockerfile(&file.path) {
                docker_patterns
            } else if is_terraform_file(&file.path) {
                tf_patterns
            } else if is_kubernetes_manifest(&file.path, &contents) {
                k8s_patterns
            } else {
                continue;
            };
            for pattern in target_patterns {
                for m in pattern.regex.find_iter(&contents) {
                    let (line, column) = byte_offset_to_line_col(&contents, m.start());
                    let location = Location::file(file.path.clone())
                        .with_span(m.start(), m.len())
                        .with_line(line, column);
                    findings.push(
                        Finding::new(
                            pattern.code,
                            pattern.message.to_string(),
                            pattern.severity,
                            Category::Security,
                        )
                        .with_help(pattern.help)
                        .with_location(location),
                    );
                }
            }
        }
        Ok(findings)
    }
}

fn is_dockerfile(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower == "dockerfile"
        || lower == "containerfile"
        || lower.starts_with("dockerfile.")
        || lower.ends_with(".dockerfile")
}

fn is_terraform_file(path: &std::path::Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = ext.to_ascii_lowercase();
    lower == "tf" || lower == "tfvars"
}

fn is_kubernetes_manifest(path: &std::path::Path, contents: &str) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = ext.to_ascii_lowercase();
    if lower != "yaml" && lower != "yml" {
        return false;
    }
    let Some(re) = k8s_manifest_signature() else {
        return false;
    };
    let head: String = contents.lines().take(80).collect::<Vec<_>>().join("\n");
    re.is_match(&head)
}

fn k8s_manifest_signature() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^\s*apiVersion:\s*\S[\s\S]*?^\s*kind:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet|ReplicationController)\b",
        )
        .ok()
    })
    .as_ref()
}

struct PatternSpec {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    pattern: &'static str,
}

struct CompiledPattern {
    code: &'static str,
    message: &'static str,
    severity: Severity,
    help: &'static str,
    regex: Regex,
}

const DOCKER_PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-IAC-001",
        message: "image tag ':latest'; pulls a moving target and breaks build reproducibility",
        severity: Severity::Medium,
        help: "pin to a specific tag (alpine:3.20) or a digest (alpine@sha256:...)",
        pattern: r"(?im)^\s*FROM\s+\S+:latest\b",
    },
    PatternSpec {
        code: "RSTR-IAC-001",
        message: "FROM directive uses no tag; defaults to :latest",
        severity: Severity::Medium,
        help: "pin to a specific tag or @sha256: digest",
        pattern: r"(?im)^\s*FROM\s+[^:@\s]+\s*$",
    },
    PatternSpec {
        code: "RSTR-IAC-002",
        message: "explicit USER root; container will run privileged",
        severity: Severity::High,
        help: "switch to a non-root USER for the runtime stage, or omit and rely on the base image's default",
        pattern: r"(?im)^\s*USER\s+root\s*$",
    },
    PatternSpec {
        code: "RSTR-IAC-003",
        message: "ADD with a remote URL; bypasses caching, no checksum verification, and may follow redirects",
        severity: Severity::Medium,
        help: "use RUN curl -fsSL <url> -o <file> with a sha256sum check instead",
        pattern: r"(?im)^\s*ADD\s+https?://",
    },
    PatternSpec {
        code: "RSTR-IAC-005",
        message: "chmod 777 grants world-writable permissions; rarely correct",
        severity: Severity::High,
        help: "use the minimum permissions needed (typically 0755 for dirs, 0644 for files)",
        pattern: r"\bchmod\s+(0?)777\b",
    },
    PatternSpec {
        code: "RSTR-IAC-006",
        message: "curl|sh pattern pipes remote content into a shell; no signature check and TLS failure becomes a silent compromise",
        severity: Severity::High,
        help: "download the script, inspect/verify it (gpg, sha256), then execute",
        pattern: r"(?i)curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b",
    },
];

const K8S_PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-IAC-007",
        message: "Kubernetes container runs with `privileged: true`; grants full host-level capabilities",
        severity: Severity::High,
        help: "drop `privileged: true` and request only the specific capabilities you actually need under `securityContext.capabilities.add`",
        pattern: r"(?m)^\s*privileged:\s*true\b",
    },
    PatternSpec {
        code: "RSTR-IAC-008",
        message: "PodSpec shares a host namespace (`hostNetwork`, `hostPID`, or `hostIPC` is true); breaks isolation between the container and the node",
        severity: Severity::High,
        help: "remove the host* flag; if you genuinely need host access, document the threat model and pin the workload to a dedicated node pool",
        pattern: r"(?m)^\s*host(?:Network|PID|IPC):\s*true\b",
    },
];

const TF_PATTERN_SPECS: &[PatternSpec] = &[
    PatternSpec {
        code: "RSTR-IAC-009",
        message: "Terraform sets `acl = \"public-read\"` (or `public-read-write`); the bucket is world-readable",
        severity: Severity::High,
        help: "use `acl = \"private\"` and a `aws_s3_bucket_policy` for any explicit cross-account / public access",
        pattern: r#"(?i)\bacl\s*=\s*"public-read(?:-write)?""#,
    },
    PatternSpec {
        code: "RSTR-IAC-010",
        message: "Terraform allows ingress from `0.0.0.0/0`; the resource is reachable from the entire internet",
        severity: Severity::Critical,
        help: "narrow `cidr_blocks` to the office/VPN range, or front the service with a load balancer and tighten the security-group rules",
        pattern: r#"(?m)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0""#,
    },
    PatternSpec {
        code: "RSTR-IAC-011",
        message: "Terraform sets `publicly_accessible = true` on a database; the DB endpoint is exposed to the internet",
        severity: Severity::High,
        help: "set `publicly_accessible = false` and connect via private networking (VPC peering, PrivateLink, or VPN)",
        pattern: r"(?m)\bpublicly_accessible\s*=\s*true\b",
    },
];

static DOCKER_PATTERNS: OnceLock<Result<Vec<CompiledPattern>, regex::Error>> = OnceLock::new();
static K8S_PATTERNS: OnceLock<Result<Vec<CompiledPattern>, regex::Error>> = OnceLock::new();
static TF_PATTERNS: OnceLock<Result<Vec<CompiledPattern>, regex::Error>> = OnceLock::new();

fn compile_specs(
    cache: &'static OnceLock<Result<Vec<CompiledPattern>, regex::Error>>,
    specs: &'static [PatternSpec],
) -> Result<&'static [CompiledPattern], AnalyzerError> {
    let cached = cache.get_or_init(|| {
        specs
            .iter()
            .map(|spec| {
                Regex::new(spec.pattern).map(|regex| CompiledPattern {
                    code: spec.code,
                    message: spec.message,
                    severity: spec.severity,
                    help: spec.help,
                    regex,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    });
    match cached {
        Ok(v) => Ok(v.as_slice()),
        Err(e) => Err(AnalyzerError::Failed {
            name: "iac",
            message: format!("failed to compile a builtin iac pattern: {e}"),
        }),
    }
}

fn compiled_docker_patterns() -> Result<&'static [CompiledPattern], AnalyzerError> {
    compile_specs(&DOCKER_PATTERNS, DOCKER_PATTERN_SPECS)
}

fn compiled_k8s_patterns() -> Result<&'static [CompiledPattern], AnalyzerError> {
    compile_specs(&K8S_PATTERNS, K8S_PATTERN_SPECS)
}

fn compiled_tf_patterns() -> Result<&'static [CompiledPattern], AnalyzerError> {
    compile_specs(&TF_PATTERNS, TF_PATTERN_SPECS)
}

fn byte_offset_to_line_col(text: &str, offset: usize) -> (usize, usize) {
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
    use std::path::PathBuf;

    #[test]
    fn compiled_patterns_compile_cleanly() {
        assert!(compiled_docker_patterns().is_ok());
        assert!(compiled_k8s_patterns().is_ok());
        assert!(compiled_tf_patterns().is_ok());
    }

    #[test]
    fn is_dockerfile_recognises_canonical_and_variant_names() {
        assert!(is_dockerfile(&PathBuf::from("Dockerfile")));
        assert!(is_dockerfile(&PathBuf::from("dockerfile")));
        assert!(is_dockerfile(&PathBuf::from("Dockerfile.dev")));
        assert!(is_dockerfile(&PathBuf::from("Containerfile")));
        assert!(is_dockerfile(&PathBuf::from("dev.dockerfile")));
        assert!(!is_dockerfile(&PathBuf::from("Makefile")));
        assert!(!is_dockerfile(&PathBuf::from("docker-compose.yml")));
    }

    #[test]
    fn is_terraform_file_recognises_tf_and_tfvars() {
        assert!(is_terraform_file(&PathBuf::from("main.tf")));
        assert!(is_terraform_file(&PathBuf::from("variables.TF")));
        assert!(is_terraform_file(&PathBuf::from("prod.tfvars")));
        assert!(!is_terraform_file(&PathBuf::from("main.tfstate")));
        assert!(!is_terraform_file(&PathBuf::from("README.md")));
    }

    #[test]
    fn is_kubernetes_manifest_requires_apiversion_and_kind() {
        let manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n";
        assert!(is_kubernetes_manifest(&PathBuf::from("dep.yaml"), manifest));
        let pod = "apiVersion: v1\nkind: Pod\n";
        assert!(is_kubernetes_manifest(&PathBuf::from("pod.yml"), pod));
        let configmap = "apiVersion: v1\nkind: ConfigMap\n";
        assert!(!is_kubernetes_manifest(
            &PathBuf::from("cm.yaml"),
            configmap
        ));
        let not_yaml = "apiVersion: v1\nkind: Pod\n";
        assert!(!is_kubernetes_manifest(&PathBuf::from("pod.txt"), not_yaml));
        let plain_yaml = "foo: bar\nbaz: qux\n";
        assert!(!is_kubernetes_manifest(
            &PathBuf::from("cfg.yaml"),
            plain_yaml
        ));
    }

    fn docker_regex(code: &str, message_substring: &str) -> Option<&'static Regex> {
        let patterns = compiled_docker_patterns().ok()?;
        patterns
            .iter()
            .find(|p| p.code == code && p.message.contains(message_substring))
            .map(|p| &p.regex)
    }

    fn docker_regex_by_code(code: &str) -> Option<&'static Regex> {
        let patterns = compiled_docker_patterns().ok()?;
        patterns.iter().find(|p| p.code == code).map(|p| &p.regex)
    }

    fn k8s_regex(code: &str) -> Option<&'static Regex> {
        let patterns = compiled_k8s_patterns().ok()?;
        patterns.iter().find(|p| p.code == code).map(|p| &p.regex)
    }

    fn tf_regex(code: &str) -> Option<&'static Regex> {
        let patterns = compiled_tf_patterns().ok()?;
        patterns.iter().find(|p| p.code == code).map(|p| &p.regex)
    }

    #[test]
    fn from_latest_matches() {
        let re = docker_regex("RSTR-IAC-001", "latest");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("FROM alpine:latest\n"));
            assert!(re.is_match("FROM node:latest\nRUN npm i\n"));
            assert!(!re.is_match("FROM alpine:3.20\n"));
        }
    }

    #[test]
    fn user_root_matches() {
        let re = docker_regex_by_code("RSTR-IAC-002");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("FROM alpine\nUSER root\n"));
            assert!(!re.is_match("FROM alpine\nUSER appuser\n"));
        }
    }

    #[test]
    fn add_remote_url_matches() {
        let re = docker_regex_by_code("RSTR-IAC-003");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("ADD https://example.com/get.sh /tmp/\n"));
            assert!(!re.is_match("ADD ./local-file /tmp/\n"));
        }
    }

    #[test]
    fn chmod_777_matches() {
        let re = docker_regex_by_code("RSTR-IAC-005");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("RUN chmod 777 /tmp/foo\n"));
            assert!(re.is_match("RUN chmod 0777 /tmp/foo\n"));
            assert!(!re.is_match("RUN chmod 755 /usr/bin/app\n"));
        }
    }

    #[test]
    fn curl_pipe_sh_matches() {
        let re = docker_regex_by_code("RSTR-IAC-006");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("RUN curl -fsSL https://get.example.com | bash\n"));
            assert!(re.is_match("RUN curl https://get.example.com | sudo sh\n"));
            assert!(!re.is_match("RUN curl -fsSL https://get.example.com -o /tmp/get.sh\n"));
        }
    }

    #[test]
    fn k8s_privileged_true_matches() {
        let re = k8s_regex("RSTR-IAC-007");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("    securityContext:\n      privileged: true\n"));
            assert!(re.is_match("        privileged: true\n"));
            assert!(!re.is_match("        privileged: false\n"));
            assert!(!re.is_match("        allowPrivilegeEscalation: true\n"));
        }
    }

    #[test]
    fn k8s_host_namespace_matches() {
        let re = k8s_regex("RSTR-IAC-008");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("spec:\n  hostNetwork: true\n"));
            assert!(re.is_match("  hostPID: true\n"));
            assert!(re.is_match("  hostIPC: true\n"));
            assert!(!re.is_match("  hostNetwork: false\n"));
            assert!(!re.is_match("  hostname: example\n"));
        }
    }

    #[test]
    fn tf_public_acl_matches() {
        let re = tf_regex("RSTR-IAC-009");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match(r#"  acl = "public-read""#));
            assert!(re.is_match(r#"  acl   =   "public-read-write""#));
            assert!(!re.is_match(r#"  acl = "private""#));
            assert!(!re.is_match(r#"  acl = "authenticated-read""#));
        }
    }

    #[test]
    fn tf_open_cidr_matches() {
        let re = tf_regex("RSTR-IAC-010");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match(r#"  cidr_blocks = ["0.0.0.0/0"]"#));
            assert!(re.is_match(r#"cidr_blocks=[ "0.0.0.0/0"]"#));
            assert!(!re.is_match(r#"  cidr_blocks = ["10.0.0.0/8"]"#));
        }
    }

    #[test]
    fn tf_publicly_accessible_matches() {
        let re = tf_regex("RSTR-IAC-011");
        assert!(re.is_some());
        if let Some(re) = re {
            assert!(re.is_match("  publicly_accessible = true"));
            assert!(re.is_match("publicly_accessible=true"));
            assert!(!re.is_match("  publicly_accessible = false"));
        }
    }

    fn crawl_with(files: Vec<PathBuf>) -> CrawlSummary {
        use crate::crawler::FileKind;
        CrawlSummary {
            files: files
                .into_iter()
                .map(|p| crate::crawler::DiscoveredFile {
                    path: p,
                    kind: FileKind::Source,
                    size: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn wants_returns_false_without_iac_files() {
        let crawl = crawl_with(vec!["src/lib.rs".into(), "README.md".into()]);
        assert!(!IacAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_for_dockerfile() {
        let crawl = crawl_with(vec!["Dockerfile".into()]);
        assert!(IacAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_for_terraform() {
        let crawl = crawl_with(vec!["infra/main.tf".into()]);
        assert!(IacAnalyzer::new().wants(&crawl));
    }

    #[test]
    fn wants_returns_true_for_yaml() {
        let crawl = crawl_with(vec!["k8s/pod.yaml".into()]);
        assert!(IacAnalyzer::new().wants(&crawl));
    }
}
