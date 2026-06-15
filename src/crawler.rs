use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use ignore::{DirEntry, WalkBuilder, WalkState};
use thiserror::Error;

use crate::cli::Cli;

#[derive(Debug, Error)]
pub enum CrawlError {
    #[error("target path does not exist: {0}")]
    MissingTarget(PathBuf),

    #[error("failed to canonicalize target path '{path}': {source}")]
    Canonicalize {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("filesystem walk encountered an unrecoverable error: {0}")]
    Walk(#[from] ignore::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    Manifest,
    Source,
    Config,
    Other,
}

impl FileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::Manifest => "manifest",
            FileKind::Source => "source",
            FileKind::Config => "config",
            FileKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub kind: FileKind,
    pub size: Option<u64>,
}

#[derive(Debug, Default)]
pub struct CrawlSummary {
    pub files: Vec<DiscoveredFile>,
    pub skipped: usize,
    pub errors: Vec<String>,
}

impl CrawlSummary {
    pub fn total(&self) -> usize {
        self.files.len()
    }

    pub fn count_of(&self, kind: FileKind) -> usize {
        self.files.iter().filter(|f| f.kind == kind).count()
    }
}

pub fn walk_project(cli: &Cli) -> Result<CrawlSummary, CrawlError> {
    let target = &cli.path;
    if !target.exists() {
        return Err(CrawlError::MissingTarget(target.clone()));
    }

    let root = std::fs::canonicalize(target).map_err(|source| CrawlError::Canonicalize {
        path: target.clone(),
        source,
    })?;

    let mut builder = WalkBuilder::new(&root);
    builder
        .hidden(!cli.include_hidden)
        .git_ignore(!cli.no_ignore)
        .git_global(!cli.no_ignore)
        .git_exclude(!cli.no_ignore)
        .ignore(!cli.no_ignore)
        .parents(!cli.no_ignore)
        .follow_links(cli.follow_links);

    if let Some(depth) = cli.max_depth {
        builder.max_depth(Some(depth));
    }
    if let Some(threads) = cli.threads {
        builder.threads(threads.max(1));
    }

    let mut overrides = ignore::overrides::OverrideBuilder::new(&root);
    for pattern in NOISE_DIRECTORIES {
        let _ = overrides.add(&format!("!{pattern}"));
    }
    if let Ok(ov) = overrides.build() {
        builder.overrides(ov);
    }

    let walker = builder.build_parallel();

    let (tx, rx) = mpsc::channel::<WalkMessage>();

    let aggregator = thread::spawn(move || {
        let mut summary = CrawlSummary::default();
        while let Ok(msg) = rx.recv() {
            match msg {
                WalkMessage::File(file) => summary.files.push(file),
                WalkMessage::Skip => summary.skipped += 1,
                WalkMessage::Err(e) => summary.errors.push(e),
            }
        }
        summary
    });

    let include_minified = cli.include_minified;
    walker.run(|| {
        let tx = tx.clone();
        Box::new(move |result| {
            match result {
                Ok(entry) => {
                    if let Some(message) = classify_entry(&entry, include_minified) {
                        if tx.send(message).is_err() {
                            return WalkState::Quit;
                        }
                    }
                }
                Err(err) => {
                    let _ = tx.send(WalkMessage::Err(err.to_string()));
                }
            }
            WalkState::Continue
        })
    });

    drop(tx);

    let summary = aggregator
        .join()
        .unwrap_or_else(|_| CrawlSummary::default());

    Ok(summary)
}

enum WalkMessage {
    File(DiscoveredFile),
    Skip,
    Err(String),
}

fn classify_entry(entry: &DirEntry, include_minified: bool) -> Option<WalkMessage> {
    let file_type = entry.file_type()?;
    if !file_type.is_file() {
        return Some(WalkMessage::Skip);
    }

    let path = entry.path().to_path_buf();
    let kind = classify_path(&path);

    if !include_minified && is_minified_file(&path) {
        return Some(WalkMessage::Skip);
    }

    let size = entry.metadata().ok().map(|m| m.len());

    Some(WalkMessage::File(DiscoveredFile { path, kind, size }))
}

fn is_minified_file(path: &Path) -> bool {
    if has_minified_name(path) {
        return true;
    }
    if !is_textual_extension(path) {
        return false;
    }
    looks_minified_by_content(path)
}

fn has_minified_name(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    for marker in MINIFIED_NAME_MARKERS {
        if lower.contains(marker) {
            return true;
        }
    }
    false
}

fn is_textual_extension(path: &Path) -> bool {
    let Some(ext) = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
    else {
        return false;
    };
    TEXTUAL_EXTENSIONS_FOR_MINIFIED_SCAN.contains(&ext.as_str())
}

fn looks_minified_by_content(path: &Path) -> bool {
    use std::io::Read;

    const PROBE_BYTES: usize = 8 * 1024;
    const MIN_PROBE_BYTES: usize = 256;
    const AVG_LINE_LENGTH_THRESHOLD: usize = 500;

    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = vec![0u8; PROBE_BYTES];
    let Ok(read) = file.read(&mut buf) else {
        return false;
    };
    if read < MIN_PROBE_BYTES {
        return false;
    }
    buf.truncate(read);
    if buf.contains(&0) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&buf) else {
        return false;
    };
    let lines = text.split('\n').count().max(1);
    text.len() / lines >= AVG_LINE_LENGTH_THRESHOLD
}

const MINIFIED_NAME_MARKERS: &[&str] = &[
    ".min.js",
    ".min.mjs",
    ".min.cjs",
    ".min.css",
    ".bundle.js",
    ".bundle.mjs",
    ".bundle.css",
    "-min.js",
    "-min.css",
];

const TEXTUAL_EXTENSIONS_FOR_MINIFIED_SCAN: &[&str] =
    &["js", "mjs", "cjs", "jsx", "ts", "tsx", "css"];

fn classify_path(path: &Path) -> FileKind {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if MANIFEST_FILES.iter().any(|m| *m == file_name) {
        return FileKind::Manifest;
    }

    if is_dotfile_config(&file_name) {
        return FileKind::Config;
    }

    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());

    if let Some(ext) = extension.as_deref() {
        if SOURCE_EXTENSIONS.contains(&ext) {
            return FileKind::Source;
        }
        if CONFIG_EXTENSIONS.contains(&ext) {
            return FileKind::Config;
        }
    }

    FileKind::Other
}

fn is_dotfile_config(file_name: &str) -> bool {
    file_name == ".env" || file_name == ".envrc" || file_name.starts_with(".env.")
}

const MANIFEST_FILES: &[&str] = &[
    "cargo.toml",
    "cargo.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "packages.lock.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "package.resolved",
    "pubspec.lock",
    "mix.lock",
];

const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "java", "kt", "kts", "rb", "php",
    "cs", "cpp", "cc", "cxx", "c", "h", "hpp", "swift", "scala", "sh", "bash",
];

const CONFIG_EXTENSIONS: &[&str] = &[
    "toml",
    "yaml",
    "yml",
    "json",
    "ini",
    "env",
    "conf",
    "cfg",
    "properties",
    "xml",
    "tf",
    "tfvars",
];

const NOISE_DIRECTORIES: &[&str] = &[
    "**/.git/**",
    "**/node_modules/**",
    "**/target/**",
    "**/dist/**",
    "**/build/**",
    "**/.venv/**",
    "**/venv/**",
    "**/__pycache__/**",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn classify_recognises_cargo_manifest() {
        assert_eq!(classify_path(Path::new("Cargo.toml")), FileKind::Manifest);
        assert_eq!(classify_path(Path::new("CARGO.TOML")), FileKind::Manifest);
        assert_eq!(
            classify_path(Path::new("project/Cargo.lock")),
            FileKind::Manifest
        );
    }

    #[test]
    fn classify_recognises_polyglot_manifests() {
        assert_eq!(classify_path(Path::new("package.json")), FileKind::Manifest);
        assert_eq!(classify_path(Path::new("go.mod")), FileKind::Manifest);
        assert_eq!(
            classify_path(Path::new("requirements.txt")),
            FileKind::Manifest
        );
        assert_eq!(classify_path(Path::new("pom.xml")), FileKind::Manifest);
    }

    #[test]
    fn classify_recognises_source_extensions() {
        assert_eq!(classify_path(Path::new("src/main.rs")), FileKind::Source);
        assert_eq!(classify_path(Path::new("app/index.ts")), FileKind::Source);
        assert_eq!(classify_path(Path::new("a/b/c.py")), FileKind::Source);
    }

    #[test]
    fn classify_recognises_config_extensions() {
        assert_eq!(classify_path(Path::new("config.yaml")), FileKind::Config);
        assert_eq!(classify_path(Path::new("settings.json")), FileKind::Config);
    }

    #[test]
    fn classify_recognises_dotfile_env_variants_as_config() {
        assert_eq!(classify_path(Path::new(".env")), FileKind::Config);
        assert_eq!(classify_path(Path::new(".envrc")), FileKind::Config);
        assert_eq!(classify_path(Path::new(".env.local")), FileKind::Config);
        assert_eq!(
            classify_path(Path::new(".env.production")),
            FileKind::Config
        );
        assert_eq!(
            classify_path(Path::new("services/api/.env")),
            FileKind::Config
        );
    }

    #[test]
    fn classify_unknown_falls_through_to_other() {
        assert_eq!(classify_path(Path::new("README")), FileKind::Other);
        assert_eq!(classify_path(Path::new("image.png")), FileKind::Other);
        assert_eq!(classify_path(Path::new("archive.tar.gz")), FileKind::Other);
    }

    #[test]
    fn has_minified_name_recognises_common_patterns() {
        assert!(has_minified_name(Path::new("jquery.min.js")));
        assert!(has_minified_name(Path::new("Bootstrap.Min.Css")));
        assert!(has_minified_name(Path::new("vendor.bundle.js")));
        assert!(has_minified_name(Path::new("app-min.js")));
        assert!(has_minified_name(Path::new("path/to/lib.min.mjs")));
        assert!(!has_minified_name(Path::new("jquery.js")));
        assert!(!has_minified_name(Path::new("admin.js")));
        assert!(!has_minified_name(Path::new("minified-runner.test.ts")));
    }

    #[test]
    fn is_textual_extension_only_targets_web_assets() {
        assert!(is_textual_extension(Path::new("a.js")));
        assert!(is_textual_extension(Path::new("a.MJS")));
        assert!(is_textual_extension(Path::new("a.css")));
        assert!(is_textual_extension(Path::new("a.ts")));
        assert!(!is_textual_extension(Path::new("a.rs")));
        assert!(!is_textual_extension(Path::new("a.py")));
        assert!(!is_textual_extension(Path::new("noext")));
    }

    #[test]
    fn looks_minified_by_content_flags_long_single_line_js() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "rastray-crawler-min-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob.js");
        let mut payload = String::with_capacity(2048);
        while payload.len() < 1600 {
            payload.push_str("function a(b){return b.x}var c=1;");
        }
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(payload.as_bytes());
        }
        assert!(looks_minified_by_content(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn looks_minified_by_content_keeps_normal_source_files() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "rastray-crawler-min-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("normal.js");
        let body =
            "function add(a, b) {\n    return a + b;\n}\n\nmodule.exports = { add };\n".repeat(20);
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(body.as_bytes());
        }
        assert!(!looks_minified_by_content(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn looks_minified_by_content_ignores_too_small_files() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "rastray-crawler-min-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("tiny.js");
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(&[b'a'; 100]);
        }
        assert!(!looks_minified_by_content(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_dotfile_config_boundary_cases() {
        assert!(is_dotfile_config(".env"));
        assert!(is_dotfile_config(".envrc"));
        assert!(is_dotfile_config(".env.staging"));
        assert!(!is_dotfile_config(".envoy"));
        assert!(!is_dotfile_config("env"));
        assert!(!is_dotfile_config(".env_local"));
    }

    #[test]
    fn file_kind_as_str_round_trip() {
        assert_eq!(FileKind::Manifest.as_str(), "manifest");
        assert_eq!(FileKind::Source.as_str(), "source");
        assert_eq!(FileKind::Config.as_str(), "config");
        assert_eq!(FileKind::Other.as_str(), "other");
    }

    #[test]
    fn crawl_summary_count_of_filters_kinds() {
        let summary = CrawlSummary {
            files: vec![
                DiscoveredFile {
                    path: PathBuf::from("a.rs"),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: PathBuf::from("b.rs"),
                    kind: FileKind::Source,
                    size: None,
                },
                DiscoveredFile {
                    path: PathBuf::from("Cargo.toml"),
                    kind: FileKind::Manifest,
                    size: None,
                },
            ],
            skipped: 0,
            errors: Vec::new(),
        };
        assert_eq!(summary.total(), 3);
        assert_eq!(summary.count_of(FileKind::Source), 2);
        assert_eq!(summary.count_of(FileKind::Manifest), 1);
        assert_eq!(summary.count_of(FileKind::Config), 0);
    }
}
