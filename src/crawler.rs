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

    walker.run(|| {
        let tx = tx.clone();
        Box::new(move |result| {
            match result {
                Ok(entry) => {
                    if let Some(message) = classify_entry(&entry) {
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

fn classify_entry(entry: &DirEntry) -> Option<WalkMessage> {
    let file_type = entry.file_type()?;
    if !file_type.is_file() {
        return Some(WalkMessage::Skip);
    }

    let path = entry.path().to_path_buf();
    let kind = classify_path(&path);
    let size = entry.metadata().ok().map(|m| m.len());

    Some(WalkMessage::File(DiscoveredFile { path, kind, size }))
}

fn classify_path(path: &Path) -> FileKind {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if MANIFEST_FILES.iter().any(|m| *m == file_name) {
        return FileKind::Manifest;
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
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
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
