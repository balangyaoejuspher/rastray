use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::crawler::{CrawlSummary, FileKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    Kotlin,
    Ruby,
    Php,
    CSharp,
    C,
    Cpp,
    Swift,
    Dart,
    Elixir,
}

impl Language {
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
            Language::Go => "go",
            Language::Java => "java",
            Language::Kotlin => "kotlin",
            Language::Ruby => "ruby",
            Language::Php => "php",
            Language::CSharp => "csharp",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Swift => "swift",
            Language::Dart => "dart",
            Language::Elixir => "elixir",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    Cargo,
    Npm,
    Pypi,
    Gomod,
    Maven,
    Gradle,
    Composer,
    Bundler,
    Nuget,
    Swiftpm,
    Pub,
    Hex,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Gomod => "gomod",
            Ecosystem::Maven => "maven",
            Ecosystem::Gradle => "gradle",
            Ecosystem::Composer => "composer",
            Ecosystem::Bundler => "bundler",
            Ecosystem::Nuget => "nuget",
            Ecosystem::Swiftpm => "swiftpm",
            Ecosystem::Pub => "pub",
            Ecosystem::Hex => "hex",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framework {
    Nextjs,
    Nestjs,
    Express,
    React,
    Vue,
    Svelte,
    Fastapi,
    Django,
    Flask,
    Gin,
    SpringBoot,
    Rails,
    Laravel,
    Symfony,
    Actix,
    Axum,
    Rocket,
}

impl Framework {
    pub fn as_str(self) -> &'static str {
        match self {
            Framework::Nextjs => "nextjs",
            Framework::Nestjs => "nestjs",
            Framework::Express => "express",
            Framework::React => "react",
            Framework::Vue => "vue",
            Framework::Svelte => "svelte",
            Framework::Fastapi => "fastapi",
            Framework::Django => "django",
            Framework::Flask => "flask",
            Framework::Gin => "gin",
            Framework::SpringBoot => "spring-boot",
            Framework::Rails => "rails",
            Framework::Laravel => "laravel",
            Framework::Symfony => "symfony",
            Framework::Actix => "actix",
            Framework::Axum => "axum",
            Framework::Rocket => "rocket",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectedProject {
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub language: Language,
    pub ecosystem: Option<Ecosystem>,
    pub frameworks: Vec<Framework>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ProjectFingerprint {
    pub languages: BTreeSet<Language>,
    pub ecosystems: BTreeSet<Ecosystem>,
    pub frameworks: BTreeSet<Framework>,
    pub projects: Vec<DetectedProject>,
}

impl ProjectFingerprint {
    pub fn detected(&self) -> bool {
        !self.projects.is_empty()
    }
}

pub fn fingerprint(crawl: &CrawlSummary) -> ProjectFingerprint {
    let mut fp = ProjectFingerprint::default();
    for file in &crawl.files {
        if file.kind != FileKind::Manifest {
            continue;
        }
        let Some(name) = file
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
        else {
            continue;
        };
        if let Some(detected) = detect_project(&file.path, &name) {
            fp.languages.insert(detected.language);
            if let Some(eco) = detected.ecosystem {
                fp.ecosystems.insert(eco);
            }
            for fw in &detected.frameworks {
                fp.frameworks.insert(*fw);
            }
            fp.projects.push(detected);
        }
    }
    fp.projects.sort_by(|a, b| a.root.cmp(&b.root));
    fp
}

fn detect_project(path: &Path, lower_name: &str) -> Option<DetectedProject> {
    let root = path.parent()?.to_path_buf();
    let contents = std::fs::read_to_string(path).ok()?;

    match lower_name {
        "cargo.toml" => {
            let frameworks = detect_rust_frameworks(&contents);
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language: Language::Rust,
                ecosystem: Some(Ecosystem::Cargo),
                frameworks,
            })
        }
        "package.json" => {
            let (language, frameworks) = detect_js_language_and_frameworks(&contents);
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language,
                ecosystem: Some(Ecosystem::Npm),
                frameworks,
            })
        }
        "pyproject.toml" | "requirements.txt" | "pipfile" | "poetry.lock" | "uv.lock" => {
            let frameworks = detect_python_frameworks(&contents);
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language: Language::Python,
                ecosystem: Some(Ecosystem::Pypi),
                frameworks,
            })
        }
        "go.mod" => {
            let frameworks = detect_go_frameworks(&contents);
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language: Language::Go,
                ecosystem: Some(Ecosystem::Gomod),
                frameworks,
            })
        }
        "pom.xml" => {
            let frameworks = detect_java_frameworks(&contents);
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language: Language::Java,
                ecosystem: Some(Ecosystem::Maven),
                frameworks,
            })
        }
        "build.gradle" | "build.gradle.kts" => {
            let frameworks = detect_java_frameworks(&contents);
            let language = if lower_name.ends_with(".kts") {
                Language::Kotlin
            } else {
                Language::Java
            };
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language,
                ecosystem: Some(Ecosystem::Gradle),
                frameworks,
            })
        }
        "composer.json" => {
            let frameworks = detect_php_frameworks(&contents);
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language: Language::Php,
                ecosystem: Some(Ecosystem::Composer),
                frameworks,
            })
        }
        "gemfile" | "gemfile.lock" => {
            let frameworks = detect_ruby_frameworks(&contents);
            Some(DetectedProject {
                root,
                manifest: path.to_path_buf(),
                language: Language::Ruby,
                ecosystem: Some(Ecosystem::Bundler),
                frameworks,
            })
        }
        "package.resolved" => Some(DetectedProject {
            root,
            manifest: path.to_path_buf(),
            language: Language::Swift,
            ecosystem: Some(Ecosystem::Swiftpm),
            frameworks: Vec::new(),
        }),
        "pubspec.lock" | "pubspec.yaml" => Some(DetectedProject {
            root,
            manifest: path.to_path_buf(),
            language: Language::Dart,
            ecosystem: Some(Ecosystem::Pub),
            frameworks: Vec::new(),
        }),
        "mix.lock" | "mix.exs" => Some(DetectedProject {
            root,
            manifest: path.to_path_buf(),
            language: Language::Elixir,
            ecosystem: Some(Ecosystem::Hex),
            frameworks: Vec::new(),
        }),
        "packages.lock.json" => Some(DetectedProject {
            root,
            manifest: path.to_path_buf(),
            language: Language::CSharp,
            ecosystem: Some(Ecosystem::Nuget),
            frameworks: Vec::new(),
        }),
        _ => None,
    }
}

fn detect_rust_frameworks(contents: &str) -> Vec<Framework> {
    let mut out = Vec::new();
    let lower = contents.to_ascii_lowercase();
    if lower.contains("\nactix-web") || lower.contains("\"actix-web\"") {
        out.push(Framework::Actix);
    }
    if lower.contains("\naxum") || lower.contains("\"axum\"") {
        out.push(Framework::Axum);
    }
    if lower.contains("\nrocket") || lower.contains("\"rocket\"") {
        out.push(Framework::Rocket);
    }
    out
}

fn detect_js_language_and_frameworks(contents: &str) -> (Language, Vec<Framework>) {
    let mut frameworks = Vec::new();
    let language = if contents.contains("\"typescript\"") || contents.contains("\"@types/node\"") {
        Language::TypeScript
    } else {
        Language::JavaScript
    };
    if contents.contains("\"next\"") {
        frameworks.push(Framework::Nextjs);
    }
    if contents.contains("\"@nestjs/core\"") || contents.contains("\"@nestjs/common\"") {
        frameworks.push(Framework::Nestjs);
    }
    if contents.contains("\"express\"") {
        frameworks.push(Framework::Express);
    }
    if contents.contains("\"react\"") {
        frameworks.push(Framework::React);
    }
    if contents.contains("\"vue\"") {
        frameworks.push(Framework::Vue);
    }
    if contents.contains("\"svelte\"") {
        frameworks.push(Framework::Svelte);
    }
    (language, frameworks)
}

fn detect_python_frameworks(contents: &str) -> Vec<Framework> {
    let mut out = Vec::new();
    let lower = contents.to_ascii_lowercase();
    if lower.contains("fastapi") {
        out.push(Framework::Fastapi);
    }
    if lower.contains("django") {
        out.push(Framework::Django);
    }
    if lower.contains("flask") {
        out.push(Framework::Flask);
    }
    out
}

fn detect_go_frameworks(contents: &str) -> Vec<Framework> {
    let mut out = Vec::new();
    if contents.contains("github.com/gin-gonic/gin") {
        out.push(Framework::Gin);
    }
    out
}

fn detect_java_frameworks(contents: &str) -> Vec<Framework> {
    let mut out = Vec::new();
    if contents.contains("spring-boot-starter") || contents.contains("org.springframework.boot") {
        out.push(Framework::SpringBoot);
    }
    out
}

fn detect_php_frameworks(contents: &str) -> Vec<Framework> {
    let mut out = Vec::new();
    if contents.contains("\"laravel/framework\"") {
        out.push(Framework::Laravel);
    }
    if contents.contains("\"symfony/framework-bundle\"") || contents.contains("\"symfony/symfony\"")
    {
        out.push(Framework::Symfony);
    }
    out
}

fn detect_ruby_frameworks(contents: &str) -> Vec<Framework> {
    let mut out = Vec::new();
    let trimmed = contents.to_ascii_lowercase();
    if trimmed.contains("\"rails\"")
        || trimmed.contains("'rails'")
        || trimmed.contains("\n  rails ")
    {
        out.push(Framework::Rails);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::DiscoveredFile;
    use std::io::Write;

    fn make_temp_dir(name: &str) -> Option<PathBuf> {
        let mut dir = std::env::temp_dir();
        dir.push(format!("rastray-fp-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir)
    }

    fn write_manifest(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(body.as_bytes());
        }
        path
    }

    fn crawl_with(files: Vec<(PathBuf, FileKind)>) -> CrawlSummary {
        let mut s = CrawlSummary::default();
        for (path, kind) in files {
            s.files.push(DiscoveredFile {
                path,
                kind,
                size: None,
            });
        }
        s
    }

    #[test]
    fn empty_crawl_produces_empty_fingerprint() {
        let s = CrawlSummary::default();
        let fp = fingerprint(&s);
        assert!(!fp.detected());
        assert!(fp.languages.is_empty());
        assert!(fp.ecosystems.is_empty());
        assert!(fp.frameworks.is_empty());
        assert!(fp.projects.is_empty());
    }

    #[test]
    fn cargo_toml_detects_rust_with_axum() {
        let Some(dir) = make_temp_dir("cargo-axum") else {
            return;
        };
        let manifest = write_manifest(
            &dir,
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\naxum = \"0.7\"\n",
        );
        let fp = fingerprint(&crawl_with(vec![(manifest, FileKind::Manifest)]));
        assert!(fp.languages.contains(&Language::Rust));
        assert!(fp.ecosystems.contains(&Ecosystem::Cargo));
        assert!(fp.frameworks.contains(&Framework::Axum));
        assert_eq!(fp.projects.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn package_json_detects_typescript_and_nestjs() {
        let Some(dir) = make_temp_dir("nest") else {
            return;
        };
        let body = r#"{
  "name": "api",
  "dependencies": {
    "@nestjs/core": "^10.0.0",
    "@nestjs/common": "^10.0.0",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
"#;
        let manifest = write_manifest(&dir, "package.json", body);
        let fp = fingerprint(&crawl_with(vec![(manifest, FileKind::Manifest)]));
        assert!(fp.languages.contains(&Language::TypeScript));
        assert!(fp.ecosystems.contains(&Ecosystem::Npm));
        assert!(fp.frameworks.contains(&Framework::Nestjs));
        assert!(fp.frameworks.contains(&Framework::Express));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pyproject_detects_python_and_django() {
        let Some(dir) = make_temp_dir("django") else {
            return;
        };
        let body = "[project]\nname = \"myapp\"\ndependencies = [\"django\", \"requests\"]\n";
        let manifest = write_manifest(&dir, "pyproject.toml", body);
        let fp = fingerprint(&crawl_with(vec![(manifest, FileKind::Manifest)]));
        assert!(fp.languages.contains(&Language::Python));
        assert!(fp.frameworks.contains(&Framework::Django));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn go_mod_detects_go_and_gin() {
        let Some(dir) = make_temp_dir("gin") else {
            return;
        };
        let body = "module example.com/api\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.10.0\n)\n";
        let manifest = write_manifest(&dir, "go.mod", body);
        let fp = fingerprint(&crawl_with(vec![(manifest, FileKind::Manifest)]));
        assert!(fp.languages.contains(&Language::Go));
        assert!(fp.frameworks.contains(&Framework::Gin));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn monorepo_detects_multiple_projects_in_subdirectories() {
        let Some(dir) = make_temp_dir("monorepo") else {
            return;
        };
        let api_dir = dir.join("apps").join("api");
        let web_dir = dir.join("apps").join("web");
        let _ = std::fs::create_dir_all(&api_dir);
        let _ = std::fs::create_dir_all(&web_dir);
        let api = write_manifest(
            &api_dir,
            "package.json",
            "{\"dependencies\":{\"@nestjs/core\":\"^10\"}}",
        );
        let web = write_manifest(
            &web_dir,
            "package.json",
            "{\"dependencies\":{\"next\":\"^14\",\"react\":\"^18\"}}",
        );
        let fp = fingerprint(&crawl_with(vec![
            (api, FileKind::Manifest),
            (web, FileKind::Manifest),
        ]));
        assert_eq!(fp.projects.len(), 2);
        assert!(fp.frameworks.contains(&Framework::Nestjs));
        assert!(fp.frameworks.contains(&Framework::Nextjs));
        assert!(fp.frameworks.contains(&Framework::React));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_manifest_file_yields_no_project() {
        let Some(dir) = make_temp_dir("missing") else {
            return;
        };
        let manifest = dir.join("Cargo.toml");
        let fp = fingerprint(&crawl_with(vec![(manifest, FileKind::Manifest)]));
        assert!(!fp.detected());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_manifest_name_is_ignored() {
        let Some(dir) = make_temp_dir("unknown") else {
            return;
        };
        let manifest = write_manifest(&dir, "Makefile", "all:\n\techo hi\n");
        let fp = fingerprint(&crawl_with(vec![(manifest, FileKind::Manifest)]));
        assert!(!fp.detected());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
