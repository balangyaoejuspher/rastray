use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::{
    Diagnostic, DiagnosticRelatedInformation, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    InitializeParams, InitializeResult, InitializedParams, Location as LspLocation, MessageType,
    NumberOrString, Position, Range, ServerCapabilities, ServerInfo, TextDocumentSyncCapability,
    TextDocumentSyncKind, Url,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::cli::{Cli, Confidence, Severity};
use crate::config::Config;
use crate::crawler::{CrawlSummary, DiscoveredFile, FileKind};
use crate::modules::{default_registry, Analyzer};
use crate::reporter::Finding;

pub struct RastrayLanguageServer {
    client: Client,
    analyzers: Vec<Arc<dyn Analyzer + Send + Sync>>,
    documents: Mutex<HashMap<Url, String>>,
}

impl RastrayLanguageServer {
    pub fn new(client: Client) -> Self {
        let cli = Cli::default_for_lsp();
        let config = Config::default();
        let analyzers = default_registry(&cli, &config)
            .into_iter()
            .map(Arc::<dyn Analyzer + Send + Sync>::from)
            .collect();
        Self {
            client,
            analyzers,
            documents: Mutex::new(HashMap::new()),
        }
    }

    async fn scan_and_publish(&self, uri: Url) {
        let path = match uri.to_file_path() {
            Ok(p) => p,
            Err(_) => return,
        };
        let metadata = std::fs::metadata(&path).ok();
        let size = metadata.as_ref().map(|m| m.len());
        let kind = classify_path_for_lsp(&path);
        if !matches!(kind, FileKind::Source | FileKind::Manifest) {
            self.publish(uri, Vec::new()).await;
            return;
        }
        let crawl = CrawlSummary {
            files: vec![DiscoveredFile {
                path: path.clone(),
                kind,
                size,
            }],
            skipped: 0,
            errors: Vec::new(),
            fingerprint: Default::default(),
        };
        let mut findings = Vec::new();
        for analyzer in &self.analyzers {
            if analyzer.name() == "dependencies" {
                continue;
            }
            if !analyzer.wants(&crawl) {
                continue;
            }
            if let Ok(mut f) = analyzer.analyze(&crawl) {
                findings.append(&mut f);
            }
        }
        let diagnostics = findings_to_diagnostics(&path, &findings, &uri);
        self.publish(uri, diagnostics).await;
    }

    async fn publish(&self, uri: Url, diagnostics: Vec<Diagnostic>) {
        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for RastrayLanguageServer {
    async fn initialize(&self, _params: InitializeParams) -> LspResult<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "rastray".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(
                MessageType::INFO,
                format!("rastray LSP v{} ready", env!("CARGO_PKG_VERSION")),
            )
            .await;
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        {
            let mut docs = self.documents.lock().await;
            docs.insert(uri.clone(), params.text_document.text);
        }
        self.scan_and_publish(uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let mut docs = self.documents.lock().await;
        if let Some(change) = params.content_changes.into_iter().last() {
            docs.insert(uri, change.text);
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        self.scan_and_publish(uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        {
            let mut docs = self.documents.lock().await;
            docs.remove(&uri);
        }
        self.publish(uri, Vec::new()).await;
    }

    async fn shutdown(&self) -> LspResult<()> {
        Ok(())
    }
}

pub async fn run_lsp_server() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(RastrayLanguageServer::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}

fn classify_path_for_lsp(path: &Path) -> FileKind {
    let manifest_names = [
        "Cargo.toml",
        "Cargo.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "Gemfile.lock",
        "composer.lock",
        "packages.lock.json",
        "Package.resolved",
        "pubspec.lock",
        "mix.lock",
        "pom.xml",
        "gradle.lockfile",
        "go.sum",
        "go.mod",
    ];
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if manifest_names.contains(&name) {
        return FileKind::Manifest;
    }
    let source_exts = [
        "rs", "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "go", "java", "rb", "php", "cs",
    ];
    if let Some(ext) = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        if source_exts.contains(&ext.as_str()) {
            return FileKind::Source;
        }
    }
    FileKind::Other
}

pub fn findings_to_diagnostics(
    file_path: &Path,
    findings: &[Finding],
    uri: &Url,
) -> Vec<Diagnostic> {
    findings
        .iter()
        .filter(|f| {
            f.location
                .as_ref()
                .is_some_and(|loc| paths_equal(&loc.file, file_path))
        })
        .map(|f| finding_to_diagnostic(f, uri))
        .collect()
}

fn finding_to_diagnostic(finding: &Finding, uri: &Url) -> Diagnostic {
    let (line, column) = finding
        .location
        .as_ref()
        .map(|loc| {
            (
                loc.line.unwrap_or(1).saturating_sub(1) as u32,
                loc.column.unwrap_or(1).saturating_sub(1) as u32,
            )
        })
        .unwrap_or((0, 0));
    let length = finding
        .location
        .as_ref()
        .and_then(|loc| loc.byte_length)
        .unwrap_or(1) as u32;
    let range = Range {
        start: Position {
            line,
            character: column,
        },
        end: Position {
            line,
            character: column.saturating_add(length),
        },
    };
    let related = finding.help.as_ref().map(|help| {
        vec![DiagnosticRelatedInformation {
            location: LspLocation {
                uri: uri.clone(),
                range,
            },
            message: format!("help: {help}"),
        }]
    });
    Diagnostic {
        range,
        severity: Some(map_severity(finding.severity)),
        code: Some(NumberOrString::String(finding.code.clone())),
        code_description: None,
        source: Some("rastray".to_string()),
        message: finding.message.clone(),
        related_information: related,
        tags: None,
        data: None,
    }
}

fn map_severity(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Critical | Severity::High => DiagnosticSeverity::ERROR,
        Severity::Medium => DiagnosticSeverity::WARNING,
        Severity::Low => DiagnosticSeverity::INFORMATION,
        Severity::Info => DiagnosticSeverity::HINT,
    }
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ac), Ok(bc)) => ac == bc,
        _ => a == b,
    }
}

impl Cli {
    pub fn default_for_lsp() -> Self {
        Self {
            path: PathBuf::from("."),
            min_severity: Severity::Info,
            min_confidence: Confidence::Low,
            json: false,
            format: None,
            output: None,
            config: None,
            no_config: true,
            fail_on: None,
            baseline: None,
            write_baseline: None,
            since: None,
            changed_only: false,
            summary_only: false,
            fix: false,
            fix_yes: false,
            offline: true,
            no_cache: true,
            no_default_skip: false,
            no_ignore: false,
            include_hidden: false,
            follow_links: false,
            include_minified: false,
            threads: Some(1),
            max_depth: None,
            verbose: 0,
            quiet: true,
            command: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::{Category, Location};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rastray-lsp-test-{}-{name}", std::process::id()))
    }

    fn make_url(path: &Path) -> Option<Url> {
        Url::from_file_path(path)
            .ok()
            .or_else(|| Url::parse("file:///rastray-lsp-test").ok())
    }

    #[test]
    fn maps_severity_to_lsp_severity() {
        assert_eq!(map_severity(Severity::Critical), DiagnosticSeverity::ERROR);
        assert_eq!(map_severity(Severity::High), DiagnosticSeverity::ERROR);
        assert_eq!(map_severity(Severity::Medium), DiagnosticSeverity::WARNING);
        assert_eq!(map_severity(Severity::Low), DiagnosticSeverity::INFORMATION);
        assert_eq!(map_severity(Severity::Info), DiagnosticSeverity::HINT);
    }

    #[test]
    fn finding_to_diagnostic_uses_zero_based_position() {
        let path = temp_path("position.rs");
        let url = match make_url(&path) {
            Some(u) => u,
            None => return,
        };
        let finding = Finding::new(
            "RSTR-TEST-001",
            "test message",
            Severity::High,
            Category::Security,
        )
        .with_help("do the safe thing")
        .with_location(
            Location::file(path.clone())
                .with_span(42, 7)
                .with_line(3, 5),
        );
        let diag = finding_to_diagnostic(&finding, &url);
        assert_eq!(diag.range.start.line, 2);
        assert_eq!(diag.range.start.character, 4);
        assert_eq!(diag.range.end.character, 4 + 7);
        assert_eq!(diag.severity, Some(DiagnosticSeverity::ERROR));
        assert_eq!(diag.source.as_deref(), Some("rastray"));
        let code_string = if let Some(NumberOrString::String(s)) = diag.code.as_ref() {
            s.clone()
        } else {
            String::new()
        };
        assert_eq!(code_string, "RSTR-TEST-001");
        let related = diag
            .related_information
            .as_ref()
            .and_then(|r| r.first())
            .map(|r| r.message.clone())
            .unwrap_or_default();
        assert!(related.contains("do the safe thing"));
    }

    #[test]
    fn findings_filtered_by_path_match() {
        let path_a = temp_path("a.rs");
        let path_b = temp_path("b.rs");
        let url_a = match make_url(&path_a) {
            Some(u) => u,
            None => return,
        };
        let findings = vec![
            Finding::new("RSTR-X", "m", Severity::High, Category::Security)
                .with_location(Location::file(path_a.clone()).with_line(1, 1)),
            Finding::new("RSTR-Y", "m", Severity::High, Category::Security)
                .with_location(Location::file(path_b.clone()).with_line(1, 1)),
        ];
        let diags = findings_to_diagnostics(&path_a, &findings, &url_a);
        assert_eq!(diags.len(), 1);
        let s = match &diags[0].code {
            Some(NumberOrString::String(s)) => s.clone(),
            _ => String::new(),
        };
        assert_eq!(s, "RSTR-X");
    }

    #[test]
    fn classify_path_recognises_rust_source() {
        let path = PathBuf::from("/tmp/x.rs");
        assert_eq!(classify_path_for_lsp(&path), FileKind::Source);
    }

    #[test]
    fn classify_path_recognises_cargo_manifest() {
        let path = PathBuf::from("/tmp/Cargo.toml");
        assert_eq!(classify_path_for_lsp(&path), FileKind::Manifest);
    }

    #[test]
    fn classify_path_returns_other_for_unknown() {
        let path = PathBuf::from("/tmp/notes.txt");
        assert_eq!(classify_path_for_lsp(&path), FileKind::Other);
    }

    #[test]
    fn default_cli_for_lsp_is_quiet_and_offline() {
        let cli = Cli::default_for_lsp();
        assert!(cli.quiet);
        assert!(cli.offline);
        assert!(cli.no_config);
        assert!(cli.no_cache);
        assert_eq!(cli.min_severity, Severity::Info);
    }
}
