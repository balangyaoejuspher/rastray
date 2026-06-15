pub mod crypto;
pub mod dependencies;
pub mod deserialization;
pub mod gha;
pub mod iac;
pub mod injection;
pub mod jwt;
pub mod network;
pub mod nosqli;
pub mod open_redirect;
pub mod orm;
pub mod path_traversal;
pub mod performance;
pub mod secrets;
pub mod ssrf;
pub mod ssti;
pub mod webapp_config;
pub mod xss;
pub mod xxe;

use thiserror::Error;

use crate::cli::Cli;
use crate::crawler::CrawlSummary;
use crate::reporter::Finding;

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("analyzer '{name}' failed: {message}")]
    Failed { name: &'static str, message: String },
}

pub trait Analyzer {
    fn name(&self) -> &'static str;

    fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError>;
}

pub fn default_registry(cli: &Cli) -> Vec<Box<dyn Analyzer + Send + Sync>> {
    vec![
        Box::new(secrets::SecretsAnalyzer::new()),
        Box::new(crypto::CryptoAnalyzer::new()),
        Box::new(injection::InjectionAnalyzer::new()),
        Box::new(network::NetworkAnalyzer::new()),
        Box::new(gha::GhaAnalyzer::new()),
        Box::new(iac::IacAnalyzer::new()),
        Box::new(deserialization::DeserializationAnalyzer::new()),
        Box::new(path_traversal::PathTraversalAnalyzer::new()),
        Box::new(ssrf::SsrfAnalyzer::new()),
        Box::new(xss::XssAnalyzer::new()),
        Box::new(open_redirect::OpenRedirectAnalyzer::new()),
        Box::new(ssti::SstiAnalyzer::new()),
        Box::new(xxe::XxeAnalyzer::new()),
        Box::new(nosqli::NosqliAnalyzer::new()),
        Box::new(webapp_config::WebappConfigAnalyzer::new()),
        Box::new(jwt::JwtAnalyzer::new()),
        Box::new(orm::OrmAnalyzer::new()),
        Box::new(dependencies::DependenciesAnalyzer::with_options(
            cli.offline,
            cli.no_cache,
        )),
        Box::new(performance::PerformanceAnalyzer::new()),
    ]
}
