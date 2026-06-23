#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default)]
    scan: ScanConfig,
    #[serde(default)]
    rules: HashMap<String, RuleConfig>,
    #[serde(default)]
    suppress: Vec<SuppressRule>,
    #[serde(default, rename = "custom_rule")]
    custom_rules: Vec<CustomRule>,
}

#[derive(Debug, Default, Deserialize)]
struct ScanConfig {
    #[serde(default)]
    fail_on: Option<String>,
    #[serde(default)]
    ignore: ScanIgnore,
}

#[derive(Debug, Default, Deserialize)]
struct ScanIgnore {
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RuleConfig {
    Toggle(bool),
    Detailed(RuleDetail),
}

#[derive(Debug, Default, Deserialize)]
struct RuleDetail {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SuppressRule {
    path: String,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CustomRule {
    id: String,
    pattern: String,
    message: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    help: Option<String>,
    #[serde(default)]
    extensions: Vec<String>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<Config>(s);
    }
});
