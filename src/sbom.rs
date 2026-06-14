use std::path::Path;

use serde_json::{json, Value};
use thiserror::Error;

use crate::modules::dependencies::DiscoveredPackage;

const SCHEMA_VERSION_CYCLONEDX: &str = "1.5";
const SPEC_VERSION_SPDX: &str = "SPDX-2.3";
const TOOL_NAME: &str = "rastray";
const TOOL_VENDOR: &str = "rastray";

#[derive(Debug, Error)]
pub enum SbomError {
    #[error("failed to serialize SBOM as JSON: {0}")]
    Json(#[from] Box<serde_json::Error>),
    #[error("failed to write SBOM to '{path}': {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl From<serde_json::Error> for SbomError {
    fn from(err: serde_json::Error) -> Self {
        SbomError::Json(Box::new(err))
    }
}

pub fn render_cyclonedx(
    packages: &[DiscoveredPackage],
    tool_version: &str,
    output_path: Option<&Path>,
) -> Result<(), SbomError> {
    let doc = cyclonedx_document(packages, tool_version);
    write_json(&doc, output_path)
}

pub fn render_spdx_json(
    packages: &[DiscoveredPackage],
    tool_version: &str,
    output_path: Option<&Path>,
) -> Result<(), SbomError> {
    let doc = spdx_document(packages, tool_version);
    write_json(&doc, output_path)
}

fn cyclonedx_document(packages: &[DiscoveredPackage], tool_version: &str) -> Value {
    let components: Vec<Value> = packages
        .iter()
        .map(|p| {
            let purl = package_url(p);
            json!({
                "type": "library",
                "bom-ref": purl,
                "name": p.name,
                "version": p.version,
                "purl": purl,
            })
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": SCHEMA_VERSION_CYCLONEDX,
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": TOOL_VENDOR,
                "name": TOOL_NAME,
                "version": tool_version,
            }],
        },
        "components": components,
    })
}

fn spdx_document(packages: &[DiscoveredPackage], tool_version: &str) -> Value {
    let spdx_packages: Vec<Value> = packages
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            json!({
                "SPDXID": format!("SPDXRef-Package-{idx}"),
                "name": p.name,
                "versionInfo": p.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": package_url(p),
                }],
            })
        })
        .collect();

    json!({
        "spdxVersion": SPEC_VERSION_SPDX,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "rastray-sbom",
        "documentNamespace": format!("https://github.com/balangyaoejuspher/rastray/sbom/{tool_version}"),
        "creationInfo": {
            "creators": [format!("Tool: {TOOL_NAME}-{tool_version}")],
            "created": "1970-01-01T00:00:00Z",
        },
        "packages": spdx_packages,
    })
}

fn package_url(pkg: &DiscoveredPackage) -> String {
    let typ = match pkg.ecosystem {
        "crates.io" => "cargo",
        "npm" => "npm",
        "PyPI" => "pypi",
        "Go" => "golang",
        "RubyGems" => "gem",
        "Packagist" => "composer",
        "NuGet" => "nuget",
        "SwiftURL" => "swift",
        "Pub" => "pub",
        "Hex" => "hex",
        "Maven" => "maven",
        other => other,
    };
    if pkg.ecosystem == "Maven" {
        let name_path = pkg.name.replacen(':', "/", 1);
        return format!("pkg:{typ}/{}@{}", name_path, pkg.version);
    }
    format!("pkg:{typ}/{}@{}", pkg.name, pkg.version)
}

fn write_json(doc: &Value, output_path: Option<&Path>) -> Result<(), SbomError> {
    let payload = serde_json::to_string_pretty(doc)?;
    match output_path {
        Some(path) => std::fs::write(path, &payload).map_err(|source| SbomError::Io {
            path: path.to_path_buf(),
            source,
        }),
        None => {
            println!("{payload}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_packages() -> Vec<DiscoveredPackage> {
        vec![
            DiscoveredPackage {
                ecosystem: "crates.io",
                name: "serde".to_string(),
                version: "1.0.0".to_string(),
                source: PathBuf::from("Cargo.lock"),
            },
            DiscoveredPackage {
                ecosystem: "npm",
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                source: PathBuf::from("package-lock.json"),
            },
        ]
    }

    #[test]
    fn cyclonedx_has_required_top_level_fields() {
        let doc = cyclonedx_document(&sample_packages(), "0.2.0");
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert_eq!(doc["components"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn cyclonedx_component_has_purl() {
        let doc = cyclonedx_document(&sample_packages(), "0.2.0");
        let first = &doc["components"][0];
        assert_eq!(first["purl"], "pkg:cargo/serde@1.0.0");
        assert_eq!(first["name"], "serde");
        assert_eq!(first["version"], "1.0.0");
    }

    #[test]
    fn spdx_has_required_top_level_fields() {
        let doc = spdx_document(&sample_packages(), "0.2.0");
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(doc["packages"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn spdx_package_has_purl_external_ref() {
        let doc = spdx_document(&sample_packages(), "0.2.0");
        let first = &doc["packages"][0];
        assert_eq!(first["name"], "serde");
        assert_eq!(first["versionInfo"], "1.0.0");
        let purl = &first["externalRefs"][0]["referenceLocator"];
        assert_eq!(purl, "pkg:cargo/serde@1.0.0");
    }

    #[test]
    fn package_url_npm_translates_ecosystem() {
        let pkg = DiscoveredPackage {
            ecosystem: "npm",
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: PathBuf::from("package-lock.json"),
        };
        assert_eq!(package_url(&pkg), "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn package_url_pypi_translates_ecosystem() {
        let pkg = DiscoveredPackage {
            ecosystem: "PyPI",
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            source: PathBuf::from("requirements.txt"),
        };
        assert_eq!(package_url(&pkg), "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn package_url_go_translates_ecosystem() {
        let pkg = DiscoveredPackage {
            ecosystem: "Go",
            name: "github.com/foo/bar".to_string(),
            version: "v1.0.0".to_string(),
            source: PathBuf::from("go.sum"),
        };
        assert_eq!(package_url(&pkg), "pkg:golang/github.com/foo/bar@v1.0.0");
    }
}
