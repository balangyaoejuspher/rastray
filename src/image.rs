use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use thiserror::Error;

use crate::modules::secrets::scan_text_for_secrets;
use crate::modules::AnalyzerError;
use crate::reporter::Finding;

#[derive(Debug, Error)]
pub enum ImageScanError {
    #[error("image archive '{path}' not found")]
    NotFound { path: PathBuf },

    #[error("failed to open image archive '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("secret pattern compilation failed: {0}")]
    Analyzer(#[from] AnalyzerError),
}

#[derive(Debug, Clone)]
pub struct ImageScanOptions {
    pub max_file_bytes: u64,
}

impl Default for ImageScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Default)]
pub struct ImageScanStats {
    pub layers_scanned: usize,
    pub files_scanned: usize,
    pub files_skipped_too_large: usize,
    pub files_skipped_binary: usize,
}

pub struct ImageScanResult {
    pub findings: Vec<Finding>,
    pub stats: ImageScanStats,
}

pub fn scan_image_archive(
    archive: &Path,
    opts: &ImageScanOptions,
) -> Result<ImageScanResult, ImageScanError> {
    if !archive.exists() {
        return Err(ImageScanError::NotFound {
            path: archive.to_path_buf(),
        });
    }

    let bytes = std::fs::read(archive).map_err(|source| ImageScanError::Io {
        path: archive.to_path_buf(),
        source,
    })?;

    let mut stats = ImageScanStats::default();
    let mut findings = Vec::new();

    walk_archive(&bytes, archive, opts, &mut stats, &mut findings, 0)?;

    Ok(ImageScanResult { findings, stats })
}

const MAX_NESTING_DEPTH: usize = 4;

fn walk_archive(
    bytes: &[u8],
    parent_label: &Path,
    opts: &ImageScanOptions,
    stats: &mut ImageScanStats,
    findings: &mut Vec<Finding>,
    depth: usize,
) -> Result<(), ImageScanError> {
    if depth > MAX_NESTING_DEPTH {
        return Ok(());
    }

    let decompressed = decompress_if_gz(bytes);
    let reader = Cursor::new(decompressed.as_ref());
    let mut archive = tar::Archive::new(reader);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let parent_str = parent_label.display().to_string();
    let mut is_layer_archive = false;

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let entry_path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => continue,
        };
        let entry_name = entry_path.display().to_string();

        let header = entry.header();
        let size = header.size().unwrap_or(0);
        let entry_type = header.entry_type();
        if !entry_type.is_file() {
            continue;
        }

        if looks_like_inner_tar(&entry_name) {
            is_layer_archive = true;
            if size > opts.max_file_bytes.saturating_mul(64) {
                continue;
            }
            let mut inner = Vec::with_capacity(size as usize);
            if entry.read_to_end(&mut inner).is_err() {
                continue;
            }
            let inner_label = PathBuf::from(format!("{parent_str}::{entry_name}"));
            walk_archive(&inner, &inner_label, opts, stats, findings, depth + 1)?;
            continue;
        }

        if size > opts.max_file_bytes {
            stats.files_skipped_too_large += 1;
            continue;
        }

        let mut buf = Vec::with_capacity(size as usize);
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }

        if looks_binary(&buf) {
            stats.files_skipped_binary += 1;
            continue;
        }

        let contents = match std::str::from_utf8(&buf) {
            Ok(s) => s.to_string(),
            Err(_) => {
                stats.files_skipped_binary += 1;
                continue;
            }
        };

        stats.files_scanned += 1;
        let synthetic = PathBuf::from(format!("{parent_str}::{entry_name}"));
        let mut blob_findings = scan_text_for_secrets(&contents, synthetic)?;
        for f in &mut blob_findings {
            f.message = format!("{} (in image layer {})", f.message, entry_name);
        }
        findings.extend(blob_findings);
    }

    if is_layer_archive {
        stats.layers_scanned += 1;
    }

    Ok(())
}

fn decompress_if_gz(bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return std::borrow::Cow::Borrowed(bytes);
    }
    let mut out = Vec::new();
    let mut dec = GzDecoder::new(bytes);
    if dec.read_to_end(&mut out).is_ok() {
        std::borrow::Cow::Owned(out)
    } else {
        std::borrow::Cow::Borrowed(bytes)
    }
}

fn looks_like_inner_tar(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("/layer.tar")
        || lower.ends_with(".tar")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
}

fn looks_binary(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let probe = &buf[..buf.len().min(8192)];
    let nul_count = probe.iter().filter(|&&b| b == 0).count();
    nul_count * 100 / probe.len() > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_inner_tar_recognises_oci_layer_paths() {
        assert!(looks_like_inner_tar("blobs/sha256/abc/layer.tar"));
        assert!(looks_like_inner_tar("ABCD/layer.tar"));
        assert!(looks_like_inner_tar("layer.tar.gz"));
        assert!(looks_like_inner_tar("layer.tgz"));
        assert!(!looks_like_inner_tar("manifest.json"));
        assert!(!looks_like_inner_tar("config.json"));
    }

    #[test]
    fn looks_binary_flags_zero_heavy_buffers() {
        let binary = vec![0u8; 1024];
        assert!(looks_binary(&binary));
    }

    #[test]
    fn looks_binary_passes_text_buffers() {
        let text = b"const aws = \"AKIAIOSFODNN7EXAMPLE\";\n".repeat(20);
        assert!(!looks_binary(&text));
    }

    #[test]
    fn decompress_if_gz_passes_through_plain_bytes() {
        let plain = b"hello world";
        let out = decompress_if_gz(plain);
        assert_eq!(out.as_ref(), plain);
    }
}
