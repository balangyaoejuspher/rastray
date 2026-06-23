#![no_main]

use libfuzzer_sys::fuzz_target;
use regex::Regex;
use std::sync::OnceLock;

static DIRECTIVE_RE: OnceLock<Regex> = OnceLock::new();

fn directive_regex() -> Option<&'static Regex> {
    if let Some(re) = DIRECTIVE_RE.get() {
        return Some(re);
    }
    if let Ok(re) = Regex::new(r"rastray-ignore(?:-(line|file))?\s*:\s*([^/\n]*)") {
        let _ = DIRECTIVE_RE.set(re);
    }
    DIRECTIVE_RE.get()
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Some(re) = directive_regex() else {
        return;
    };
    for caps in re.captures_iter(s) {
        let _ = caps.get(1).map(|m| m.as_str());
        let _ = caps.get(2).map(|m| m.as_str());
    }
});
