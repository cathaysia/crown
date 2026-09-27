// The helpers below are shared by several test binaries; each uses a subset.
#![allow(dead_code)]

use anyhow::bail;
use std::collections::BTreeMap;

pub fn parse_response_line(line: &str) -> anyhow::Result<(String, Vec<u8>)> {
    let parts: Vec<String> = line.split("=").map(|v| v.trim().to_lowercase()).collect();
    match parts.as_slice() {
        [key] => Ok((key.to_string(), vec![])),
        [key, value] => {
            let key = key.to_owned();
            let value = value.to_owned();
            if value.is_empty() || value == "0" {
                return Ok((key, vec![]));
            }
            Ok((key, hex::decode(value)?))
        }
        _ => bail!("bad response line: {line}"),
    }
}

/// One case from a NIST-style `.rsp`/`.txt` vector file: the fields of a
/// blank-line separated group (`Count = 0`, `Key = ..`, `IV = ..`, ...) with
/// lowercased names. Values are hex-decoded; values that are not hex (XTS'
/// decimal data unit sequence numbers, `FAIL`, quoted strings, ...) stay
/// available through `raw_field`/`int_field`.
#[derive(Clone, Debug, Default)]
pub struct Vector {
    pub fields: BTreeMap<String, Vec<u8>>,
    pub raw: BTreeMap<String, String>,
}

impl Vector {
    /// The first present field among `names` (all lower-case).
    pub fn field(&self, names: &[&str]) -> Option<&[u8]> {
        names
            .iter()
            .find_map(|n| self.fields.get(*n))
            .map(|v| &v[..])
    }

    /// The first present raw (non hex-decoded) field among `names`.
    pub fn raw_field(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|n| self.raw.get(*n)).map(|v| &v[..])
    }

    /// Concatenation of every present field in `names` (`key1 || key2 ||
    /// key3`, `plaintext1 || plaintext2`). `None` when none are present.
    pub fn concat(&self, names: &[&str]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut found = false;
        for n in names {
            if let Some(v) = self.fields.get(*n) {
                out.extend_from_slice(v);
                found = true;
            }
        }
        found.then_some(out)
    }

    /// Whether a field or a bare marker (`FAIL`) with this name is present.
    pub fn has(&self, name: &str) -> bool {
        self.fields.contains_key(name) || self.raw.contains_key(name)
    }

    /// The `int` field among `names`, parsed as a decimal integer from the raw
    /// text (XTS data unit sequence numbers, ChaCha block counters).
    pub fn int_field(&self, names: &[&str]) -> Option<u64> {
        names
            .iter()
            .find_map(|n| self.raw.get(*n))
            .and_then(|v| v.trim().parse().ok())
    }
}

/// Parse a NIST-style vector file into its blank-line separated cases.
///
/// `[ENCRYPT]`-style section headers are dropped; `[Keylen = 128]`-style
/// parameter headers are kept as the field they name; `#` comments are
/// dropped.
pub fn parse_vectors(content: &str) -> Vec<Vector> {
    let mut out: Vec<Vector> = Vec::new();
    let mut cur = Vector::default();
    let mut started = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if started {
                out.push(core::mem::take(&mut cur));
                started = false;
            }
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && !trimmed.contains('=') {
            continue;
        }

        let line = trimmed
            .strip_prefix('[')
            .and_then(|l| l.strip_suffix(']'))
            .unwrap_or(trimmed);

        let Some((name, value)) = line.split_once('=') else {
            // A bare token marks a negative case in the CAVS files (`FAIL`).
            cur.raw.insert(line.trim().to_lowercase(), String::new());
            started = true;
            continue;
        };
        let name = name.trim().to_lowercase();
        let value = value.trim().to_owned();
        let raw_value = value.to_lowercase();
        // The raw text is always kept: some fields are decimal (`Outputlen`,
        // XTS data unit sequence numbers) even when they happen to be valid
        // hex as well.
        cur.raw.insert(name.clone(), raw_value.clone());

        if value.is_empty() || value == "0" {
            cur.fields.insert(name.clone(), Vec::new());
        } else if let Some(quoted) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            // Some files (boringssl's ChaCha20-Poly1305 set) quote ASCII
            // plaintexts instead of hex encoding them.
            cur.fields.insert(name.clone(), quoted.as_bytes().to_vec());
        } else if let Ok(bytes) = hex::decode(&raw_value) {
            cur.fields.insert(name.clone(), bytes);
        }
        started = true;
    }

    if started {
        out.push(cur);
    }
    out
}

/// Read a vector file relative to the pyca/cryptography vector root.
pub fn read_pyca(path: &str) -> String {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/";
    std::fs::read_to_string(format!("{BASE_DIR}/{path}"))
        .unwrap_or_else(|err| panic!("read {BASE_DIR}{path}: {err}"))
}
