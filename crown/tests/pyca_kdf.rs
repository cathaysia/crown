//! Golden vectors for the KDF family from the pyca/cryptography tree: HKDF,
//! PBKDF2, scrypt, Argon2id and ANS X9.63.

mod utils;

use crown::core::CoreRead;
use crown::envelope::EvpHash;
use crown::error::CryptoResult;
use crown::kdf;
use utils::{parse_vectors, read_pyca, Vector};

/// The digests crown can name for `x963_derive_hash`.
fn hash_of(name: &str) -> Option<fn() -> CryptoResult<EvpHash>> {
    Some(match name {
        "SHA-1" => EvpHash::new_sha1,
        "SHA-224" => EvpHash::new_sha224,
        "SHA-256" => EvpHash::new_sha256,
        "SHA-384" => EvpHash::new_sha384,
        "SHA-512" => EvpHash::new_sha512,
        _ => return None,
    })
}

/// `PASSWORD`/`SALT` are plain text in the PBKDF2 and scrypt files; hex
/// everywhere else. The RFC 6070 file spells embedded NUL bytes as `\0`.
fn field_or_text(v: &Vector, names: &[&str]) -> Option<Vec<u8>> {
    if let Some(bytes) = v.field(names) {
        return Some(bytes.to_vec());
    }
    v.raw_field(names).map(unescape)
}

fn unescape(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'0' => out.push(0),
                other => out.push(other),
            }
            i += 2;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Run one HKDF case with the digest the file names; `N` is the digest size.
fn hkdf_case<const N: usize, H, F>(hash_fn: F, v: &Vector, file: &str) -> Option<()>
where
    H: crown::hash::Hash<N> + crown::mac::hmac::MaybeMarshalable,
    F: Fn() -> H + Copy,
{
    let ikm = v.field(&["ikm"])?;
    let salt = v.field(&["salt"])?;
    let info = v.field(&["info"])?;

    // The extract step, where the file provides the PRK.
    if let Some(prk) = v.field(&["prk"]) {
        let computed = kdf::hkdf::extract::<N, H, F>(hash_fn, ikm, salt);
        assert_eq!(
            hex::encode(&computed[..prk.len()]),
            hex::encode(prk),
            "{file}: PRK for IKM {}",
            hex::encode(ikm)
        );
    }

    let len = v.int_field(&["l"])? as usize;
    let okm = v.field(&["okm"])?;
    assert_eq!(okm.len(), len);
    let mut out = vec![0u8; len];
    kdf::hkdf::new::<N, F, H>(hash_fn, ikm, salt, info)
        .read_exact(&mut out)
        .unwrap();
    assert_eq!(
        hex::encode(&out),
        hex::encode(okm),
        "{file}: OKM for IKM {}",
        hex::encode(ikm)
    );
    Some(())
}

#[test]
fn test_pyca_hkdf() {
    use crown::hash::{sha1, sha256, sha512};

    let mut checked = 0usize;
    for file in [
        "KDF/rfc-5869-HKDF-SHA1.txt",
        "KDF/rfc-5869-HKDF-SHA256.txt",
        "KDF/hkdf-generated.txt",
    ] {
        for v in parse_vectors(&read_pyca(file)) {
            let Some(name) = v.raw_field(&["hash"]) else {
                continue;
            };
            let done = match name {
                "SHA-1" => hkdf_case::<20, _, _>(sha1::new, &v, file),
                "SHA-256" => hkdf_case::<32, _, _>(sha256::new256, &v, file),
                "SHA-384" => hkdf_case::<48, _, _>(sha512::new384, &v, file),
                "SHA-512" => hkdf_case::<64, _, _>(sha512::new512, &v, file),
                other => panic!("unexpected digest {other}"),
            };
            checked += done.is_some() as usize;
        }
    }

    assert!(checked >= 8, "only {checked} HKDF vectors were verified");
}

#[test]
fn test_pyca_pbkdf2() {
    use crown::password_hash::pbkdf2;

    let mut checked = 0usize;
    for v in parse_vectors(&read_pyca("KDF/rfc-6070-PBKDF2-SHA1.txt")) {
        let (Some(password), Some(salt), Some(iterations), Some(length), Some(expected)) = (
            field_or_text(&v, &["password"]),
            field_or_text(&v, &["salt"]),
            v.int_field(&["iterations"]),
            v.int_field(&["length"]),
            v.field(&["derived_key"]),
        ) else {
            continue;
        };

        let out = pbkdf2::key::<20, _, _>(
            &password,
            &salt,
            iterations as u32,
            length as usize,
            crown::hash::sha1::new,
        );
        assert_eq!(
            hex::encode(&out),
            hex::encode(expected),
            "PBKDF2-SHA1 with {iterations} iterations"
        );
        checked += 1;
    }

    assert!(checked >= 6, "only {checked} PBKDF2 vectors were verified");
}

#[test]
fn test_pyca_scrypt() {
    use crown::password_hash::scrypt;

    let mut checked = 0usize;
    for v in parse_vectors(&read_pyca("KDF/scrypt.txt")) {
        let (Some(password), Some(salt), Some(n), Some(r), Some(p), Some(length), Some(expected)) = (
            field_or_text(&v, &["password"]),
            field_or_text(&v, &["salt"]),
            v.int_field(&["n"]),
            v.int_field(&["r"]),
            v.int_field(&["p"]),
            v.int_field(&["length"]),
            v.field(&["derived_key"]),
        ) else {
            continue;
        };

        // The RFC 7914 vector with N = 2^20, r = 8 needs a gigabyte.
        if n * r * 128 > 64 * 1024 * 1024 {
            continue;
        }

        let out = scrypt::key(
            &password,
            &salt,
            n as usize,
            r as usize,
            p as usize,
            length as usize,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&out),
            hex::encode(expected),
            "scrypt N={n} r={r} p={p}"
        );
        checked += 1;
    }

    assert!(checked >= 3, "only {checked} scrypt vectors were verified");
}

#[test]
fn test_pyca_argon2id() {
    use crown::password_hash::argon2;

    let mut checked = 0usize;
    for v in parse_vectors(&read_pyca("KDF/argon2id.txt")) {
        let (
            Some(length),
            Some(lanes),
            Some(iter),
            Some(memcost),
            Some(password),
            Some(salt),
            Some(expected),
        ) = (
            v.int_field(&["length"]),
            v.int_field(&["lanes"]),
            v.int_field(&["iter"]),
            v.int_field(&["memcost"]),
            field_or_text(&v, &["pass"]),
            v.field(&["salt"]).map(|s| s.to_vec()),
            v.field(&["output"]),
        )
        else {
            continue;
        };

        // crown's Argon2 has no key (secret) or associated-data inputs.
        if v.field(&["secret"]).is_some_and(|s| !s.is_empty())
            || v.field(&["ad"]).is_some_and(|s| !s.is_empty())
        {
            continue;
        }

        let out = argon2::id_key(
            &password,
            &salt,
            iter as u32,
            memcost as u32,
            lanes as u8,
            length as u32,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&out),
            hex::encode(expected),
            "Argon2id t={iter} m={memcost} p={lanes}"
        );
        checked += 1;
    }

    assert!(
        checked >= 4,
        "only {checked} Argon2id vectors were verified"
    );
}

/// The X9.63 file selects the digest with a `[SHA-1]` section header, which
/// applies to every following case until the next header.
#[test]
fn test_pyca_ansx963() {
    let content = read_pyca("KDF/ansx963_2001.txt");
    let mut checked = 0usize;
    let mut hash = None;
    let mut block = String::new();

    let flush = |block: &str, hash: Option<fn() -> CryptoResult<EvpHash>>, checked: &mut usize| {
        let Some(hash) = hash else { return };
        let vectors = parse_vectors(block);
        let Some(v) = vectors.first() else { return };
        let (Some(z), Some(shared), Some(key_data)) = (
            v.field(&["z"]),
            v.field(&["sharedinfo"]),
            v.field(&["key_data"]),
        ) else {
            return;
        };

        let out = kdf::sskdf::x963_derive_hash(hash, z, shared, key_data.len()).unwrap();
        assert_eq!(
            hex::encode(&out),
            hex::encode(key_data),
            "X9.63 KDF for Z {}",
            hex::encode(z)
        );
        *checked += 1;
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|l| l.strip_suffix(']'))
            .filter(|n| n.starts_with("SHA-"))
        {
            flush(&block, hash, &mut checked);
            block.clear();
            hash = hash_of(name);
            continue;
        }
        if trimmed.is_empty() {
            flush(&block, hash, &mut checked);
            block.clear();
            continue;
        }
        block.push_str(line);
        block.push('\n');
    }
    flush(&block, hash, &mut checked);

    assert!(checked > 50, "only {checked} X9.63 vectors were verified");
}
