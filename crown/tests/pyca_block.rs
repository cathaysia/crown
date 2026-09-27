mod utils;

use crown::{envelope::EvpBlockCipher, error::CryptoResult, padding::NoPadding};
use utils::{parse_vectors, read_pyca, Vector};

/// Raw CBC vectors carry no padding, so the padding is switched off and the
/// cipher is driven with already-complete blocks.
type Cbc = fn(&[u8], &[u8]) -> CryptoResult<EvpBlockCipher>;

#[rustfmt::skip]
const FILES: &[(Cbc, &str, usize)] = &[
    // 3DES: NIST "TCBCI"/"TCBC" permutation / substitution / variable-key
    // batteries plus the multi-block MMT files.
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIinvperm.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIMMT1.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIMMT2.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIMMT3.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIpermop.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIsubtab.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIvarkey.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCIvartext.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCinvperm.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCMMT1.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCMMT2.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCMMT3.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCpermop.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCsubtab.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCvarkey.rsp", 8),
    (tripledes_cbc, "ciphers/3DES/CBC/TCBCvartext.rsp", 8),
    // AES (NIST CAVS CBC batteries).
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCGFSbox128.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCGFSbox192.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCGFSbox256.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCKeySbox128.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCKeySbox192.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCKeySbox256.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCMMT128.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCMMT192.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCMMT256.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarKey128.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarKey192.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarKey256.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarTxt128.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarTxt192.rsp", 16),
    (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarTxt256.rsp", 16),
    // Other ciphers that have a CBC mode.
    (EvpBlockCipher::new_blowfish_cbc, "ciphers/Blowfish/bf-cbc.txt", 8),
    (|key: &[u8], iv: &[u8]| EvpBlockCipher::new_camellia_cbc(key, iv, None), "ciphers/Camellia/camellia-cbc.txt", 16),
    (EvpBlockCipher::new_cast5_cbc, "ciphers/CAST5/cast5-cbc.txt", 8),
    (EvpBlockCipher::new_idea_cbc, "ciphers/IDEA/idea-cbc.txt", 8),
    (|key: &[u8], iv: &[u8]| EvpBlockCipher::new_rc2_cbc(key, iv, None), "ciphers/RC2/rc2-cbc.txt", 8),
    (EvpBlockCipher::new_sm4_cbc, "ciphers/SM4/draft-ribose-cfrg-sm4-10-cbc.txt", 16),
];

/// Vector files key their key material as `KEY`, `KEYs` (the three-key 3DES
/// form) or `key1`/`key2`/`key3`; data comes either single (`PLAINTEXT`) or
/// numbered (`PLAINTEXT1..3` next to `IV1..3`).
fn key_of(v: &Vector) -> Option<Vec<u8>> {
    v.concat(&["key", "keys"])
        .or_else(|| v.concat(&["key1", "key2", "key3"]))
}

/// The NIST 3DES batteries carry a single 8-byte key (`K1 = K2 = K3`) or the
/// two-key form; expand either into a 24-byte 3DES key.
fn tripledes_key(key: &[u8]) -> Vec<u8> {
    match key.len() {
        8 => [key, key, key].concat(),
        16 => [&key[..8], &key[8..], &key[..8]].concat(),
        _ => key.to_vec(),
    }
}

fn tripledes_cbc(key: &[u8], iv: &[u8]) -> CryptoResult<EvpBlockCipher> {
    EvpBlockCipher::new_tripledes_cbc(&tripledes_key(key), iv)
}

fn cases_of(v: &Vector) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if let (Some(pt), Some(ct), Some(iv)) = (
        v.field(&["plaintext"]),
        v.field(&["ciphertext"]),
        v.field(&["iv"]),
    ) {
        return vec![(pt.to_vec(), ct.to_vec(), iv.to_vec())];
    }

    let mut out = Vec::new();
    for i in 1..=3 {
        let (p, c, iv) = (
            format!("plaintext{i}"),
            format!("ciphertext{i}"),
            format!("iv{i}"),
        );
        let Some(iv) = v.field(&[iv.as_str(), "iv"]) else {
            continue;
        };
        if let (Some(pt), Some(ct)) = (v.field(&[p.as_str()]), v.field(&[c.as_str()])) {
            out.push((pt.to_vec(), ct.to_vec(), iv.to_vec()));
        }
    }
    out
}

#[test]
fn test_pyca_block_vectors() {
    let mut checked = 0usize;

    for (newer, filename, block_size) in FILES {
        let content = read_pyca(filename);

        for v in parse_vectors(&content) {
            let Some(key) = key_of(&v) else {
                continue;
            };

            for (pt, expected_ct, iv) in cases_of(&v) {
                if pt.is_empty() || pt.len() % block_size != 0 {
                    continue;
                }
                assert_eq!(
                    expected_ct.len(),
                    pt.len(),
                    "{filename}: plaintext/ciphertext length mismatch"
                );

                // Encryption: padding off, and `pos = len - block_size` keeps
                // the whole input as complete blocks.
                let mut cipher = newer(&key, &iv).unwrap();
                cipher.set_padding(Box::new(NoPadding));
                let mut buf = pt.clone();
                let pos = buf.len() - block_size;
                let n = cipher.encrypt(&mut buf, pos).unwrap();
                assert_eq!(n, pt.len());
                assert_eq!(
                    hex::encode(&buf),
                    hex::encode(&expected_ct),
                    "{filename}: encrypt with key {}",
                    hex::encode(&key)
                );

                // The expected ciphertext must decrypt back to the plaintext.
                let mut cipher = newer(&key, &iv).unwrap();
                cipher.set_padding(Box::new(NoPadding));
                let mut buf = expected_ct.clone();
                let n = cipher.decrypt(&mut buf).unwrap();
                assert_eq!(n, pt.len());
                assert_eq!(hex::encode(&buf[..n]), hex::encode(&pt), "{filename}: decrypt");
                checked += 1;
            }
        }
    }

    assert!(checked > 1000, "only {checked} CBC vectors were verified");
}
