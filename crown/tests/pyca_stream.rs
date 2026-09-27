mod utils;

use crown::{envelope::EvpStreamCipher, error::CryptoResult};
use utils::{parse_vectors, read_pyca, Vector};

/// Stream modes are padding free, so the vectors are applied directly.
///
/// Two families are deliberately absent: ChaCha20 (the pyca files use
/// libsodium's 64/64 counter/nonce split, which crown does not implement; the
/// stream cipher is covered by the wycheproof AEAD vectors and the in-tree
/// RFC 8439 tests) and the CFB-1/CFB-8 segment-size batteries (crown's CFB is
/// the block-sized CFB128 variant these files' MMT cases contradict).
#[rustfmt::skip]
const FILES: &[(fn(&[u8], &[u8]) -> CryptoResult<EvpStreamCipher>, &str)] = &[
    (EvpStreamCipher::new_aes_ctr, "ciphers/AES/CTR/aes-128-ctr.txt"),
    (EvpStreamCipher::new_aes_ctr, "ciphers/AES/CTR/aes-192-ctr.txt"),
    (EvpStreamCipher::new_aes_ctr, "ciphers/AES/CTR/aes-256-ctr.txt"),
    (EvpStreamCipher::new_cast5_ctr, "ciphers/CAST5/cast5-ctr.txt"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64invperm.rsp"),
    (EvpStreamCipher::new_sm4_ctr, "ciphers/SM4/draft-ribose-cfrg-sm4-10-ctr.txt"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64MMT1.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64MMT2.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64MMT3.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64permop.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64subtab.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64varkey.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFB64vartext.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64invperm.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64MMT1.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64MMT2.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64MMT3.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64permop.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64subtab.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64varkey.rsp"),
    (EvpStreamCipher::new_tripledes_cfb,"ciphers/3DES/CFB/TCFBP64vartext.rsp"),
    (EvpStreamCipher::new_blowfish_cfb, "ciphers/Blowfish/bf-cfb.txt"),
    (|key: &[u8], iv: &[u8]| ->CryptoResult<EvpStreamCipher> { EvpStreamCipher::new_camellia_cfb (key, iv, None)} , "ciphers/Camellia/camellia-cfb.txt"),
    (EvpStreamCipher::new_cast5_cfb, "ciphers/CAST5/cast5-cfb.txt"),
    (EvpStreamCipher::new_idea_cfb, "ciphers/IDEA/idea-cfb.txt"),
    (EvpStreamCipher::new_kseed_cfb, "ciphers/SEED/seed-cfb.txt"),
    (EvpStreamCipher::new_sm4_cfb, "ciphers/SM4/draft-ribose-cfrg-sm4-10-cfb.txt"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIinvperm.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIMMT1.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIMMT2.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIMMT3.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBinvperm.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIpermop.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIsubtab.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIvarkey.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBIvartext.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBMMT1.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBMMT2.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBMMT3.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBpermop.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBsubtab.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBvarkey.rsp"),
    (EvpStreamCipher::new_tripledes_ofb,"ciphers/3DES/OFB/TOFBvartext.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBGFSbox128.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBGFSbox192.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBGFSbox256.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBKeySbox128.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBKeySbox192.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBKeySbox256.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBMMT128.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBMMT192.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBMMT256.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarKey128.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarKey192.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarKey256.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarTxt128.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarTxt192.rsp"),
    (EvpStreamCipher::new_aes_ofb,"ciphers/AES/OFB/OFBVarTxt256.rsp"),
    (EvpStreamCipher::new_blowfish_ofb, "ciphers/Blowfish/bf-ofb.txt"),
    (|key: &[u8], iv: &[u8]| ->CryptoResult<EvpStreamCipher> { EvpStreamCipher::new_camellia_ofb (key, iv, None)}, "ciphers/Camellia/camellia-ofb.txt"),
    (EvpStreamCipher::new_cast5_ofb, "ciphers/CAST5/cast5-ofb.txt"),
    (EvpStreamCipher::new_idea_ofb, "ciphers/IDEA/idea-ofb.txt"),
    (EvpStreamCipher::new_kseed_ofb, "ciphers/SEED/seed-ofb.txt"),
    (EvpStreamCipher::new_sm4_ofb, "ciphers/SM4/draft-ribose-cfrg-sm4-10-ofb.txt"),];

/// 3DES files carry a single 8-byte `KEYs` (`K1 = K2 = K3`) or
/// `key1`/`key2`/`key3`; the rest use `KEY`.
fn tripledes_key(key: &[u8]) -> Vec<u8> {
    match key.len() {
        8 => [key, key, key].concat(),
        16 => [&key[..8], &key[8..], &key[..8]].concat(),
        _ => key.to_vec(),
    }
}

fn key_of(v: &Vector) -> Option<Vec<u8>> {
    v.concat(&["key", "keys"])
        .or_else(|| v.concat(&["key1", "key2", "key3"]))
}

fn iv_of(v: &Vector) -> Option<Vec<u8>> {
    v.field(&["iv", "nonce"]).map(|v| v.to_vec())
}

/// `PLAINTEXT`/`CIPHERTEXT`, or the numbered `PLAINTEXT1..3` variants next to
/// `IV1..3`.
fn cases_of(v: &Vector, shared_iv: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if let (Some(pt), Some(ct), Some(iv)) = (
        v.field(&["plaintext"]),
        v.field(&["ciphertext"]),
        shared_iv,
    ) {
        return vec![(pt.to_vec(), ct.to_vec(), iv.to_vec())];
    }

    let mut out = Vec::new();
    for i in 1..=3 {
        let (p, c) = (format!("plaintext{i}"), format!("ciphertext{i}"));
        let Some(pt) = v.field(&[p.as_str()]) else {
            continue;
        };
        let Some(ct) = v.field(&[c.as_str()]) else {
            continue;
        };
        let iv = v
            .field(&[format!("iv{i}").as_str()])
            .or(shared_iv)
            .expect("numbered or shared iv");
        out.push((pt.to_vec(), ct.to_vec(), iv.to_vec()));
    }
    out
}

#[test]
fn test_pyca_stream_vectors() {
    let mut checked = 0usize;

    for (newer, filename) in FILES {
        for v in parse_vectors(&read_pyca(filename)) {
            let Some(raw_key) = key_of(&v) else {
                continue;
            };
            let key = if filename.contains("3DES") {
                tripledes_key(&raw_key)
            } else {
                raw_key
            };
            let shared_iv = iv_of(&v);

            for (pt, expected_ct, iv) in cases_of(&v, shared_iv.as_deref()) {
                if pt.is_empty() {
                    continue;
                }
                let Ok(mut cipher) = newer(&key, &iv) else {
                    // Parameter combination this file uses is unsupported.
                    continue;
                };
                let mut buf = pt.clone();
                cipher.encrypt(&mut buf).unwrap();
                assert_eq!(
                    hex::encode(&buf),
                    hex::encode(&expected_ct),
                    "{filename}: key={} iv={}",
                    hex::encode(&key),
                    hex::encode(&iv)
                );

                let mut cipher = newer(&key, &iv).unwrap();
                let mut buf = expected_ct.clone();
                cipher.decrypt(&mut buf).unwrap();
                assert_eq!(hex::encode(&buf), hex::encode(&pt), "{filename}: decrypt");
                checked += 1;
            }
        }
    }

    assert!(checked > 2000, "only {checked} stream vectors were verified");
}
