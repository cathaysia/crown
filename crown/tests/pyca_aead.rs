mod utils;

use crown::{envelope::EvpAeadCipher, error::CryptoResult};
use utils::{parse_vectors, read_pyca, Vector};

type Aead = fn(&[u8]) -> CryptoResult<EvpAeadCipher>;

#[rustfmt::skip]
const FILES: &[(Aead, &str)] = &[
    (EvpAeadCipher::new_chacha20_poly1305, "ciphers/ChaCha20Poly1305/boringssl.txt"),
    (EvpAeadCipher::new_chacha20_poly1305, "ciphers/ChaCha20Poly1305/openssl.txt"),
    (EvpAeadCipher::new_aes_ocb3::<16, 12>, "ciphers/AES/OCB3/rfc7253.txt"),
    (EvpAeadCipher::new_aes_ocb3::<16, 13>, "ciphers/AES/OCB3/test-vector-1-nonce104.txt"),
    (EvpAeadCipher::new_aes_gcm, "ciphers/AES/GCM/gcmDecrypt128.rsp"),
    (EvpAeadCipher::new_aes_gcm, "ciphers/AES/GCM/gcmDecrypt192.rsp"),
    (EvpAeadCipher::new_aes_gcm, "ciphers/AES/GCM/gcmDecrypt256.rsp"),
    (EvpAeadCipher::new_aes_gcm, "ciphers/AES/GCM/gcmEncryptExtIV128.rsp"),
    (EvpAeadCipher::new_aes_gcm, "ciphers/AES/GCM/gcmEncryptExtIV192.rsp"),
    (EvpAeadCipher::new_aes_gcm, "ciphers/AES/GCM/gcmEncryptExtIV256.rsp"),
];

/// The tag is a separate field in most files; OCB3 appends it to the
/// ciphertext instead.
fn tag_of(v: &Vector) -> Option<Vec<u8>> {
    v.field(&["tag"]).map(|v| v.to_vec())
}

#[test]
fn test_pyca_aead_vectors() {
    let mut checked = 0usize;
    let mut rejected = 0usize;

    for (newer, filename) in FILES {
        for v in parse_vectors(&read_pyca(filename)) {
            let (Some(key), Some(nonce)) = (v.field(&["key"]), v.field(&["iv", "nonce"])) else {
                continue;
            };
            let aad = v.field(&["aad", "ad"]).unwrap_or_default().to_vec();
            let Some(mut pt) = v.field(&["plaintext", "pt", "in"]).map(|v| v.to_vec()) else {
                continue;
            };
            let ct = match v.field(&["ciphertext", "ct"]) {
                Some(ct) => ct.to_vec(),
                None => continue,
            };

            let Ok(cipher) = newer(key) else {
                continue;
            };
            if nonce.len() != cipher.nonce_size() {
                continue;
            }

            let expected = match tag_of(&v) {
                Some(tag) => [ct.clone(), tag].concat(),
                None => ct.clone(),
            };

            let tag = cipher
                .seal_in_place_separate_tag(&mut pt, nonce, &aad)
                .unwrap_or_else(|err| panic!("{filename}: seal: {err:?}"));
            let sealed = [pt.clone(), tag].concat();

            // Negative cases: CAVS marks them with `FAIL`, and a few files
            // (OpenSSL's ChaCha20-Poly1305 set) only flip a bit of the tag.
            let negative = v.has("fail") || (sealed != expected && sealed[..ct.len()] == ct[..]);
            if negative {
                // An incomplete tag is trivially invalid; otherwise the AEAD
                // must reject it.
                if expected.len() >= cipher.tag_size() {
                    let mut buf = expected.clone();
                    assert!(
                        cipher.open_in_place(&mut buf, nonce, &aad).is_err(),
                        "{filename}: negative vector accepted (nonce {})",
                        hex::encode(nonce)
                    );
                }
                rejected += 1;
                continue;
            }

            assert_eq!(
                hex::encode(&sealed),
                hex::encode(&expected),
                "{filename}: seal with nonce {}",
                hex::encode(nonce)
            );

            // And the sealed message must open back to the plaintext.
            let mut buf = expected.clone();
            let opened = cipher
                .open_in_place(&mut buf, nonce, &aad)
                .unwrap_or_else(|err| panic!("{filename}: open: {err:?}"));
            assert_eq!(
                hex::encode(&opened[..]),
                hex::encode(v.field(&["plaintext", "pt", "in"]).unwrap()),
                "{filename}: open"
            );
            checked += 1;
        }
    }

    assert!(checked > 400, "only {checked} AEAD vectors were verified");
    assert!(
        rejected > 3000,
        "only {rejected} negative AEAD vectors were verified"
    );
}
