use super::*;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Vectors from OpenSSL evpkdf_ikev2.txt (SHA-256).
#[test]
fn openssl_vectors() {
    let ni = hex_to_bytes("3651FEF5C9C35E93");
    let nr = hex_to_bytes("C09A8B90A3F04D59");
    let secret = hex_to_bytes(
        "D084A30166A50FB7325C3960874A839449EF9741C2F4F947D0201DD8C1269273D79509F37E3CA3EB4FA2FE2A28254E289CD3F34DAD4EB4DF1A07685A4B8A94FA61E2491F7598B3CE65547FF133B3F63D1AC4175EAA695033F3CEDB026A6873A36455172A8540B8A5D23A0143BED0390EE49B168269D75FFFEE9FB62BE965993C",
    );

    // SKEYSEED generation (mode GEN).
    let seedkey = seedkey_gen(EvpHash::new_sha256_hmac, &secret, &ni, &nr).unwrap();
    assert_eq!(
        seedkey,
        hex_to_bytes("EFAA7AB0EAA85A3D0BE2100CD4B6FE00FF5025A9EAFDDB3EF518E9F0D3FE60E6")
    );

    // DKM from the seed key with both SPIs set.
    let spii = hex_to_bytes("8E5C3AE507221684");
    let spir = hex_to_bytes("B1F201BB155C3ACD");
    let dkm = dkm(
        EvpHash::new_sha256_hmac,
        &seedkey,
        &ni,
        &nr,
        Some(&spii),
        Some(&spir),
        None,
        224,
    )
    .unwrap();
    assert_eq!(
        dkm,
        hex_to_bytes(
            "462B9DD525D4FD71169174272779E704BAF62C6231779AE9EFE8C58B21916B42010164AF2111EBD762F6916CA9A6F0EE05C8B320E4EE27705521DE2589ADEA1878F1A551738AF7C88DC4F0BB0C096A3F7D1F1A670FC79F49F678D60D665BB3710C8657F03BA9F62B9A818D7A228968C506E237AE9502AA6DB395C61EA6A3E79504F86B7368BFB5423DF79E48809BBCCD49FD826D024F63D7C2A5566400A12E736AA034510428F5EA008FE2FC16886FA388274EA6C2B4FCFC6141BF04F8207EF8AFC224EA1059CB220DC0B23AC0E4CCDA495A4E131B1D56E223ABA5A48E8ED1F5"
        )
    );
}

#[test]
fn rekey_and_child_sa() {
    let ni = hex_to_bytes("3651FEF5C9C35E93");
    let nr = hex_to_bytes("C09A8B90A3F04D59");
    let sk_d = hex_to_bytes("462B9DD525D4FD71169174272779E704BAF62C6231779AE9EFE8C58B21916B42");
    let new_secret = hex_to_bytes(
        "D084A30166A50FB7325C3960874A839449EF9741C2F4F947D0201DD8C1269273D79509F37E3CA3EB4FA2FE2A28254E289CD3F34DAD4EB4DF1A07685A4B8A94FA61E2491F7598B3CE65547FF133B3F63D1AC4175EAA695033F3CEDB026A6873A36455172A8540B8A5D23A0143BED0390EE49B168269D75FFFEE9FB62BE965993C",
    );

    // Rekey produces a fresh seed key of digest size.
    let rekey = seedkey_rekey(EvpHash::new_sha256_hmac, &sk_d, &new_secret, &ni, &nr).unwrap();
    assert_eq!(rekey.len(), 32);

    // Child-SA DKM from SK_d without SPIs.
    let child = dkm(
        EvpHash::new_sha256_hmac,
        &sk_d,
        &ni,
        &nr,
        None,
        None,
        None,
        64,
    )
    .unwrap();
    assert_eq!(child.len(), 64);
    assert_ne!(child[..32], child[32..]);
}

#[test]
fn rejects_invalid_parameters() {
    let short_nonce = [0u8; 7];
    assert!(seedkey_gen(
        EvpHash::new_sha256_hmac,
        &[0u8; 32],
        &short_nonce,
        &[0u8; 8]
    )
    .is_err());
    // Secret shorter than 28 bytes is rejected.
    assert!(seedkey_gen(EvpHash::new_sha256_hmac, &[0u8; 27], &[0u8; 8], &[0u8; 8]).is_err());
    // Invalid parameter combination: SPIs and shared secret together.
    assert!(dkm(
        EvpHash::new_sha256_hmac,
        &[0u8; 32],
        &[0u8; 8],
        &[0u8; 8],
        Some(&[0u8; 8]),
        Some(&[0u8; 8]),
        Some(&[0u8; 32]),
        32
    )
    .is_err());
}
