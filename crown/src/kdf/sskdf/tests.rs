use super::*;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Vectors from OpenSSL evpkdf_ss.txt (SP 800-56C One-Step KDF).
#[test]
fn openssl_hash_vectors() {
    let cases: &[(HashFactory, &str, &str, &str)] = &[
        (
            EvpHash::new_sha1,
            "d09a6b1a472f930db4f5e6b967900744",
            "b117255ab5f1b6b96fc434b0",
            "b5a3c52e97ae6e8c5069954354eab3c7",
        ),
        (
            EvpHash::new_sha1,
            "3f57fd3fd56199b3eb33890f7ee28180",
            "7a5056ba4fdb034c7cb6c4fe",
            "e51ebd30a8c4b8449b0fb29d9adc11af",
        ),
        (
            EvpHash::new_sha256,
            "afc4e154498d4770aa8365f6903dc83b",
            "662af20379b29d5ef813e655",
            "f0b80d6ae4c1e19e2105a37024e35dc6",
        ),
    ];

    for (hash, secret, info, expected) in cases {
        let out = derive_hash(*hash, &hex_to_bytes(secret), &hex_to_bytes(info), 16).unwrap();
        assert_eq!(out, hex_to_bytes(expected));
    }
}

#[test]
fn openssl_hmac_vectors() {
    let out = derive_hmac(
        EvpHash::new_sha256_hmac,
        &hex_to_bytes("532f5131e0a2fecc722f87e5aa2062cb"),
        &hex_to_bytes("6ee6c00d70a6cd14bd5a4e8fcfec8386"),
        &hex_to_bytes("861aa2886798231259bd0314"),
        16,
    )
    .unwrap();
    assert_eq!(out, hex_to_bytes("13479e9a91dd20fdd757d68ffe8869fb"));

    let out = derive_hmac(
        EvpHash::new_sha256_hmac,
        &hex_to_bytes("d504c1c41a499481ce88695d18ae2e8f"),
        &hex_to_bytes("cb09b565de1ac27a50289b3704b93afd"),
        &hex_to_bytes("5ed3768c2c7835943a789324"),
        16,
    )
    .unwrap();
    assert_eq!(out, hex_to_bytes("f081c0255b0cae16edc6ce1d6c9d12bc"));

    // With an empty salt the HMAC key becomes a zero string of digest size.
    let no_salt = derive_hmac(
        EvpHash::new_sha256_hmac,
        &[],
        &hex_to_bytes("6ee6c00d70a6cd14bd5a4e8fcfec8386"),
        &hex_to_bytes("861aa2886798231259bd0314"),
        16,
    )
    .unwrap();
    let zeros = derive_hmac(
        EvpHash::new_sha256_hmac,
        &[0u8; 32],
        &hex_to_bytes("6ee6c00d70a6cd14bd5a4e8fcfec8386"),
        &hex_to_bytes("861aa2886798231259bd0314"),
        16,
    )
    .unwrap();
    assert_eq!(no_salt, zeros);
}

// KMAC-128 vector from evpkdf_ss.txt (H(x) = KMAC, single call).
#[test]
fn openssl_kmac_vector() {
    let out = derive_kmac128(
        &[],
        &hex_to_bytes("EAD54AE33FFAFFE7875610390ADBA9DFB291EE8C1920CB13452FDF851E0A6DBBB862FD8811F8CB29CDEC13591D8C047065FCD2"),
        &hex_to_bytes("A2641090E75D5BDC0B23CCD49BB02DC63B41D3F38E0947D491DFDDC734A8582DF5C961EFE586378317AB7E5821DE3146EA26C823EE4FA48C22D7142E5BDEF50DE8BD9940E6E5AC58A6441DFCD9D5C8F6199D05BEBE1394C706F2354AC902EB5C4533EB00000400"),
        128,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("4460D885F11A2E173F65FD89A5CE6668075C2592A2D9C356B977EF39C09D3A00DFFCB56687F053397ADD00D873C2E8A89A3A43C6D7A6AFC8A6AD08E2700B899DD4808771FC36E4E46075009F13D39237F3E815A4B8A3DC439727AA814082077E4544D2B65805EC122973B48097861591DF0F9A8048BCF945702EA7578D2B481C")
    );
}

// X9.63 KDF vectors from evpkdf_x963.txt (NIST).
#[test]
fn openssl_x963_vectors() {
    let out = x963_derive_hash(
        EvpHash::new_sha1,
        &hex_to_bytes("fd17198b89ab39c4ab5d7cca363b82f9fd7e23c3984dc8a2"),
        &hex_to_bytes("856a53f3e36a26bbc5792879f307cce2"),
        128,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("6e5fad865cb4a51c95209b16df0cc490bc2c9064405c5bccd4ee4832a531fbe7f10cb79e2eab6ab1149fbd5a23cfdabc41242269c9df22f628c4424333855b64e95e2d4fb8469c669f17176c07d103376b10b384ec5763d8b8c610409f19aca8eb31f9d85cc61a8d6d4a03d03e5a506b78d6847e93d295ee548c65afedd2efec")
    );

    let out = x963_derive_hash(
        EvpHash::new_sha256,
        &hex_to_bytes("fd17198b89ab39c4ab5d7cca363b82f9fd7e23c3984dc8a2"),
        &hex_to_bytes("856a53f3e36a26bbc5792879f307cce2"),
        96,
    )
    .unwrap();
    assert_eq!(out.len(), 96);
}

#[test]
fn rejects_invalid_parameters() {
    assert!(derive_hash(EvpHash::new_sha256, b"z", b"i", 0).is_err());
    assert!(derive_hmac(EvpHash::new_sha256_hmac, b"s", b"z", b"i", 0).is_err());
}
