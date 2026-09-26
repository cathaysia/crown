use super::*;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// NIST CAVS 14.1 vectors from OpenSSL evpkdf_ssh.txt (SHA-1, types A-F).
#[test]
fn nist_cavs_sha1_types_a_to_f() {
    let key = hex_to_bytes(
        "0000008055bae931c07fd824bf10add1902b6fbc7c665347383498a686929ff5a25f8e40cb6645ea814fb1a5e0a11f852f86255641e5ed986e83a78bc8269480eac0b0dfd770cab92e7a28dd87ff452466d6ae867cead63b366b1c286e6c4811a9f14c27aea14c5171d49b78c06e3735d36e6a3be321dd5fc82308f34ee1cb17fba94a59",
    );
    let xcghash = hex_to_bytes("a4ebd45934f56792b5112dcd75a1075fdc889245");
    let session_id = xcghash.clone();

    let cases: &[(SshKdfType, usize, &str)] = &[
        (SshKdfType::A, 8, "e2f627c0b43f1ac1"),
        (SshKdfType::B, 8, "58471445f342b181"),
        (
            SshKdfType::C,
            24,
            "1ca9d310f86d51f6cb8e7007cb2b220d55c5281ce680b533",
        ),
        (
            SshKdfType::D,
            24,
            "2c60df8603d34cc1dbb03c11f725a44b44008851c73d6844",
        ),
        (
            SshKdfType::E,
            20,
            "472eb8a26166ae6aa8e06868e45c3b26e6eeed06",
        ),
        (
            SshKdfType::F,
            20,
            "e3e2fdb9d7bc21165a3dbe47e1eceb7764390bab",
        ),
    ];

    for (ty, key_len, expected) in cases {
        let out = derive(
            EvpHash::new_sha1,
            &key,
            &xcghash,
            &session_id,
            *ty,
            *key_len,
        )
        .unwrap();
        assert_eq!(out, hex_to_bytes(expected), "type {ty:?}");
    }
}

#[test]
fn output_longer_than_digest() {
    // Multi-block output must chain HASH(key || xcghash || K(i-1)).
    let out = derive(
        EvpHash::new_sha256,
        b"shared secret key",
        b"exchange hash",
        b"session id",
        SshKdfType::C,
        100,
    )
    .unwrap();
    assert_eq!(out.len(), 100);
    // First 32 bytes equal the single-block derivation.
    let first = derive(
        EvpHash::new_sha256,
        b"shared secret key",
        b"exchange hash",
        b"session id",
        SshKdfType::C,
        32,
    )
    .unwrap();
    assert_eq!(out[..32], first[..]);
}

#[test]
fn rejects_invalid_parameters() {
    assert!(derive(EvpHash::new_sha1, b"k", b"h", b"s", SshKdfType::A, 0).is_err());
}
