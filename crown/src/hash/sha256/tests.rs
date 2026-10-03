use sha2::Digest;

#[test]
fn rustcrypto_sha256_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let this = &super::sum256(&buf);

        let rustcrypto = sha2::Sha256::digest(&buf).to_vec();

        assert_eq!(this, rustcrypto.as_slice());
    }
}

/// Golden vectors generated with the vendored OpenSSL 3.5.8 CLI
/// (`printf %s <msg> | openssl dgst -sha256-192`).
#[test]
fn openssl_sha2_256_192_kat() {
    assert_eq!(
        hex::encode(super::sum256_192(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934c"
    );
    assert_eq!(
        hex::encode(super::sum256_192(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9c"
    );

    // Multi-block message, 349 bytes (> 5 SHA-256 blocks).
    let mut long: Vec<u8> = (0u8..=255).collect();
    for _ in 0..3 {
        long.extend_from_slice(b"crown-keccak-kmac-parity-vector");
    }
    assert_eq!(
        hex::encode(super::sum256_192(&long)),
        "c353d064cf350fea0e0c24445323b0268604e6d549f17653"
    );
}

#[test]
fn sha2_256_192_is_truncated_sha256() {
    for _ in 0..100 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        assert_eq!(
            super::sum256_192(&buf).as_slice(),
            &super::sum256(&buf)[..super::SIZE_256_192]
        );
    }
}
