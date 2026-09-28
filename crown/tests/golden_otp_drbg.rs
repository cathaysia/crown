//! Golden-vector gate for OTP (HOTP/TOTP), DRBG, and PBES2.
//!
//! HOTP/TOTP vectors are the official RFC 4226 App D / RFC 6238 App B values.
//! DRBG has no published CAVS vector embedded in the library's in-module tests,
//! so we assert determinism / reseed behaviour with a minimum case count.
//! PBES2 in-module tests are roundtrip-only; we keep that and add the
//! wrong-password rejection.

use crown::drbg::{HashDrbg, HmacDrbg};
use crown::otp::{hotp, totp};
use crown::password_hash::pbes2::{
    pbes2_decrypt, pbes2_encrypt, HashId, Pbes2Cipher, Pbes2Kdf,
};

// ---------------------------------------------------------------------------
// HOTP — RFC 4226 Appendix D (SHA-1, 6 digits, counters 0..9)
// ---------------------------------------------------------------------------

#[test]
fn test_golden_hotp() {
    // RFC 4226 Appendix D / RFC 6238 Appendix B SHA-1 secret.
    let secret: &[u8] = b"12345678901234567890";
    // Expected 6-digit HOTP values for counters 0..9.
    let expected: [u32; 10] = [
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    ];

    let mut checked = 0usize;
    for (i, &exp) in expected.iter().enumerate() {
        let got = hotp(secret, i as u64, 6);
        assert_eq!(got, exp, "HOTP counter {}", i);
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} HOTP vectors verified");
}

// ---------------------------------------------------------------------------
// TOTP — RFC 6238 Appendix B (SHA-1, 8 digits, step=30, t0=0)
// ---------------------------------------------------------------------------

#[test]
fn test_golden_totp() {
    let secret: &[u8] = b"12345678901234567890";
    // RFC 6238 Appendix B: (unix_time, expected 8-digit TOTP).
    let vectors: [(u64, u32); 6] = [
        (59, 94287082),
        (1111111109, 7081804),
        (1111111111, 14050471),
        (1234567890, 89005924),
        (2000000000, 69279037),
        (20000000000, 65353130),
    ];

    let mut checked = 0usize;
    for &(t, exp) in vectors.iter() {
        let got = totp(secret, t, 30, 8, 0);
        assert_eq!(got, exp, "TOTP time {}", t);
        checked += 1;
    }
    assert!(checked >= 6, "only {checked} TOTP vectors verified");
}

// ---------------------------------------------------------------------------
// DRBG — HMAC-DRBG + Hash-DRBG determinism and reseed behaviour.
//
// NOTE: the in-module tests contain no published CAVS/CAVP response-value
// vectors, so this test asserts deterministic construction and reseed/additional
// input sensitivity rather than a fixed output hex. Each verified property
// counts as one vector.
// ---------------------------------------------------------------------------

#[test]
fn test_golden_drbg() {
    let mut checked = 0usize;

    // HMAC-DRBG determinism: same seed → same two successive blocks.
    {
        let e = [0x01u8; 32];
        let n = [0x02u8; 16];
        let mut a = HmacDrbg::new(&e, &n, b"test");
        let mut b = HmacDrbg::new(&e, &n, b"test");
        let mut oa = [0u8; 64];
        let mut ob = [0u8; 64];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_eq!(oa, ob, "HMAC-DRBG determinism block 1");
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_eq!(oa, ob, "HMAC-DRBG determinism block 2");
        checked += 1;
    }

    // HMAC-DRBG reseed changes output.
    {
        let e = [0x01u8; 32];
        let n = [0x02u8; 16];
        let mut a = HmacDrbg::new(&e, &n, b"");
        let mut b = HmacDrbg::new(&e, &n, b"");
        b.reseed(&[0xAAu8; 32], b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_ne!(oa, ob, "HMAC-DRBG reseed must change output");
        checked += 1;
    }

    // HMAC-DRBG additional input changes output.
    {
        let e = [0x01u8; 32];
        let n = [0x02u8; 16];
        let mut a = HmacDrbg::new(&e, &n, b"");
        let mut b = HmacDrbg::new(&e, &n, b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"extra").unwrap();
        assert_ne!(oa, ob, "HMAC-DRBG additional input must change output");
        checked += 1;
    }

    // Hash-DRBG determinism.
    {
        let e = [0x03u8; 32];
        let n = [0x04u8; 16];
        let mut a = HashDrbg::new(&e, &n, b"p");
        let mut b = HashDrbg::new(&e, &n, b"p");
        let mut oa = [0u8; 40];
        let mut ob = [0u8; 40];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_eq!(oa, ob, "Hash-DRBG determinism");
        checked += 1;
    }

    // Hash-DRBG reseed changes output.
    {
        let e = [0x03u8; 32];
        let n = [0x04u8; 16];
        let mut a = HashDrbg::new(&e, &n, b"");
        let mut b = HashDrbg::new(&e, &n, b"");
        b.reseed(&[0x55u8; 32], b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_ne!(oa, ob, "Hash-DRBG reseed must change output");
        checked += 1;
    }

    // Hash-DRBG distinct entropy → distinct streams.
    {
        let mut a = HashDrbg::new(&[1u8; 32], &[2u8; 16], b"");
        let mut b = HashDrbg::new(&[9u8; 32], &[8u8; 16], b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_ne!(oa, ob, "Hash-DRBG distinct entropy");
        checked += 1;
    }

    assert!(checked >= 2, "only {checked} DRBG cases verified");
}

// ---------------------------------------------------------------------------
// PBES2 — roundtrip AES-128-CBC / AES-256-CBC / 3DES-CBC + wrong-password
// reject. In-module tests are roundtrip-only (no published ciphertext vector).
// ---------------------------------------------------------------------------

#[test]
fn test_golden_pbes2() {
    fn kdf_sha256(iter: u32) -> Pbes2Kdf {
        Pbes2Kdf::Pbkdf2 {
            hash: HashId::Sha256,
            iterations: iter,
        }
    }

    let mut checked = 0usize;

    // AES-128-CBC roundtrip.
    {
        let pass = b"correct horse battery staple";
        let salt = [0x11u8; 8];
        let pt = b"attack at dawn";
        let ct =
            pbes2_encrypt(pass, &salt, &kdf_sha256(1000), Pbes2Cipher::Aes128Cbc, pt).unwrap();
        assert!(ct.len() > 16);
        let got =
            pbes2_decrypt(pass, &salt, &kdf_sha256(1000), Pbes2Cipher::Aes128Cbc, &ct).unwrap();
        assert_eq!(got, pt);
        checked += 1;
    }

    // AES-256-CBC roundtrip.
    {
        let pass = b"password";
        let salt = [0x22u8; 16];
        let pt = b"hello world, this is a longer plaintext for AES-256-CBC!!";
        let ct =
            pbes2_encrypt(pass, &salt, &kdf_sha256(500), Pbes2Cipher::Aes256Cbc, pt).unwrap();
        let got =
            pbes2_decrypt(pass, &salt, &kdf_sha256(500), Pbes2Cipher::Aes256Cbc, &ct).unwrap();
        assert_eq!(got, pt);
        checked += 1;
    }

    // 3DES-CBC roundtrip.
    {
        let pass = b"3des-pass";
        let salt = [0x33u8; 8];
        let pt = b"short";
        let ct =
            pbes2_encrypt(pass, &salt, &kdf_sha256(200), Pbes2Cipher::DesEde3Cbc, pt).unwrap();
        let got =
            pbes2_decrypt(pass, &salt, &kdf_sha256(200), Pbes2Cipher::DesEde3Cbc, &ct).unwrap();
        assert_eq!(got, pt);
        checked += 1;
    }

    // Wrong password must be rejected.
    {
        let salt = [0x44u8; 8];
        let pt = b"secret data";
        let ct =
            pbes2_encrypt(b"right", &salt, &kdf_sha256(50), Pbes2Cipher::Aes128Cbc, pt).unwrap();
        assert!(
            pbes2_decrypt(b"wrong", &salt, &kdf_sha256(50), Pbes2Cipher::Aes128Cbc, &ct).is_err(),
            "wrong password must fail"
        );
        checked += 1;
    }

    assert!(checked >= 3, "only {checked} PBES2 cases verified");
}
