//! Golden-vector gate for AEAD / modes algorithms added after the original
//! wycheproof suite: AES-GCM-SIV, Ascon-AEAD128, AES Key Wrap (RFC 3394/5649),
//! Ciphertext Stealing, FF1 (NIST SP 800-38G), and DESX.
//!
//! Vectors are lifted from the in-module KATs (cross-checked against the RFCs
//! / NIST samples). Each test asserts a minimum verified-vector count.

use crown::aead::ascon::AsconAead128;
use crown::aead::gcm_siv::AesGcmSiv;
use crown::aead::Aead;
use crown::block::aes::Aes;
use crown::block::des::Desx;
use crown::block::BlockCipher;
use crown::modes::cts::Cts;
use crown::modes::ff1::{ff1_decrypt, ff1_encrypt};
use crown::modes::kw::{key_unwrap, key_unwrap_padded, key_wrap, key_wrap_padded};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// AES-GCM-SIV — RFC 8452 Appendix C.1

#[test]
fn test_golden_aes_gcm_siv() {
    // (pt, aad, expected_ct, expected_tag); key/nonce shared across C.1.
    let key = h("01000000000000000000000000000000");
    let nonce = h("030000000000000000000000");
    let vectors: [(&str, &str, &str, &str); 3] = [
        // Empty plaintext, empty AAD.
        ("", "", "", "dc20e2d83f25705bb49e439eca56de25"),
        // 8-byte plaintext, empty AAD.
        (
            "0100000000000000",
            "",
            "b5d839330ac7b786",
            "578782fff6013b815b287c22493a364c",
        ),
        // 8-byte plaintext, 1-byte AAD.
        (
            "0200000000000000",
            "01",
            "1e6daba35669f427",
            "3b0a1a2560969cdf790d99759abd1508",
        ),
    ];

    let c = AesGcmSiv::new(&key).unwrap();
    let mut checked = 0usize;
    for (idx, (pt, aad, exp_ct, exp_tag)) in vectors.iter().enumerate() {
        let aad_b = h(aad);
        let mut buf = h(pt);
        let tag = c
            .seal_in_place_separate_tag(&mut buf, &nonce, &aad_b)
            .unwrap_or_else(|e| panic!("gcm-siv seal {idx}: {e:?}"));
        assert_eq!(hex::encode(&buf), *exp_ct, "gcm-siv ct vector {idx}");
        assert_eq!(hex::encode(&tag), *exp_tag, "gcm-siv tag vector {idx}");

        // Open must recover the original plaintext.
        c.open_in_place_separate_tag(&mut buf, &tag, &nonce, &aad_b)
            .unwrap_or_else(|e| panic!("gcm-siv open {idx}: {e:?}"));
        assert_eq!(hex::encode(&buf), *pt, "gcm-siv roundtrip {idx}");
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} AES-GCM-SIV vectors verified");
}

// Ascon-AEAD128 — NIST SP 800-232 / Ascon v1.2 KATs (key = nonce = 0)

#[test]
fn test_golden_ascon_aead128() {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    // (pt, aad, expected_ct, expected_tag)
    let vectors: [(&str, &str, &str, &str); 3] = [
        // Empty AAD, empty plaintext.
        ("", "", "", "42213f50a811d2d1d7e4092aa2a42ba4"),
        // Empty AAD, 8-byte plaintext.
        (
            "0011223344556677",
            "",
            "b8ced65849e1478f",
            "1bd7041ee5b9f9d4754313e016afcdf5",
        ),
        // 8-byte AAD + 8-byte plaintext.
        (
            "0011223344556677",
            "0011223344556677",
            "4f3d43d7790affdb",
            "03d1c94596220b23edb647adfe43f4a3",
        ),
    ];

    let c = AsconAead128::new(&key);
    let mut checked = 0usize;
    for (idx, (pt, aad, exp_ct, exp_tag)) in vectors.iter().enumerate() {
        let aad_b = h(aad);
        let mut buf = h(pt);
        let tag = c
            .seal_in_place_separate_tag(&mut buf, &nonce, &aad_b)
            .unwrap_or_else(|e| panic!("ascon seal {idx}: {e:?}"));
        assert_eq!(hex::encode(&buf), *exp_ct, "ascon ct vector {idx}");
        assert_eq!(hex::encode(&tag), *exp_tag, "ascon tag vector {idx}");

        c.open_in_place_separate_tag(&mut buf, &tag, &nonce, &aad_b)
            .unwrap_or_else(|e| panic!("ascon open {idx}: {e:?}"));
        assert_eq!(hex::encode(&buf), *pt, "ascon roundtrip {idx}");
        checked += 1;
    }
    assert!(
        checked >= 3,
        "only {checked} Ascon-AEAD128 vectors verified"
    );
}

// AES Key Wrap — RFC 3394 §4.1-4.3 + RFC 5649 §6

#[test]
fn test_golden_aes_key_wrap() {
    let mut checked = 0usize;

    // RFC 3394 §4.1 — 128-bit KEK, 128-bit key.
    {
        let kek = h("000102030405060708090A0B0C0D0E0F");
        let data = h("00112233445566778899AABBCCDDEEFF");
        let expected = h("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        let c = Aes::new(&kek).unwrap();
        let ct = key_wrap(&c, &data).unwrap();
        assert_eq!(ct, expected, "RFC 3394 4.1 wrap");
        let pt = key_unwrap(&c, &ct).unwrap();
        assert_eq!(pt, data, "RFC 3394 4.1 unwrap");
        checked += 1;
    }

    // RFC 3394 §4.2 — 192-bit KEK, 128-bit key.
    {
        let kek = h("000102030405060708090A0B0C0D0E0F1011121314151617");
        let data = h("00112233445566778899AABBCCDDEEFF");
        let expected = h("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D");
        let c = Aes::new(&kek).unwrap();
        let ct = key_wrap(&c, &data).unwrap();
        assert_eq!(ct, expected, "RFC 3394 4.2 wrap");
        let pt = key_unwrap(&c, &ct).unwrap();
        assert_eq!(pt, data, "RFC 3394 4.2 unwrap");
        checked += 1;
    }

    // RFC 3394 §4.3 — 256-bit KEK, 192-bit key.
    {
        let kek = h("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let data = h("00112233445566778899AABBCCDDEEFF0001020304050607");
        let expected =
            h("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1");
        let c = Aes::new(&kek).unwrap();
        let ct = key_wrap(&c, &data).unwrap();
        assert_eq!(ct, expected, "RFC 3394 4.3 wrap");
        let pt = key_unwrap(&c, &ct).unwrap();
        assert_eq!(pt, data, "RFC 3394 4.3 unwrap");
        checked += 1;
    }

    // RFC 5649 §6 — 20-octet key with a 192-bit KEK (padded, multi-block).
    {
        let kek = h("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let pt = h("c37b7e6492584340bed12207808941155068f738");
        let expected =
            h("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
        let c = Aes::new(&kek).unwrap();
        let ct = key_wrap_padded(&c, &pt).unwrap();
        assert_eq!(ct, expected, "RFC 5649 6 20-byte wrap");
        let out = key_unwrap_padded(&c, &ct).unwrap();
        assert_eq!(out, pt, "RFC 5649 6 20-byte unwrap");
        checked += 1;
    }

    // RFC 5649 §6 — 7-octet key with a 192-bit KEK (single-block path).
    {
        let kek = h("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let pt = h("466f7250617369");
        let expected = h("afbeb0f07dfbf5419200f2ccb50bb24f");
        let c = Aes::new(&kek).unwrap();
        let ct = key_wrap_padded(&c, &pt).unwrap();
        assert_eq!(ct, expected, "RFC 5649 6 7-byte wrap");
        let out = key_unwrap_padded(&c, &ct).unwrap();
        assert_eq!(out, pt, "RFC 5649 6 7-byte unwrap");
        checked += 1;
    }

    assert!(checked >= 5, "only {checked} AES key-wrap vectors verified");
}

// Ciphertext Stealing (CS3) — in-module tests are structural/roundtrip only;
// no published RFC vector is embedded in the library. We verify the CS3
// block-swap property (full-block case) and a partial-final-block roundtrip.

#[test]
fn test_golden_cts() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 16];
    let c = Cts::new(Aes::new(&key).unwrap(), &iv).unwrap();
    let mut checked = 0usize;

    // Full-block case: 32 bytes = 2 blocks. CS3 output is C2||C1 (swapped
    // relative to plain CBC). We compute the CBC chain manually and assert
    // the swap — this is the strongest published-property check available.
    {
        let pt = [0u8; 32];
        let ct = c.encrypt(&pt).unwrap();
        assert_eq!(ct.len(), 32);
        let aes = Aes::new(&key).unwrap();
        let mut c1 = iv;
        aes.encrypt_block(&mut c1);
        let mut c2 = c1;
        aes.encrypt_block(&mut c2);
        assert_eq!(&ct[..16], &c2[..], "CS3 swaps: first half is C2");
        assert_eq!(&ct[16..], &c1[..], "CS3 swaps: second half is C1");
        assert_eq!(c.decrypt(&ct).unwrap(), pt);
        checked += 1;
    }

    // Partial final block: 20 bytes = 1 full block + 4 stolen bytes.
    // In-module test is roundtrip-only (no published vector).
    {
        let pt: Vec<u8> = (0..20u8).collect();
        let ct = c.encrypt(&pt).unwrap();
        assert_eq!(ct.len(), 20, "ciphertext length preserved");
        assert_ne!(ct, pt);
        assert_eq!(c.decrypt(&ct).unwrap(), pt);
        checked += 1;
    }

    assert!(checked >= 2, "only {checked} CTS cases verified");
}

// FF1 — NIST SP 800-38G sample vectors (FF1samples)

#[test]
fn test_golden_ff1() {
    let key = h("2B7E151628AED2A6ABF7158809CF4F3C");
    let mut checked = 0usize;

    // Sample #1: radix 10, empty tweak.
    {
        let pt: Vec<u32> = "0123456789"
            .chars()
            .map(|c| c.to_digit(10).unwrap())
            .collect();
        let ct = ff1_encrypt(&key, b"", 10, &pt).unwrap();
        let ct_s: String = ct
            .iter()
            .map(|&d| std::char::from_digit(d, 10).unwrap())
            .collect();
        assert_eq!(ct_s, "2433477484", "FF1 sample 1");
        let back = ff1_decrypt(&key, b"", 10, &ct).unwrap();
        assert_eq!(back, pt, "FF1 sample 1 roundtrip");
        checked += 1;
    }

    // Sample #2: radix 10, tweak 39 38 37 36 35 34 33 32 31 30.
    {
        let tweak = h("39383736353433323130");
        let pt: Vec<u32> = "0123456789"
            .chars()
            .map(|c| c.to_digit(10).unwrap())
            .collect();
        let ct = ff1_encrypt(&key, &tweak, 10, &pt).unwrap();
        let ct_s: String = ct
            .iter()
            .map(|&d| std::char::from_digit(d, 10).unwrap())
            .collect();
        assert_eq!(ct_s, "6124200773", "FF1 sample 2");
        let back = ff1_decrypt(&key, &tweak, 10, &ct).unwrap();
        assert_eq!(back, pt, "FF1 sample 2 roundtrip");
        checked += 1;
    }

    // Sample #3: radix 36, tweak "7777pqrs777".
    {
        let tweak = h("3737373770717273373737");
        let pt: Vec<u32> = "0123456789abcdefghi"
            .chars()
            .map(|c| c.to_digit(36).unwrap())
            .collect();
        let ct = ff1_encrypt(&key, &tweak, 36, &pt).unwrap();
        let ct_s: String = ct
            .iter()
            .map(|&d| std::char::from_digit(d, 36).unwrap())
            .collect();
        assert_eq!(ct_s, "a9tv40mll9kdu509eum", "FF1 sample 3");
        let back = ff1_decrypt(&key, &tweak, 36, &ct).unwrap();
        assert_eq!(back, pt, "FF1 sample 3 roundtrip");
        checked += 1;
    }

    assert!(checked >= 3, "only {checked} FF1 vectors verified");
}

// DESX — known vector + zero-whitening FIPS DES vector

#[test]
fn test_golden_desx() {
    let mut checked = 0usize;

    // Known DESX vector.
    // k1 = 1122334455667788, k2 = aabbccddeeff0011, k = 0123456789abcdef,
    // pt = 0123456789abcdef → ct = 0c89da6a51f84b49.
    {
        let c = Desx::new(
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        )
        .unwrap();
        let mut buf = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let pt = buf;
        c.encrypt_block(&mut buf);
        assert_eq!(
            &buf[..],
            &[0x0c, 0x89, 0xda, 0x6a, 0x51, 0xf8, 0x4b, 0x49][..],
            "DESX known vector"
        );
        c.decrypt_block(&mut buf);
        assert_eq!(buf, pt, "DESX known vector roundtrip");
        checked += 1;
    }

    // Zero whitening keys → plain DES. FIPS vector:
    // key = pt = 0123456789abcdef → ct = 56cc09e7cfdc4cef.
    {
        let c = Desx::new(
            &[0u8; 8],
            &[0u8; 8],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        )
        .unwrap();
        let mut buf = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let pt = buf;
        c.encrypt_block(&mut buf);
        assert_eq!(
            &buf[..],
            &[0x56, 0xcc, 0x09, 0xe7, 0xcf, 0xdc, 0x4c, 0xef][..],
            "DESX zero-whitening == DES FIPS vector"
        );
        c.decrypt_block(&mut buf);
        assert_eq!(buf, pt, "DESX zero-whitening roundtrip");
        checked += 1;
    }

    assert!(checked >= 2, "only {checked} DESX vectors verified");
}
