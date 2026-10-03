use super::*;

fn aes(kek: &[u8]) -> Aes {
    Aes::new(kek).unwrap()
}

// RFC 3394 §4.1 — 128-bit KEK, 128-bit key
#[test]
fn rfc3394_4_1() {
    let kek = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let expected = [
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B,
        0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    ];
    let c = aes(&kek);
    let ct = key_wrap(&c, &data).unwrap();
    assert_eq!(&ct[..], &expected[..]);
    let pt = key_unwrap(&c, &ct).unwrap();
    assert_eq!(&pt[..], &data[..]);
}

// RFC 3394 §4.2 — 192-bit KEK, 128-bit key
#[test]
fn rfc3394_4_2() {
    let kek = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let expected = [
        0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35, 0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE,
        0xD2, 0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D,
    ];
    let c = aes(&kek);
    let ct = key_wrap(&c, &data).unwrap();
    assert_eq!(&ct[..], &expected[..]);
    let pt = key_unwrap(&c, &ct).unwrap();
    assert_eq!(&pt[..], &data[..]);
}

// RFC 3394 §4.3 — 256-bit KEK, 192-bit key
#[test]
fn rfc3394_4_3() {
    let kek = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    let expected = [
        0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F, 0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71,
        0xE4, 0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95, 0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25,
        0x4D, 0xA1,
    ];
    let c = aes(&kek);
    let ct = key_wrap(&c, &data).unwrap();
    assert_eq!(&ct[..], &expected[..]);
    let pt = key_unwrap(&c, &ct).unwrap();
    assert_eq!(&pt[..], &data[..]);
}

// RFC 5649 §6 — 20-octet key with a 192-bit KEK
#[test]
fn rfc5649_6_20_byte() {
    let kek = [
        0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
        0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
    ];
    let pt = [
        0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89, 0x41,
        0x15, 0x50, 0x68, 0xf7, 0x38,
    ];
    let expected = [
        0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22, 0x48,
        0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73, 0xfa, 0x54,
        0x3b, 0x6a,
    ];
    let c = aes(&kek);
    let ct = key_wrap_padded(&c, &pt).unwrap();
    assert_eq!(&ct[..], &expected[..]);
    let out = key_unwrap_padded(&c, &ct).unwrap();
    assert_eq!(&out[..], &pt[..]);
}

// RFC 5649 §6 — 7-octet key with a 192-bit KEK (single-block path)
#[test]
fn rfc5649_6_7_byte() {
    let kek = [
        0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
        0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
    ];
    let pt = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
    let expected = [
        0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b, 0xb2,
        0x4f,
    ];
    let c = aes(&kek);
    let ct = key_wrap_padded(&c, &pt).unwrap();
    assert_eq!(&ct[..], &expected[..]);
    let out = key_unwrap_padded(&c, &ct).unwrap();
    assert_eq!(&out[..], &pt[..]);
}

#[test]
fn wrap_bad_input_len() {
    let c = aes(&[0u8; 16]);
    assert!(key_wrap(&c, &[0u8; 8]).is_err());
    assert!(key_wrap(&c, &[0u8; 12]).is_err());
    assert!(key_unwrap(&c, &[0u8; 16]).is_err());
    assert!(key_wrap_padded(&c, &[]).is_err());
}

#[test]
fn unwrap_tampered_tag_fails() {
    let kek = [
        0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
        0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
    ];
    let c = aes(&kek);
    let ct = key_wrap_padded(&c, b"hello world!!").unwrap();
    let mut bad = ct.clone();
    bad[0] ^= 0xff;
    assert!(key_unwrap_padded(&c, &bad).is_err());
}

/// The inverse-cipher variants roundtrip and are distinct from the forward
/// direction (matching OpenSSL's AES-*-WRAP-INV / WRAP-PAD-INV semantics).
#[test]
fn inverse_variants_roundtrip() {
    let kek = [
        0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
        0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
    ];
    let c = aes(&kek);
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let inv_ct = key_wrap_inv(&c, &data).unwrap();
    assert_ne!(inv_ct, key_wrap(&c, &data).unwrap());
    assert_eq!(key_unwrap_inv(&c, &inv_ct).unwrap(), data);
    // The forward unwrap must reject an inverse-wrapped value.
    assert!(key_unwrap(&c, &inv_ct).is_err());

    let padded = b"some key material";
    let padded_inv_ct = key_wrap_padded_inv(&c, padded).unwrap();
    assert_ne!(padded_inv_ct, key_wrap_padded(&c, padded).unwrap());
    assert_eq!(key_unwrap_padded_inv(&c, &padded_inv_ct).unwrap(), padded);
}

/// RFC 3217 — Triple-DES key wrap roundtrip with the fixed CEK/KEK used by
/// the RFC 3217 §4 test: wrap(kek, cek) unwraps to the parity-fixed CEK and
/// the tampered ciphertext fails the ICV check.
#[test]
fn des3_wrap_roundtrip() {
    let kek = TripleDes::new(&[
        0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e,
        0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
    ])
    .unwrap();
    let mut cek = [0x01u8; 24];
    let iv = [0x0fu8; 8];
    let ct = des3_key_wrap(&kek, &cek, &iv).unwrap();
    assert_eq!(ct.len(), 40);
    let unwrapped = des3_key_unwrap(&kek, &ct).unwrap();
    assert_eq!(unwrapped, cek);

    let mut bad = ct.clone();
    bad[7] ^= 0x01;
    assert!(des3_key_unwrap(&kek, &bad).is_err());
    // Wrong KEK fails the ICV check.
    let kek2 = TripleDes::new(&[0x02u8; 24]).unwrap();
    assert!(des3_key_unwrap(&kek2, &ct).is_err());
}

/// Two-key (16-byte) CEKs wrap after expansion handling and unwrap to the
/// parity-fixed 16 bytes.
#[test]
fn des3_wrap_two_key() {
    let kek = TripleDes::new(&[0x55u8; 24]).unwrap();
    let cek = [0x11u8; 16];
    let ct = des3_key_wrap(&kek, &cek, &[0; 8]).unwrap();
    assert_eq!(ct.len(), 32);
    let out = des3_key_unwrap(&kek, &ct).unwrap();
    assert_eq!(out, cek.to_vec());
    assert!(des3_key_wrap(&kek, &[0u8; 17], &[0; 8]).is_err());
}

/// Byte-exact vectors generated with a locally built OpenSSL 3.5.8 EVP
/// interface (AES-128-WRAP-INV, AES-192-WRAP-PAD-INV, DES3-WRAP).
#[test]
fn openssl_wrap_golden_vectors() {
    let k16: Vec<u8> = (0..16u8).map(|i| 0x11 + i).collect();
    let k24: Vec<u8> = (0..24u8).map(|i| 0xa0 + i).collect();
    let data16: Vec<u8> = (0..16u8).collect();
    let data20: Vec<u8> = (0..20u8).map(|i| 0xc3 + i).collect();

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // AES-128-WRAP-INV of data16 with k16.
    {
        let c = aes(&k16);
        let ct = key_wrap_inv(&c, &data16).unwrap();
        assert_eq!(ct, hex("6cca50e90c34d84fcc0205471da2d79112c241e4b9ba77b8"));
        assert_eq!(key_unwrap_inv(&c, &ct).unwrap(), data16);
    }
    // AES-192-WRAP-PAD-INV of data20 with k24.
    {
        let c = aes(&k24);
        let ct = key_wrap_padded_inv(&c, &data20).unwrap();
        assert_eq!(
            ct,
            hex("d46b749d89a21ca3e76aca398f00fe2117186810f458254fdebdff5e8a0474d7")
        );
        assert_eq!(key_unwrap_padded_inv(&c, &ct).unwrap(), data20);
    }
    // DES3-WRAP of k24 with k24 as KEK: unwrap-only (OpenSSL generates the
    // per-invocation IV internally).
    {
        let kek = TripleDes::new(&k24).unwrap();
        let ct =
            hex("56becc5cbc83763b0a7c0275ea947ab4909e7696697456710a1db00d9245709f098d62d626fa5bd2");
        let out = des3_key_unwrap(&kek, &ct).unwrap();
        assert_eq!(out, k24);
    }
}
