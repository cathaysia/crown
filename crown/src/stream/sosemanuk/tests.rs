use super::*;
use crate::stream::StreamCipher;
// hex is a dev-dependency

#[test]
fn test_sosemanuk_rust_crypto_short_key() {
    // Reference C Implementation (Vector 128, Test 1) from rust-crypto
    let key = hex::decode("A7C083FEB7").unwrap();
    let iv = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected =
        hex::decode("FE81D2162C9A100D04895C454A77515BBE6A431A935CB90E2221EBB7EF502328").unwrap();

    let mut cipher = Sosemanuk::new(&key).unwrap();
    cipher.set_iv(&iv).unwrap();

    let mut out = vec![0u8; expected.len()];
    cipher.xor_key_stream(&mut out).unwrap();

    assert_eq!(out, expected);
}

#[test]
fn test_sosemanuk_estream_256() {
    // ECRYPT Set 1, Vector 0 (Standard 256-bit Key)
    let key =
        hex::decode("8000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let iv = hex::decode("00000000000000000000000000000000").unwrap();
    let expected =
        hex::decode("1782FABFF497A0E89E16E1BCF22F0FE8AA8C566D293AA35B2425E4F26E31C3E7").unwrap();

    let mut cipher = Sosemanuk::new(&key).unwrap();
    cipher.set_iv(&iv).unwrap();

    let mut out = vec![0u8; expected.len()];
    cipher.xor_key_stream(&mut out).unwrap();

    assert_eq!(out, expected);
}

#[test]
fn test_sosemanuk_multi_call() {
    let key = vec![0u8; 16];
    let iv = vec![0u8; 16];

    let mut cipher = Sosemanuk::new(&key).unwrap();
    cipher.set_iv(&iv).unwrap();

    let mut out1 = vec![0u8; 10];
    let mut out2 = vec![0u8; 10];
    cipher.xor_key_stream(&mut out1).unwrap();
    cipher.xor_key_stream(&mut out2).unwrap();

    let mut cipher2 = Sosemanuk::new(&key).unwrap();
    cipher2.set_iv(&iv).unwrap();
    let mut out_combined = vec![0u8; 20];
    cipher2.xor_key_stream(&mut out_combined).unwrap();

    assert_eq!(&out_combined[..10], &out1);
    assert_eq!(&out_combined[10..], &out2);
}
