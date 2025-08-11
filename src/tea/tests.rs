//! Tests for TEA cipher implementation

use super::*;

/// A sample test key for when we just want to initialize a cipher
const TEST_KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

/// Test that the block size for tea is correct
#[test]
fn test_blocksize() {
    let c = Tea::new(&TEST_KEY).expect("NewCipher should not return error");

    assert_eq!(
        c.block_size(),
        Tea::BLOCK_SIZE,
        "cipher.block_size() returned incorrect value"
    );
}

/// Test that invalid key sizes return an error
#[test]
fn test_invalid_key_size() {
    let key_too_long = [0u8; Tea::KEY_SIZE + 1];
    assert!(
        Tea::new(&key_too_long).is_err(),
        "invalid key size {} should result in an error",
        key_too_long.len()
    );

    let key_too_short = [0u8; Tea::KEY_SIZE - 1];
    assert!(
        Tea::new(&key_too_short).is_err(),
        "invalid key size {} should result in an error",
        key_too_short.len()
    );
}

/// Test vector structure
struct TeaTest {
    rounds: usize,
    key: [u8; 16],
    plaintext: [u8; 8],
    ciphertext: [u8; 8],
}

/// Test vectors sourced from https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/tea.testvec
const TEA_TESTS: &[TeaTest] = &[
    TeaTest {
        rounds: NUM_ROUNDS,
        key: [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        plaintext: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ciphertext: [0x41, 0xea, 0x3a, 0x0a, 0x94, 0xba, 0xa9, 0x40],
    },
    TeaTest {
        rounds: NUM_ROUNDS,
        key: [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ],
        plaintext: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ciphertext: [0x31, 0x9b, 0xbe, 0xfb, 0x01, 0x6a, 0xbd, 0xb2],
    },
    TeaTest {
        rounds: 16,
        key: [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        plaintext: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ciphertext: [0xed, 0x28, 0x5d, 0xa1, 0x45, 0x5b, 0x33, 0xc1],
    },
];

/// Test encryption with known test vectors
#[test]
fn test_cipher_encrypt() {
    for (i, test) in TEA_TESTS.iter().enumerate() {
        let c = Tea::new_with_rounds(&test.key, test.rounds)
            .unwrap_or_else(|_| panic!("#{}: NewCipherWithRounds should not return error", i));

        let mut ciphertext = [0u8; Tea::BLOCK_SIZE];
        c.encrypt(&mut ciphertext, &test.plaintext);

        assert_eq!(
            ciphertext, test.ciphertext,
            "#{}: incorrect ciphertext. Got {:02x?}, wanted {:02x?}",
            i, ciphertext, test.ciphertext
        );

        let mut plaintext2 = [0u8; Tea::BLOCK_SIZE];
        c.decrypt(&mut plaintext2, &ciphertext);

        assert_eq!(
            plaintext2, test.plaintext,
            "#{}: incorrect plaintext after decrypt. Got {:02x?}, wanted {:02x?}",
            i, plaintext2, test.plaintext
        );
    }
}

/// Test round-trip encryption/decryption
#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = [0u8; 16];
    let tea = Tea::new(&key).unwrap();

    let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let mut ciphertext = [0u8; 8];
    let mut decrypted = [0u8; 8];

    tea.encrypt(&mut ciphertext, &plaintext);
    tea.decrypt(&mut decrypted, &ciphertext);

    assert_eq!(plaintext, decrypted);
}

/// Test that odd number of rounds returns an error
#[test]
fn test_odd_rounds() {
    let key = [0u8; 16];
    assert!(
        Tea::new_with_rounds(&key, 63).is_err(),
        "odd number of rounds should return error"
    );
}

/// Test with different round counts
#[test]
fn test_different_rounds() {
    let key = TEST_KEY;
    let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    // Test with different even round counts
    for rounds in [16, 32, 64, 128].iter() {
        let tea = Tea::new_with_rounds(&key, *rounds).unwrap();
        let mut ciphertext = [0u8; 8];
        let mut decrypted = [0u8; 8];

        tea.encrypt(&mut ciphertext, &plaintext);
        tea.decrypt(&mut decrypted, &ciphertext);

        assert_eq!(
            plaintext, decrypted,
            "Round-trip failed for {} rounds",
            rounds
        );
    }
}
