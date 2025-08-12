use super::*;
use crate::aes::Aes;
use crate::cipher::common_test::*;
use crate::des::Des;

struct OfbTest {
    name: &'static str,
    key: &'static [u8],
    iv: &'static [u8],
    input: &'static [u8],
    output: &'static [u8],
}

const OFB_TESTS: &[OfbTest] = &[
    // NIST SP 800-38A pp 52-55
    OfbTest {
        name: "OFB-AES128",
        key: &COMMON_KEY128,
        iv: &COMMON_IV,
        input: &COMMON_INPUT,
        output: &[
            0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c,
            0xfb, 0x4a, 0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03, 0xf5, 0x3c, 0x52, 0xda,
            0xc5, 0x4e, 0xd8, 0x25, 0x97, 0x40, 0x05, 0x1e, 0x9c, 0x5f, 0xec, 0xf6, 0x43, 0x44,
            0xf7, 0xa8, 0x22, 0x60, 0xed, 0xcc, 0x30, 0x4c, 0x65, 0x28, 0xf6, 0x59, 0xc7, 0x78,
            0x66, 0xa5, 0x10, 0xd9, 0xc1, 0xd6, 0xae, 0x5e,
        ],
    },
    OfbTest {
        name: "OFB-AES192",
        key: &COMMON_KEY192,
        iv: &COMMON_IV,
        input: &COMMON_INPUT,
        output: &[
            0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab, 0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a,
            0x41, 0x74, 0xfc, 0xc2, 0x8b, 0x8d, 0x4c, 0x63, 0x83, 0x7c, 0x09, 0xe8, 0x17, 0x00,
            0xc1, 0x10, 0x04, 0x01, 0x8d, 0x9a, 0x9a, 0xea, 0xc0, 0xf6, 0x59, 0x6f, 0x55, 0x9c,
            0x6d, 0x4d, 0xaf, 0x59, 0xa5, 0xf2, 0x6d, 0x9f, 0x20, 0x08, 0x57, 0xca, 0x6c, 0x3e,
            0x9c, 0xac, 0x52, 0x4b, 0xd9, 0xac, 0xc9, 0x2a,
        ],
    },
    OfbTest {
        name: "OFB-AES256",
        key: &COMMON_KEY256,
        iv: &COMMON_IV,
        input: &COMMON_INPUT,
        output: &[
            0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, 0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d,
            0x38, 0x60, 0x4f, 0xeb, 0xdc, 0x67, 0x40, 0xd2, 0x0b, 0x3a, 0xc8, 0x8f, 0x6a, 0xd8,
            0x2a, 0x4f, 0xb0, 0x8d, 0x71, 0xab, 0x47, 0xa0, 0x86, 0xe8, 0x6e, 0xed, 0xf3, 0x9d,
            0x1c, 0x5b, 0xba, 0x97, 0xc4, 0x08, 0x01, 0x26, 0x14, 0x1d, 0x67, 0xf3, 0x7b, 0xe8,
            0x53, 0x8f, 0x5a, 0x8b, 0xe7, 0x40, 0xe4, 0x84,
        ],
    },
];

#[test]
fn test_ofb() {
    for test in OFB_TESTS {
        // Test encryption with different lengths
        for j in [0, 5] {
            let cipher = match test.key.len() {
                16 => Aes::new(test.key).unwrap(),
                24 => Aes::new(test.key).unwrap(),
                32 => Aes::new(test.key).unwrap(),
                _ => panic!("Invalid key length"),
            };

            let plaintext = &test.input[..test.input.len() - j];
            let mut ofb = cipher.to_ofb(test.iv).unwrap();
            let mut ciphertext = vec![0u8; plaintext.len()];
            ofb.xor_key_stream(&mut ciphertext, plaintext).unwrap();

            let expected = &test.output[..plaintext.len()];
            if ciphertext != expected {
                panic!(
                    "{}/{}: encrypting\ninput: {:02x?}\nhave:  {:02x?}\nwant:  {:02x?}",
                    test.name,
                    plaintext.len(),
                    plaintext,
                    ciphertext,
                    expected
                );
            }
        }

        // Test decryption with different lengths
        for j in [0, 5] {
            let cipher = match test.key.len() {
                16 => Aes::new(test.key).unwrap(),
                24 => Aes::new(test.key).unwrap(),
                32 => Aes::new(test.key).unwrap(),
                _ => panic!("Invalid key length"),
            };
            let ciphertext = &test.output[..test.input.len() - j];
            let mut ofb = cipher.to_ofb(test.iv).unwrap();
            let mut plaintext = vec![0u8; ciphertext.len()];
            ofb.xor_key_stream(&mut plaintext, ciphertext).unwrap();

            let expected = &test.input[..ciphertext.len()];
            if plaintext != expected {
                panic!(
                    "{}/{}: decrypting\nhave: {:02x?}\nwant: {:02x?}",
                    test.name,
                    ciphertext.len(),
                    plaintext,
                    expected
                );
            }
        }
    }
}

#[test]
fn test_ofb_stream_aes128() {
    for _ in 0..10 {
        let mut key = [0u8; 16];
        rand::fill(&mut key);

        let mut iv = [0u8; 16];
        rand::fill(&mut iv);

        let cipher = Aes::new(&key).unwrap();
        test_stream_cipher(cipher, &iv);
    }
}

#[test]
fn test_ofb_stream_aes192() {
    for _ in 0..10 {
        let mut key = [0u8; 24];
        rand::fill(&mut key);

        let mut iv = [0u8; 16];
        rand::fill(&mut iv);

        let cipher = Aes::new(&key).unwrap();
        test_stream_cipher(cipher, &iv);
    }
}

#[test]
fn test_ofb_stream_aes256() {
    for _ in 0..10 {
        let mut key = [0u8; 32];
        rand::fill(&mut key);

        let mut iv = [0u8; 16];
        rand::fill(&mut iv);

        let cipher = Aes::new(&key).unwrap();
        test_stream_cipher(cipher, &iv);
    }
}

#[test]
fn test_ofb_stream_des() {
    for _ in 0..10 {
        let mut key = [0u8; 8];
        rand::fill(&mut key);

        let mut iv = [0u8; 8];
        rand::fill(&mut iv);

        let cipher = Des::new(&key).unwrap();
        test_stream_cipher(cipher, &iv);
    }
}

fn test_stream_cipher<B: BlockCipher + OfbAbleMarker + Clone + 'static>(cipher: B, iv: &[u8]) {
    use rand::Rng;
    let mut rng = rand::rng();

    // Test with random data
    let data_len = rng.random_range(1..1000);
    let mut plaintext = vec![0u8; data_len];
    rng.fill(&mut plaintext[..]);

    // Encrypt
    let mut ofb1 = cipher.clone().to_ofb(iv).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len()];
    ofb1.xor_key_stream(&mut ciphertext, &plaintext).unwrap();

    // Decrypt
    let mut ofb2 = cipher.clone().to_ofb(iv).unwrap();
    let mut decrypted = vec![0u8; ciphertext.len()];
    ofb2.xor_key_stream(&mut decrypted, &ciphertext).unwrap();

    assert_eq!(plaintext, decrypted);

    // Test streaming behavior - encrypt in chunks
    let mut ofb3 = cipher.clone().to_ofb(iv).unwrap();
    let mut ciphertext2 = vec![0u8; plaintext.len()];
    let chunk_size = rng.random_range(1..=plaintext.len().min(50));

    let mut pos = 0;
    while pos < plaintext.len() {
        let end = (pos + chunk_size).min(plaintext.len());
        ofb3.xor_key_stream(&mut ciphertext2[pos..end], &plaintext[pos..end])
            .unwrap();
        pos = end;
    }

    assert_eq!(ciphertext, ciphertext2);
}
