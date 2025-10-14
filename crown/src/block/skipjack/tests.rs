use super::*;

#[test]
fn test_skipjack() {
    let mut key = [0u8; 10];
    rand::fill(&mut key);
    let enc = super::Skipjack::new(&key).unwrap();
    for _ in 0..1000 {
        let mut inout = [0u8; 16];
        rand::fill(&mut inout);
        let mut out = inout;
        enc.encrypt_block(&mut out);
        enc.decrypt_block(&mut out);
        assert_eq!(inout, out);
    }
}

#[test]
fn test_skipjack_basic() {
    let key = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let plaintext = [0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa];
    let expected_ciphertext = [0x25, 0x87, 0xca, 0xe2, 0x7a, 0x12, 0xd3, 0x00];

    let cipher = Skipjack::new(&key).unwrap();

    let mut data = plaintext;
    cipher.encrypt_block(&mut data);
    assert_eq!(data, expected_ciphertext);

    cipher.decrypt_block(&mut data);
    assert_eq!(data, plaintext);
}

#[test]
fn test_skipjack_multiple_rounds() {
    let key = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let cipher = Skipjack::new(&key).unwrap();

    let mut data = [0u8; 8];

    for _ in 0..1000 {
        cipher.encrypt_block(&mut data);
    }

    for _ in 0..1000 {
        cipher.decrypt_block(&mut data);
    }

    assert_eq!(data, [0u8; 8]);
}

#[test]
fn test_skipjack_invalid_key_size() {
    let short_key = [0u8; 9];
    let long_key = [0u8; 11];

    assert!(Skipjack::new(&short_key).is_err());
    assert!(Skipjack::new(&long_key).is_err());
}

#[test]
fn test_skipjack_block_size() {
    let key = [0u8; 10];
    let cipher = Skipjack::new(&key).unwrap();
    assert_eq!(cipher.block_size(), 8);
}
