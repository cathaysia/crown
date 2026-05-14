use super::*;
use crate::block::BlockCipher;

#[test]
fn test_safer_k64() {
    let pt = [1, 2, 3, 4, 5, 6, 7, 8];
    let key = [8, 7, 6, 5, 4, 3, 2, 1];
    let expected_ct = [200, 242, 156, 221, 135, 120, 62, 217];

    let cipher = Safer::new_k64(&key, 6).unwrap();
    let mut buf = pt;
    cipher.encrypt_block(&mut buf);
    assert_eq!(buf, expected_ct);

    cipher.decrypt_block(&mut buf);
    assert_eq!(buf, pt);
}

#[test]
fn test_safer_sk64() {
    let pt = [1, 2, 3, 4, 5, 6, 7, 8];
    let key = [1, 2, 3, 4, 5, 6, 7, 8];
    let expected_ct = [95, 206, 155, 162, 5, 132, 56, 199];

    let cipher = Safer::new_sk64(&key, 6).unwrap();
    let mut buf = pt;
    cipher.encrypt_block(&mut buf);
    assert_eq!(buf, expected_ct);

    cipher.decrypt_block(&mut buf);
    assert_eq!(buf, pt);
}

#[test]
fn test_safer_sk128() {
    let pt = [1, 2, 3, 4, 5, 6, 7, 8];
    let key = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0];
    let expected_ct = [255, 120, 17, 228, 179, 167, 46, 113];

    let cipher = Safer::new_sk128(&key, 0).unwrap();
    let mut buf = pt;
    cipher.encrypt_block(&mut buf);
    assert_eq!(buf, expected_ct);

    cipher.decrypt_block(&mut buf);
    assert_eq!(buf, pt);
}

#[test]
fn test_safer_k128_setup() {
    let key = [0u8; 16];
    let cipher = Safer::new_k128(&key, 0).unwrap();
    assert_eq!(cipher.rounds, 10);
}
