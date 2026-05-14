use super::*;
use crate::block::BlockCipher;

#[test]
fn test_noekeon() {
    let key = hex::decode("AA3C8C86D98BF8BE21E0360978FBE490").unwrap();
    let pt = hex::decode("E4966CD313A06CAFD023C9FD45322316").unwrap();
    let ct_expected = hex::decode("A6ECB8A861FD62D91302FE9E47013FC3").unwrap();

    let cipher = Noekeon::new(&key).unwrap();
    let mut block = pt.clone();

    // Test encryption
    cipher.encrypt_block(&mut block);
    assert_eq!(block, ct_expected);

    // Test decryption
    cipher.decrypt_block(&mut block);
    assert_eq!(block, pt);
}

#[test]
fn test_noekeon_vectors() {
    let vectors = [
        (
            "AA3C8C86D98BF8BE21E0360978FBE490",
            "E4966CD313A06CAFD023C9FD45322316",
            "A6ECB8A861FD62D91302FE9E47013FC3",
        ),
        (
            "ED43D187217EE0973D76C3372E7DAED3",
            "E33832CCF22F2F0A4A8B8F18122017D3",
            "94A5DFF5AE1CBB22ADEBA70DB78290A0",
        ),
        (
            "6FDC2338F210FBD3C18C02F6B46AD5A8",
            "DB29EDB55FB3603A92A8EB9C6D9D3E8F",
            "78F36FF89EBB8C6AE810F7002215303D",
        ),
    ];

    for (k_hex, pt_hex, ct_hex) in vectors {
        let key = hex::decode(k_hex).unwrap();
        let pt = hex::decode(pt_hex).unwrap();
        let ct_expected = hex::decode(ct_hex).unwrap();

        let cipher = Noekeon::new(&key).unwrap();
        let mut block = pt.clone();

        cipher.encrypt_block(&mut block);
        assert_eq!(
            block, ct_expected,
            "Encryption failed for vector with key {}",
            k_hex
        );

        cipher.decrypt_block(&mut block);
        assert_eq!(block, pt, "Decryption failed for vector with key {}", k_hex);
    }
}
