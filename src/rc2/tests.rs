use super::*;

#[test]
fn test_encrypt_decrypt() {
    let tests = [
        (
            "0000000000000000",
            "0000000000000000",
            "ebb773f993278eff",
            63,
        ),
        (
            "ffffffffffffffff",
            "ffffffffffffffff",
            "278b27e42e2f0d49",
            64,
        ),
        (
            "3000000000000000",
            "1000000000000001",
            "30649edf9be7d2c2",
            64,
        ),
        ("88", "0000000000000000", "61a8a244adacccf0", 64),
        ("88bca90e90875a", "0000000000000000", "6ccf4308974c267f", 64),
        (
            "88bca90e90875a7f0f79c384627bafb2",
            "0000000000000000",
            "1a807d272bbe5db1",
            64,
        ),
        (
            "88bca90e90875a7f0f79c384627bafb2",
            "0000000000000000",
            "2269552ab0f85ca6",
            128,
        ),
        (
            "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
            "0000000000000000",
            "5b78d3a43dfff1f1",
            129,
        ),
    ];

    for (key_hex, plain_hex, cipher_hex, t1) in tests {
        let key = hex::decode(key_hex).unwrap();
        let plain = hex::decode(plain_hex).unwrap();
        let expected_cipher = hex::decode(cipher_hex).unwrap();

        let cipher = Rc2Cipher::new(&key, t1).unwrap();
        let mut dst = [0u8; 8];

        // Test encryption
        cipher.encrypt(&mut dst, &plain);
        assert_eq!(
            dst.as_slice(),
            expected_cipher.as_slice(),
            "encrypt failed: got {:02x?} wanted {:02x?}",
            dst,
            expected_cipher
        );

        // Test decryption
        cipher.decrypt(&mut dst, &expected_cipher);
        assert_eq!(
            dst.as_slice(),
            plain.as_slice(),
            "decrypt failed: got {:02x?} wanted {:02x?}",
            dst,
            plain
        );
    }
}
