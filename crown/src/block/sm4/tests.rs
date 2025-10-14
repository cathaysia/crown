use crate::block::BlockCipher;

#[test]
fn test_sm4() {
    let mut key = [0u8; 16];
    rand::fill(&mut key);
    let enc = super::Sm4::new(&key).unwrap();
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
fn test_sm4_gloden() {
    let plaintext: &[u8] = &[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key: &[u8] = &[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let ciphertext: &[u8] = &[
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42,
        0x46,
    ];
    let ciphertext_1000000t: &[u8] = &[
        0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F, 0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F,
        0x66,
    ];

    {
        let enc = super::Sm4::new(key).unwrap();
        let mut out = plaintext.to_vec();
        enc.encrypt_block(&mut out);
        assert_eq!(ciphertext, out);
        enc.decrypt_block(&mut out);
        assert_eq!(plaintext, out);
    }

    {
        let enc = super::Sm4::new(key).unwrap();
        let mut out = plaintext.to_vec();
        for _ in 0..1000000 {
            enc.encrypt_block(&mut out);
        }
        assert_eq!(ciphertext_1000000t, out);
        for _ in 0..1000000 {
            enc.decrypt_block(&mut out);
        }
        assert_eq!(plaintext, out);
    }
}
