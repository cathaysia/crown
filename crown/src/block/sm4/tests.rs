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

#[test]
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
fn test_sm4_asm_matches_soft() {
    if !super::asm::sm4_supported() {
        return;
    }
    let mut key = [0u8; 16];
    rand::fill(&mut key);
    let enc = super::Sm4::new(&key).unwrap();

    // The SM4-NI set_key must agree with the software round-key schedule.
    let mut hw_rk = [0u32; 32];
    super::asm::set_key(&key, &mut hw_rk);
    assert_eq!(enc.ek, hw_rk);

    for _ in 0..256 {
        let mut inout = [0u8; 16];
        rand::fill(&mut inout);

        let mut soft = inout;
        super::s_sm4_do(&mut soft, &enc.ek);
        let mut hw = inout;
        super::asm::encrypt_block(&mut hw, &enc.ek);
        assert_eq!(soft, hw);

        let mut soft_dec = hw;
        super::s_sm4_do(&mut soft_dec, &enc.dk);
        let mut hw_dec = hw;
        super::asm::decrypt_block(&mut hw_dec, &enc.ek);
        assert_eq!(soft_dec, hw_dec);
    }
}
