use super::*;

#[test]
fn test_rabbit_keystream() {
    let key = [0u8; 16];
    let iv = [0u8; 8];
    let mut rabbit = Rabbit::new(&key, Some(&iv)).unwrap();

    let mut output = [0u8; 32];
    rabbit.xor_key_stream(&mut output).unwrap();

    let expected = [
        0xED, 0xB7, 0x05, 0x67, 0x37, 0x5D, 0xCD, 0x7C, 0xD8, 0x95, 0x54, 0xF8, 0x5E, 0x27, 0xA7,
        0xC6, 0x8D, 0x4A, 0xDC, 0x70, 0x32, 0x29, 0x8F, 0x7B, 0xD4, 0xEF, 0xF5, 0x04, 0xAC, 0xA6,
        0x29, 0x5F,
    ];

    assert_eq!(output, expected);
}

#[test]
fn test_rabbit_vector_2_with_iv() {
    let key = [0u8; 16];
    let iv = [0x59, 0x7E, 0x26, 0xC1, 0x75, 0xF5, 0x73, 0xC3];
    let mut rabbit = Rabbit::new(&key, Some(&iv)).unwrap();

    let mut output = [0u8; 16];
    rabbit.xor_key_stream(&mut output).unwrap();

    // RFC 4503 A.2 Vector 2
    // S[0]: 1F CD 4E B9 58 00 12 E2 E0 DC CC 92 22 01 7D 6D
    // Reversed: 6D, 7D, 01, 22, 92, CC, DC, E0, E2, 12, 00, 58, B9, 4E, CD, 1F
    let expected = [
        0x6D, 0x7D, 0x01, 0x22, 0x92, 0xCC, 0xDC, 0xE0, 0xE2, 0x12, 0x00, 0x58, 0xB9, 0x4E, 0xCD,
        0x1F,
    ];
    assert_eq!(output, expected);
}

#[test]
fn test_rabbit_vector_3_with_iv() {
    let key = [0u8; 16];
    let iv = [0x27, 0x17, 0xF4, 0xD2, 0x1A, 0x56, 0xEB, 0xA6];
    let mut rabbit = Rabbit::new(&key, Some(&iv)).unwrap();

    let mut output = [0u8; 16];
    rabbit.xor_key_stream(&mut output).unwrap();

    // RFC 4503 A.2 Vector 3
    // S[0]: 44 5A D8 C8 05 85 8D BF 70 B6 AF 23 A1 51 10 4D
    // Reversed: 4D, 10, 51, A1, 23, AF, B6, 70, BF, 8D, 85, 05, C8, D8, 5A, 44
    let expected = [
        0x4D, 0x10, 0x51, 0xA1, 0x23, 0xAF, 0xB6, 0x70, 0xBF, 0x8D, 0x85, 0x05, 0xC8, 0xD8, 0x5A,
        0x44,
    ];
    assert_eq!(output, expected);
}

#[test]
fn test_rabbit_no_iv() {
    let key = [0u8; 16];
    let mut rabbit = Rabbit::new(&key, None).unwrap();

    let mut output = [0u8; 16];
    rabbit.xor_key_stream(&mut output).unwrap();

    // RFC 4503 A.1 Vector 1
    // S[0]: B1 57 54 F0 36 A5 D6 EC F5 6B 45 26 1C 4A F7 02
    // Reversed bytes: 02, F7, 4A, 1C, 26, 45, 6B, F5, EC, D6, A5, 36, F0, 54, 57, B1
    let expected = [
        0x02, 0xF7, 0x4A, 0x1C, 0x26, 0x45, 0x6B, 0xF5, 0xEC, 0xD6, 0xA5, 0x36, 0xF0, 0x54, 0x57,
        0xB1,
    ];
    assert_eq!(output, expected);
}

#[test]
fn test_rabbit_incremental() {
    let key = [0u8; 16];
    let iv = [0u8; 8];
    let mut rabbit = Rabbit::new(&key, Some(&iv)).unwrap();

    let mut output = [0u8; 32];
    for i in 0..32 {
        rabbit.xor_key_stream(&mut output[i..i + 1]).unwrap();
    }

    let expected = [
        0xED, 0xB7, 0x05, 0x67, 0x37, 0x5D, 0xCD, 0x7C, 0xD8, 0x95, 0x54, 0xF8, 0x5E, 0x27, 0xA7,
        0xC6, 0x8D, 0x4A, 0xDC, 0x70, 0x32, 0x29, 0x8F, 0x7B, 0xD4, 0xEF, 0xF5, 0x04, 0xAC, 0xA6,
        0x29, 0x5F,
    ];

    assert_eq!(output, expected);
}
