use super::*;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// RFC 3711 test vectors from OpenSSL evpkdf_srtp.txt.
#[test]
fn rfc3711_vectors() {
    let cases: &[(&str, &str, u32, &str, u8, &str)] = &[
        // kdr = 0: the index is not in play.
        (
            "E1F97A0D3E018BE0D64FA32C06DE4139",
            "0EC675AD498AFEEBB6960B3AABE6",
            0,
            "000000000000",
            0,
            "C61E7A93744F39EE10734AFE3FF7A087",
        ),
        (
            "E1F97A0D3E018BE0D64FA32C06DE4139",
            "0EC675AD498AFEEBB6960B3AABE6",
            0,
            "000000000000",
            1,
            "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4",
        ),
        (
            "E1F97A0D3E018BE0D64FA32C06DE4139",
            "0EC675AD498AFEEBB6960B3AABE6",
            0,
            "000000000000",
            2,
            "30CBBC08863D8C85D49DB34A9AE1",
        ),
        // RFC 3711 B.3 test case 1: kdr = 1, SRTP labels.
        (
            "8C307F105F79D5D2C26B1A933AE22CD5",
            "563B4C15458D977B68080242CEE1",
            1,
            "08284B49F520",
            0,
            "A920DF50EAA111D03FBE9B203121C07D",
        ),
        (
            "8C307F105F79D5D2C26B1A933AE22CD5",
            "563B4C15458D977B68080242CEE1",
            1,
            "08284B49F520",
            1,
            "A337DC070C0DAFA942F1E3A27ACD3C9917CE4B4D",
        ),
        (
            "8C307F105F79D5D2C26B1A933AE22CD5",
            "563B4C15458D977B68080242CEE1",
            1,
            "08284B49F520",
            2,
            "9E2BC99C86037F2AD98D72927428",
        ),
        // RFC 3711 B.3 test case 2: SRTCP labels (4-byte index).
        (
            "8C307F105F79D5D2C26B1A933AE22CD5",
            "563B4C15458D977B68080242CEE1",
            1,
            "69B62109",
            3,
            "94D76CA7ADB05B8631CF62538D97BE74",
        ),
        (
            "8C307F105F79D5D2C26B1A933AE22CD5",
            "563B4C15458D977B68080242CEE1",
            1,
            "69B62109",
            4,
            "FA02251D693645BC1001F83C5A13CB3E3D77F7EA",
        ),
        (
            "8C307F105F79D5D2C26B1A933AE22CD5",
            "563B4C15458D977B68080242CEE1",
            1,
            "69B62109",
            5,
            "70C0481A04E3610EC8AF8623FA9B",
        ),
    ];

    for (key, salt, kdr, index, label, expected) in cases {
        let out = derive_aes_cm(
            &hex_to_bytes(key),
            &hex_to_bytes(salt),
            &hex_to_bytes(index),
            *kdr,
            *label,
        )
        .unwrap();
        assert_eq!(out, hex_to_bytes(expected), "label {label} kdr {kdr}");
    }
}

#[test]
fn rejects_invalid_parameters() {
    let key = hex_to_bytes("E1F97A0D3E018BE0D64FA32C06DE4139");
    let salt = hex_to_bytes("0EC675AD498AFEEBB6960B3AABE6");
    let index = hex_to_bytes("000000000000");

    // Wrong salt length.
    assert!(derive_aes_cm(&key, &salt[..13], &index, 0, 0).is_err());
    // Label out of range.
    assert!(derive_aes_cm(&key, &salt, &index, 0, 8).is_err());
    // kdr must be a power of two.
    assert!(derive_aes_cm(&key, &salt, &index, 3, 0).is_err());
    // Index too short for the label's index length.
    assert!(derive_aes_cm(&key, &salt, &index[..4], 1, 0).is_err());
}
