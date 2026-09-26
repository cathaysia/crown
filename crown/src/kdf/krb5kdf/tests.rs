use super::*;
use crate::block::aes::Aes;
use crate::block::des::TripleDes;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// RFC 3961 DES3-CBC-HMAC-SHA1 key derivation vectors from OpenSSL
// evpkdf_krb5.txt.
#[test]
fn des3_vectors() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92",
            "0000000155",
            "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd",
        ),
        (
            "5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2",
            "00000001aa",
            "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207",
        ),
        (
            "98e6fd8a04a4b6859b75a176540b9752bad3ecd610a252bc",
            "0000000155",
            "13fef80d763e94ec6d13fd2ca1d085070249dad39808eabf",
        ),
        (
            "622aec25a2fe2cad7094680b7c64940280084c1a7cec92b5",
            "00000001aa",
            "f8dfbf04b097e6d9dc0702686bcb3489d91fd9a4516b703e",
        ),
    ];

    for (key, constant, expected) in cases {
        let cipher = TripleDes::new(&hex_to_bytes(key)).unwrap();
        let out = derive_des3(&cipher, &hex_to_bytes(constant)).unwrap();
        assert_eq!(out, hex_to_bytes(expected), "key {key}");
    }
}

// AES-128/AES-256-CBC KRB5KDF vectors from evpkdf_krb5.txt.
#[test]
fn aes_vectors() {
    let cases: &[(usize, &str, &str, &str)] = &[
        (
            16,
            "42263C6E89F4FC28B8DF68EE09799F15",
            "0000000299",
            "34280A382BC92769B2DA2F9EF066854B",
        ),
        (
            16,
            "42263C6E89F4FC28B8DF68EE09799F15",
            "00000002AA",
            "5B14FC4E250E14DDF9DCCF1AF6674F53",
        ),
        (
            32,
            "FE697B52BC0D3CE14432BA036A92E65BBB52280990A2FA27883998D72AF30161",
            "0000000299",
            "BFAB388BDCB238E9F9C98D6A878304F04D30C82556375AC507A7A852790F4674",
        ),
    ];

    for (key_len, key, constant, expected) in cases {
        let cipher = Aes::new(&hex_to_bytes(key)).unwrap();
        let out = derive(&cipher, *key_len, &hex_to_bytes(constant)).unwrap();
        assert_eq!(out, hex_to_bytes(expected), "constant {constant}");
    }
}

#[test]
fn rejects_invalid_parameters() {
    let cipher = Aes::new(&[0u8; 16]).unwrap();
    // Constant must be 1..block_size bytes.
    assert!(derive(&cipher, 16, &[]).is_err());
    assert!(derive(&cipher, 16, &[0u8; 17]).is_err());
    assert!(derive(&cipher, 0, &[1u8]).is_err());
}
