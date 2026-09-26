use super::*;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Vectors produced with `openssl kdf -kdfopt ... PKCS12KDF` (OpenSSL 3.5.8).
#[test]
fn openssl_vectors() {
    let out = derive(EvpHash::new_sha256, b"password", b"nacl", 2, 1000, 32).unwrap();
    assert_eq!(
        out,
        hex_to_bytes("0DA3E7EBDC2066AA3887AD6C3405C98B4B2FDAA8116FEDC237D9E9F03F13DB17")
    );

    let out = derive(EvpHash::new_sha1, b"password", b"nacl", 1, 1000, 16).unwrap();
    assert_eq!(out, hex_to_bytes("967FB258873E217B52B7B802B28C5201"));

    let out = derive(EvpHash::new_md5_sha1, b"password", b"salt", 2, 2048, 32).unwrap();
    assert_eq!(
        out,
        hex_to_bytes("706440254F382843074997D824DAFB302F8F8EF653526E18B6F2FBC87BD648E3")
    );
}

#[test]
fn rejects_invalid_parameters() {
    assert!(derive(EvpHash::new_sha256, b"p", b"s", 0, 10, 16).is_err());
    assert!(derive(EvpHash::new_sha256, b"p", b"s", 4, 10, 16).is_err());
    assert!(derive(EvpHash::new_sha256, b"p", b"s", 2, 0, 16).is_err());
    assert!(derive(EvpHash::new_sha256, b"p", b"s", 2, 10, 0).is_err());
}
