use crate::core::{CoreRead, CoreWrite};
use crate::hash::Hash;
use sha3::Digest;

/// Message used by the multi-block golden vectors below.
fn long_message() -> Vec<u8> {
    let mut m: Vec<u8> = (0u8..=255).collect();
    for _ in 0..3 {
        m.extend_from_slice(b"crown-keccak-kmac-parity-vector");
    }
    m
}

#[test]
fn rustcrypto_sha3_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let k256 = super::sum256(&buf);
        let k384 = super::sum384(&buf);
        let k512 = super::sum512(&buf);

        let r256 = sha3::Sha3_256::digest(&buf).to_vec();
        let r384 = sha3::Sha3_384::digest(&buf).to_vec();
        let r512 = sha3::Sha3_512::digest(&buf).to_vec();

        assert_eq!(k256, r256.as_slice());
        assert_eq!(k384, r384.as_slice());
        assert_eq!(k512, r512.as_slice());
    }
}

#[test]
fn rustcrypto_legacy_keccak_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());

        let mut h = super::new_legacy_keccak224();
        h.write_all(&buf).unwrap();
        let r = sha3::Keccak224::digest(&buf).to_vec();
        assert_eq!(h.sum().as_slice(), r.as_slice());

        let mut h = super::new_legacy_keccak256();
        h.write_all(&buf).unwrap();
        let r = sha3::Keccak256::digest(&buf).to_vec();
        assert_eq!(h.sum().as_slice(), r.as_slice());

        let mut h = super::new_legacy_keccak384();
        h.write_all(&buf).unwrap();
        let r = sha3::Keccak384::digest(&buf).to_vec();
        assert_eq!(h.sum().as_slice(), r.as_slice());

        let mut h = super::new_legacy_keccak512();
        h.write_all(&buf).unwrap();
        let r = sha3::Keccak512::digest(&buf).to_vec();
        assert_eq!(h.sum().as_slice(), r.as_slice());
    }
}

/// Golden vectors generated with the vendored OpenSSL 3.5.8 CLI
/// (`printf %s <msg> | openssl dgst -keccak-224`, etc.).
#[test]
fn openssl_legacy_keccak_kat() {
    let cases: [(Vec<u8>, &str, &str, &str, &str);
        3] = [
        (
            b"".to_vec(),
            "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
            "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
        ),
        (
            b"abc".to_vec(),
            "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8",
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e",
            "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
        ),
        (
            long_message(),
            "9c02c2dc3614da6cf41c6d879f41da1acf811410650d334e1ebd9f93",
            "1e445bb84ebe5a0ecd4066b495cf9c92e94d5a91ab2477aa3d158ee86c5b6fd8",
            "62827fb7fb0dc574b53ee04f410f5c1f4dcccc94a8ce60f3f9259492ab4882b6bf7e75948c2a463a790af3d92498e637",
            "3d3f3b389e9fe6955f3169b4b3bf1f6714c17474f7b264adf8f09cd2683833b741e447c974898d54c794df24e69e59871ec3a8e3e25fa705b8ce06475d47885c",
        ),
    ];

    for (msg, k224, k256, k384, k512) in &cases {
        let mut h = super::new_legacy_keccak224();
        h.write_all(msg).unwrap();
        assert_eq!(hex::encode(h.sum()), *k224);

        let mut h = super::new_legacy_keccak256();
        h.write_all(msg).unwrap();
        assert_eq!(hex::encode(h.sum()), *k256);

        let mut h = super::new_legacy_keccak384();
        h.write_all(msg).unwrap();
        assert_eq!(hex::encode(h.sum()), *k384);

        let mut h = super::new_legacy_keccak512();
        h.write_all(msg).unwrap();
        assert_eq!(hex::encode(h.sum()), *k512);
    }
}

/// Golden vectors generated with the vendored OpenSSL 3.5.8 CLI
/// (`printf %s <msg> | openssl dgst -keccak-kmac-128`, etc.).
#[test]
fn openssl_keccak_kmac_kat() {
    let cases: [(Vec<u8>, &str, &str); 3] = [
        (
            b"".to_vec(),
            "83aa04c211dc19d16912571ed0a75130d36aebd58562dd080c1ea84a8c7d73f7",
            "700eb71ffd0c7eceb15c7eb439aa9cc7b1f8c28c358d0335f635b0249510b4bc0325d5d967108947bdf315f9b662db16a160e96877dc5e1479a942a98010802c",
        ),
        (
            b"abc".to_vec(),
            "3bcfe6e0471a2168f61c444843e32aea0a09ec15bd9155f169189147f98c11fc",
            "f4e4a2d747910716f38c8ec58a5a50f6b0ea4ebd1e4c92a19e9b36ae640580f1fda41b8b534dfc57a1a719528dadc28e3e6181daba9dc9595e459e249b2bcd95",
        ),
        (
            long_message(),
            "4863d51bc185ff2900b43b7ffd9540c17b5c2c290ca7e860bcff79e2ec90c0b6",
            "09eba6cb3a5c7d3a15c49ba83861634653795c24102b69e084b0a1e8b9f4ead9bde4dc8585e54d18d4c445ccca944368a5604f6060428255105df76ad942aa2d",
        ),
    ];

    for (msg, k128, k256) in &cases {
        let mut h = super::new_keccak_kmac128();
        h.write_all(msg).unwrap();
        assert_eq!(hex::encode(h.sum()), *k128);

        let mut h = super::new_keccak_kmac256();
        h.write_all(msg).unwrap();
        assert_eq!(hex::encode(h.sum()), *k256);
    }
}

/// Squeeze past the default output length; vectors from
/// `openssl dgst -keccak-kmac-128 -xoflen 64` (resp. `-keccak-kmac-256 -xoflen 16`).
#[test]
fn openssl_keccak_kmac_xof_kat() {
    let mut h = super::new_keccak_kmac128();
    h.write_all(b"").unwrap();
    let mut out = [0u8; 64];
    h.read(&mut out).unwrap();
    assert_eq!(
        hex::encode(out),
        "83aa04c211dc19d16912571ed0a75130d36aebd58562dd080c1ea84a8c7d73f7\
         e23dae72079f856934c8a344911d465547c012a6cfa9d8bdb64f32ad9575d8dc"
    );

    let mut h = super::new_keccak_kmac128();
    h.write_all(b"abc").unwrap();
    let mut out = [0u8; 64];
    h.read(&mut out).unwrap();
    assert_eq!(
        hex::encode(out),
        "3bcfe6e0471a2168f61c444843e32aea0a09ec15bd9155f169189147f98c11fc\
         43f93d66358897b6fefa253ae02fc193c1dae0d3a8c09734c5ef32e03676d920"
    );

    let mut h = super::new_keccak_kmac256();
    h.write_all(b"abc").unwrap();
    let mut out = [0u8; 16];
    h.read(&mut out).unwrap();
    assert_eq!(hex::encode(out), "f4e4a2d747910716f38c8ec58a5a50f6");
}
