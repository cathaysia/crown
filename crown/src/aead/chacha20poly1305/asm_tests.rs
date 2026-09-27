//! BoringSSL chacha20_poly1305_tests.txt vectors, run through the
//! stitched assembly (SSE4.1/AVX2 dispatch).

use super::asm;

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// (key, nonce, plaintext, aad, ciphertext, tag)
const VECTORS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "070000004041424344454647",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        "50515253c0c1c2c3c4c5c6c7",
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        "1ae10b594f09e26a7e902ecbd0600691",
    ),
    (
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "070000004041424344454647",
        "31323334353637383961626364656630", // IN: "123456789abcdef0" (ASCII)
        "31",                               // AD: "1" (ASCII)
        "ae49da6934cb77822c83ed9852e46c9e",
        "dac9c841c168379dcf8f2bb8e22d6da2",
    ),
];

#[test]
fn seal_open_roundtrip_vectors() {
    if !asm::sse41_capable() {
        return;
    }
    for (k, nonce, pt, ad, ct, tag) in VECTORS {
        let key: [u8; 32] = hex_bytes(k).try_into().unwrap();
        let nonce: [u8; 12] = hex_bytes(nonce).try_into().unwrap();
        let pt = hex_bytes(pt);
        let ad = hex_bytes(ad);
        let ct = hex_bytes(ct);
        let tag = hex_bytes(tag);

        let mut out = vec![0u8; pt.len()];
        let got_tag = asm::seal(&mut out, &pt, &ad, &key, 0, &nonce).unwrap();
        assert_eq!(out, ct, "seal ciphertext");
        assert_eq!(got_tag.to_vec(), tag, "seal tag");

        let mut back = vec![0u8; ct.len()];
        let got_tag = asm::open(&mut back, &ct, &ad, &key, 0, &nonce).unwrap();
        assert_eq!(back, pt, "open plaintext");
        assert_eq!(got_tag.to_vec(), tag, "open tag");
    }
}

#[test]
fn open_tampered_tag_mismatches() {
    if !asm::sse41_capable() {
        return;
    }
    let (k, nonce, _pt, ad, ct, tag) = VECTORS[1];
    let key: [u8; 32] = hex_bytes(k).try_into().unwrap();
    let nonce: [u8; 12] = hex_bytes(nonce).try_into().unwrap();
    let ct = hex_bytes(ct);
    let ad = hex_bytes(ad);
    let mut tag = hex_bytes(tag);
    tag[0] ^= 1;

    let mut back = vec![0u8; ct.len()];
    let computed = asm::open(&mut back, &ct, &ad, &key, 0, &nonce).unwrap();
    assert_ne!(computed.to_vec(), tag);
}
