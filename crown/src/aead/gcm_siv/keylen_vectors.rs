// Golden vectors for AES-128/192/256-GCM-SIV; 128-bit cases match the RFC
// 8452 shape, 192/256 follow OpenSSL's extension (see mod.rs provenance).

pub(super) struct KeyTestCase {
    pub(super) keylen: usize,
    pub(super) key: &'static str,
    pub(super) nonce: &'static str,
    pub(super) aad: &'static str,
    pub(super) plaintext: &'static str,
    pub(super) ciphertext: &'static str,
    pub(super) tag: &'static str,
}

pub(super) const CASES: &[(&str, KeyTestCase)] = &[
    (
        "128-8pt-1aad",
        KeyTestCase {
            keylen: 16,
            key: "0102030405060708090a0b0c0d0e0f10",
            nonce: "030405060708090a0b0c0d0e",
            aad: "01",
            plaintext: "0001020304050607",
            ciphertext: "d7130eb4458f078b",
            tag: "b8907407fa2469a1ced1cd12ee62d38b",
        },
    ),
    (
        "128-12pt",
        KeyTestCase {
            keylen: 16,
            key: "0102030405060708090a0b0c0d0e0f10",
            nonce: "030405060708090a0b0c0d0e",
            aad: "",
            plaintext: "202122232425262728292a2b",
            ciphertext: "ee2ba0575fbd42f228d33ae4",
            tag: "2a3a12420641490e181f223f663b05f8",
        },
    ),
    (
        "192-8pt-1aad",
        KeyTestCase {
            keylen: 24,
            key: "0102030405060708090a0b0c0d0e0f101112131415161718",
            nonce: "030405060708090a0b0c0d0e",
            aad: "01",
            plaintext: "0001020304050607",
            ciphertext: "c4f3b3f552d8b73e",
            tag: "9d80e779cce8b1540b4f2e2ab0c1e87b",
        },
    ),
    (
        "192-12pt",
        KeyTestCase {
            keylen: 24,
            key: "0102030405060708090a0b0c0d0e0f101112131415161718",
            nonce: "030405060708090a0b0c0d0e",
            aad: "",
            plaintext: "202122232425262728292a2b",
            ciphertext: "1a51df28273b9a5f95910548",
            tag: "3368f191c1382df0ad9fc738bbb1f49a",
        },
    ),
    (
        "256-8pt-1aad",
        KeyTestCase {
            keylen: 32,
            key: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            nonce: "030405060708090a0b0c0d0e",
            aad: "01",
            plaintext: "0001020304050607",
            ciphertext: "3d19ff5107b4eb36",
            tag: "c59b19e15a6e0a08e8f344419247e19d",
        },
    ),
    (
        "256-12pt",
        KeyTestCase {
            keylen: 32,
            key: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            nonce: "030405060708090a0b0c0d0e",
            aad: "",
            plaintext: "202122232425262728292a2b",
            ciphertext: "f2002da33be97403be93ff79",
            tag: "3eded77ff0b0165d6b3ccf7f7894421a",
        },
    ),
];
