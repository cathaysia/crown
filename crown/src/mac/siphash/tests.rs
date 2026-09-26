use super::*;

/// The canonical SipHash reference vector set (Aumasson/Bernstein):
/// key = 000102...0f, inputs are 00.., 00 01, ... (0 to 14 bytes).
/// Reference values produced by OpenSSL 3.5.8 `openssl mac SIPHASH`.
const KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

const VEC8: [&str; 15] = [
    "310e0edd47db6f72",
    "fd67dc93c539f874",
    "5a4fa9d909806c0d",
    "2d7efbd796666785",
    "b7877127e09427cf",
    "8da699cd64557618",
    "cee3fe586e46c9cb",
    "37d1018bf50002ab",
    "6224939a79f5f593",
    "b0e4a90bdf82009e",
    "f3b9dd94c5bb5d7a",
    "a7ad6b22462fb3f4",
    "fbe50e86bc8f1e75",
    "903d84c02756ea14",
    "eef27a8e90ca23f7",
];

const VEC16: [&str; 15] = [
    "a3817f04ba25a8e66df67214c7550293",
    "da87c1d86b99af44347659119b22fc45",
    "8177228da4a45dc7fca38bdef60affe4",
    "9c70b60c5267a94e5f33b6b02985ed51",
    "f88164c12d9c8faf7d0f6e7c7bcd5579",
    "1368875980776f8854527a07690e9627",
    "14eeca338b208613485ea0308fd7a15e",
    "a1f1ebbed8dbc153c0b84aa61ff08239",
    "3b62a9ba6258f5610f83e264f31497b4",
    "264499060ad9baabc47f8b02bb6d71ed",
    "00110dc378146956c95447d3f3d0fbba",
    "0151c568386b6677a2b4dc6f81e5dc18",
    "d626b266905ef35882634df68532c125",
    "9869e247e9c08b10d029934fc4b952f7",
    "31fcefac66d7de9c7ec7485fe4494902",
];

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn reference_vectors_64bit() {
    for (i, expected) in VEC8.iter().enumerate() {
        let msg: alloc::vec::Vec<u8> = (0..i as u8).collect();
        let tag = sum(&msg, &KEY);
        assert_eq!(tag, hex_to_bytes(expected)[..], "SipHash len={i}");

        // Streaming must match the one-shot result.
        let mut h = SipHash::new(&KEY, TAG_SIZE).unwrap();
        for chunk in msg.chunks(3) {
            h.write(chunk);
        }
        assert!(h.verify(&hex_to_bytes(expected)), "streaming len={i}");
    }
}

#[test]
fn reference_vectors_128bit() {
    for (i, expected) in VEC16.iter().enumerate() {
        let msg: alloc::vec::Vec<u8> = (0..i as u8).collect();
        let tag = sum128(&msg, &KEY);
        assert_eq!(tag, hex_to_bytes(expected)[..], "SipHash-128 len={i}");
    }
}

#[test]
fn invalid_output_size_rejected() {
    assert!(SipHash::new(&KEY, 12).is_err());
}

#[test]
fn write_after_sum_panics() {
    let mut h = SipHash::new(&KEY, TAG_SIZE).unwrap();
    let _ = h.sum();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        h.write(b"more");
    }));
    assert!(result.is_err());
}
