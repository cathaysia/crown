use super::*;

// The canonical RIPEMD-160 test set (Dobbertin, Bosselaers, Preneel), also
// matching `openssl dgst -ripemd160` output.
const VECTORS: [(&str, &str); 8] = [
    ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (
        "abcdefghijklmnopqrstuvwxyz",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    ),
    (
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ),
    (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ),
    (
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
    ),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_vectors() {
    for (input, expected) in VECTORS {
        assert_eq!(
            &hex(&sum_ripemd160(input.as_bytes())),
            &expected,
            "input={input:?}"
        );
    }
}

#[test]
fn million_a() {
    // One million repetitions of 'a'.
    let tag = {
        let mut h = new_ripemd160();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.write_all(&chunk).unwrap();
        }
        h.sum()
    };
    assert_eq!(hex(&tag), "52783243c1697bdbe16d37f97f68f08325dc1528");
}

#[test]
fn streaming_matches_oneshot() {
    let data: alloc::vec::Vec<u8> = (0..250u32).map(|i| (i * 31 + 7) as u8).collect();
    let expected = sum_ripemd160(&data);

    let mut h = new_ripemd160();
    h.write_all(&data[..11]).unwrap();
    h.write_all(&data[11..130]).unwrap();
    h.write_all(&data[130..]).unwrap();
    assert_eq!(h.sum(), expected);
}

#[test]
fn reset_reuses_state() {
    let mut h = new_ripemd160();
    h.write_all(b"abc").unwrap();
    assert_eq!(h.sum(), sum_ripemd160(b"abc"));

    h.reset();
    h.write_all(b"a").unwrap();
    assert_eq!(h.sum(), sum_ripemd160(b"a"));
}
