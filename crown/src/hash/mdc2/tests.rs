use super::*;

// OpenSSL test/recipes/30-test_evp_data/evpmd_mdc2.txt and test/mdc2test.c.
#[test]
fn openssl_pad1() {
    let input = b"Now is the time for all ";
    let mut h = new_mdc2();
    h.write_all(input).unwrap();
    assert_eq!(
        h.sum(),
        [
            0x42, 0xe5, 0x0c, 0xd2, 0x24, 0xba, 0xce, 0xba, 0x76, 0x0b, 0xdd, 0x2b, 0xd4, 0x09,
            0x28, 0x1a,
        ]
    );
}

#[test]
fn openssl_pad2() {
    let input = b"Now is the time for all ";
    let mut h = Mdc2::new_with_pad(PAD_2).unwrap();
    h.write_all(input).unwrap();
    assert_eq!(
        h.sum(),
        [
            0x2e, 0x46, 0x79, 0xb5, 0xad, 0xd9, 0xca, 0x75, 0x35, 0xd8, 0x7a, 0xfe, 0xab, 0x33,
            0xbe, 0xe2,
        ]
    );
}

#[test]
fn empty_input() {
    // Without any block processed the digest is the bare init state
    // (0x52*8 || 0x25*8) — the classic MDC-2 empty-input vector.
    assert_eq!(
        sum_mdc2(b""),
        [
            0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25,
            0x25, 0x25,
        ]
    );
}

#[test]
fn streaming_matches_oneshot() {
    let data: alloc::vec::Vec<u8> = (0..64u32).map(|i| (i * 13 + 5) as u8).collect();
    let expected = sum_mdc2(&data);

    let mut h = new_mdc2();
    h.write_all(&data[..5]).unwrap();
    h.write_all(&data[5..19]).unwrap();
    h.write_all(&data[19..]).unwrap();
    assert_eq!(h.sum(), expected);

    // Same for the alternate padding.
    let mut h2 = Mdc2::new_with_pad(PAD_2).unwrap();
    h2.write_all(&data[..7]).unwrap();
    h2.write_all(&data[7..]).unwrap();
    let mut expected2 = Mdc2::new_with_pad(PAD_2).unwrap();
    expected2.write_all(&data).unwrap();
    assert_eq!(h2.sum(), expected2.sum());
}

#[test]
fn reset_reuses_state() {
    let mut h = new_mdc2();
    h.write_all(b"Now is the time for all ").unwrap();
    let first = h.sum();

    h.reset();
    h.write_all(b"Now is the time for all ").unwrap();
    assert_eq!(h.sum(), first);
}

#[test]
fn invalid_pad_rejected() {
    assert!(Mdc2::new_with_pad(0).is_err());
    assert!(Mdc2::new_with_pad(3).is_err());
}
