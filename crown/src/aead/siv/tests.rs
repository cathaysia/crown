use super::*;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Round-trip test cases from OpenSSL evpciph_aes_siv.txt: key, AADs, tag,
/// plaintext, ciphertext. The first case is RFC 5297 A.1, the 3-AAD cases
/// are RFC 5297 A.2 (and permutations of empty AADs).
#[test]
fn rfc5297_vectors() {
    let cases: &[(&str, &[&str], &str, &str, &str)] = &[
        (
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            &["101112131415161718191a1b1c1d1e1f2021222324252627"],
            "85632d07c6e8f37f950acd320a2ecc93",
            "112233445566778899aabbccddee",
            "40c02b9690c4dc04daef7f6afe5c",
        ),
        (
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            &[],
            "f1c5fdeac1f15a26779c1501f9fb7588",
            "112233445566778899aabbccddee",
            "27e946c669088ab06da58c5c831c",
        ),
        (
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            &[""],
            "d1022f5b3664e5a4dfaf90f85be6f28a",
            "112233445566778899aabbccddee",
            "b66cff6b8eca0b79f083b39a0901",
        ),
        (
            "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
            &[
                "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
                "102030405060708090a0",
                "09f911029d74e35bd84156c5635688c0",
            ],
            "7bdb6e3b432667eb06f4d14bff2fbd0f",
            "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
            "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d",
        ),
        (
            "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
            &[
                "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
                "",
                "09f911029d74e35bd84156c5635688c0",
            ],
            "83ce6593a8fa67eb6fcd2819cedfc011",
            "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
            "30d937b42f71f71f93fc2d8d702d3eac8dc7651eefcd81120081ff29d626f97f3de17f2969b691c91b69b652bf3a6d",
        ),
        (
            "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
            &[
                "",
                "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
                "09f911029d74e35bd84156c5635688c0",
            ],
            "77dd4a44f5a6b41302121ee7f378de25",
            "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
            "0fcd664c922464c88939d71fad7aefb864e501b0848a07d39201c1067a7288f3dadf0131a823a0bc3d588e8564a5fe",
        ),
        (
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfefffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
            &["101112131415161718191a1b1c1d1e1f2021222324252627"],
            "89e869b93256785154f0963962fe0740",
            "112233445566778899aabbccddee",
            "eff356e42dec1f4febded36642f2",
        ),
        (
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfefffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
            &["101112131415161718191a1b1c1d1e1f2021222324252627"],
            "724dfb2eaf94dbb19b0ba3a299a0801e",
            "112233445566778899aabbccddee",
            "f3b05a55498ec2552690b89810e4",
        ),
    ];

    for (key, aads, tag, pt, ct) in cases {
        let key = hex_to_bytes(key);
        let tag = hex_to_bytes(tag);
        let pt = hex_to_bytes(pt);
        let ct = hex_to_bytes(ct);
        let aads: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            aads.iter().map(|a| hex_to_bytes(a)).collect();
        let aads: alloc::vec::Vec<&[u8]> = aads.iter().map(|a| a.as_slice()).collect();

        let mut siv = AesSiv::new(&key).unwrap();

        let mut buf = pt.clone();
        let out_tag = siv.seal_in_place(&mut buf, &aads).unwrap();
        assert_eq!(buf, ct, "seal mismatch");
        assert_eq!(out_tag.to_vec(), tag, "tag mismatch");

        siv.open_in_place(&mut buf, &out_tag, &aads).unwrap();
        assert_eq!(buf, pt, "open mismatch");
    }
}

// SIV accepts a single one-block plaintext and empty plaintext (RFC 5297
// allows empty plaintext; CMAC over the empty message path len < 16).
#[test]
fn empty_and_single_block() {
    let key = hex_to_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let mut siv = AesSiv::new(&key).unwrap();

    let mut empty: [u8; 0] = [];
    let tag = siv.seal_in_place(&mut empty, &[]).unwrap();
    assert_eq!(tag.len(), 16);
    siv.open_in_place(&mut empty, &tag, &[]).unwrap();

    let mut block = [0u8; 16];
    let tag = siv.seal_in_place(&mut block, &[]).unwrap();
    siv.open_in_place(&mut block, &tag, &[]).unwrap();
    assert_eq!(block, [0u8; 16]);
}

// Tampering with the tag or the ciphertext must fail and clear the buffer.
#[test]
fn rejects_bad_tag() {
    let key = hex_to_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let aad = [0x10u8, 0x11, 0x12];
    let mut siv = AesSiv::new(&key).unwrap();

    let mut buf = b"hello world".to_vec();
    let tag = siv.seal_in_place(&mut buf, &[&aad]).unwrap();

    // Wrong tag length is rejected outright.
    assert!(siv.open_in_place(&mut buf, &tag[..15], &[&aad]).is_err());

    // A tampered tag fails authentication and cleanses the output.
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let mut buf2 = buf.clone();
    assert_eq!(
        siv.open_in_place(&mut buf2, &bad_tag, &[&aad]),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(buf2.iter().all(|b| *b == 0));

    // A tampered ciphertext fails authentication as well.
    let mut buf3 = buf.clone();
    buf3[0] ^= 1;
    assert!(siv.open_in_place(&mut buf3, &tag, &[&aad]).is_err());

    // Missing AAD changes S2V, so the tag check fails.
    let mut buf4 = buf;
    assert!(siv.open_in_place(&mut buf4, &tag, &[]).is_err());
}

#[test]
fn rejects_invalid_key_size() {
    assert!(AesSiv::new(&[0u8; 16]).is_err());
    assert!(AesSiv::new(&[0u8; 40]).is_err());
    assert!(AesSiv::new(&[0u8; 65]).is_err());
}
