use super::*;

fn sample_key() -> alloc::vec::Vec<u8> {
    (0x40u8..0x60).collect()
}

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Reference values validated against the NIST SP 800-185 sample PDFs and
// OpenSSL 3.5.8 `openssl mac KMAC128/KMAC256`.
#[test]
fn sp800_185_sample_1_kmac128() {
    // KMAC128(K, 00010203, 256, S="") — NIST sample #1.
    let mut mac = Kmac128::new(&sample_key(), b"").unwrap();
    mac.write(&[0x00, 0x01, 0x02, 0x03]);
    let mut tag = [0u8; 32];
    mac.sum(&mut tag);
    assert_eq!(
        &tag,
        &hex_to_bytes("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E")[..]
    );
}

#[test]
fn sp800_185_sample_2_kmac128_empty() {
    // KMAC128(K, "", 256, S="").
    let mut mac = Kmac128::new(&sample_key(), b"").unwrap();
    let mut tag = [0u8; 32];
    mac.sum(&mut tag);
    assert_eq!(
        &tag,
        &hex_to_bytes("58E8A99428D57617AA5CAEAE1DE3DB108AF411286E64A00A6E1F308C3FE9557C")[..]
    );
}

#[test]
fn sp800_185_sample_3_kmac128_custom() {
    // KMAC128(K, 00010203, 256, S="My Tagged Application").
    let s = b"My Tagged Application";
    let mut mac = Kmac128::new(&sample_key(), s).unwrap();
    mac.write(&[0x00, 0x01, 0x02, 0x03]);
    let mut tag = [0u8; 32];
    mac.sum(&mut tag);
    assert_eq!(
        &tag,
        &hex_to_bytes("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5")[..]
    );
}

#[test]
fn sp800_185_sample_4_kmac256_custom() {
    // KMAC256(K, 00010203, 512, S="My Tagged Application").
    let s = b"My Tagged Application";
    let mut mac = Kmac256::new(&sample_key(), s).unwrap();
    mac.write(&[0x00, 0x01, 0x02, 0x03]);
    let mut tag = [0u8; 64];
    mac.sum(&mut tag);
    assert_eq!(
        &tag,
        &hex_to_bytes(
            "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7\
             F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"
        )[..]
    );
}

#[test]
fn sp800_185_sample_5_kmac256_empty() {
    // KMAC256(K, "", 512, S="").
    let mut mac = Kmac256::new(&sample_key(), b"").unwrap();
    let mut tag = [0u8; 64];
    mac.sum(&mut tag);
    assert_eq!(
        &tag,
        &hex_to_bytes(
            "2387AADC639D5214F0A794D88D613A2E43AD8261CC09BE3AB328A3C72A0881D3\
             B550E8AA41D50B723CDD463509FDABF8F7A60FF737245C6E35A3820EE7530CD2"
        )[..]
    );
}

#[test]
fn streaming_matches_oneshot() {
    let msg: alloc::vec::Vec<u8> = (0..200u8).collect();

    let mut one = Kmac128::new(&sample_key(), b"").unwrap();
    one.write(&msg);
    let mut expected = [0u8; 32];
    one.sum(&mut expected);

    let mut stream = Kmac128::new(&sample_key(), b"").unwrap();
    for chunk in msg.chunks(17) {
        stream.write(chunk);
    }
    assert!(stream.verify(&expected));
}

#[test]
fn xof_omits_length_encoding() {
    // KMAC128_XOF(K, 00010203, S="My Tagged Application") — arbitrary output
    // without right_encode(L).
    let s = b"My Tagged Application";
    let mut mac = Kmac128::new(&sample_key(), s).unwrap();
    mac.write(&[0x00, 0x01, 0x02, 0x03]);
    let mut out = [0u8; 64];
    mac.sum_xof(&mut out);
    assert_eq!(
        &out,
        &hex_to_bytes(
            "396369E8217C7FBF76093CF74CBB1EDB15369E7F4FBBB42B4DB28C63AF3696C9\
             6F06E41CC53F2BEC0F7376905DD923A8959DB5921625C99E357D486C8199C6E4"
        )[..]
    );
}

#[test]
fn wrong_tag_fails() {
    let mut mac = Kmac128::new(&sample_key(), b"").unwrap();
    mac.write(b"abc");
    let mut tag = [0u8; 32];
    mac.sum(&mut tag);
    tag[0] ^= 1;

    let mut mac2 = Kmac128::new(&sample_key(), b"").unwrap();
    mac2.write(b"abc");
    assert!(!mac2.verify(&tag));
}

#[test]
fn write_after_sum_panics() {
    let mut mac = Kmac128::new(&sample_key(), b"").unwrap();
    let mut tag = [0u8; 32];
    mac.sum(&mut tag);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mac.write(b"more");
    }));
    assert!(result.is_err());
}
