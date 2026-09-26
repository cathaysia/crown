use super::*;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Vectors from OpenSSL evpkdf_pbkdf1.txt (password "password", salt
// "saltsalt", plus the empty-password set).
#[test]
fn openssl_vectors() {
    let cases: &[(HashFactory, &str, u64, &str)] = &[
        (
            EvpHash::new_md2,
            "2C5DAEBD49984F34642ACC09BAD696D7",
            1,
            "password",
        ),
        (
            EvpHash::new_md5,
            "FDBDF3419FFF98BDB0241390F62A9DB3",
            1,
            "password",
        ),
        (
            EvpHash::new_sha1,
            "CAB86DD6261710891E8CB56EE3625691",
            1,
            "password",
        ),
        (
            EvpHash::new_md2,
            "FD7999A1AB54B01B4FC39389A5FE820D",
            2,
            "password",
        ),
        (
            EvpHash::new_md5,
            "3D4A8D4FB4C6E8686B21D36142902966",
            2,
            "password",
        ),
        (EvpHash::new_md2, "8ECD1C4C1D57C415295784CCD4686905", 1, ""),
        (EvpHash::new_md5, "F3D07DE5EFB5E2C3EAFC16B0CF7E07FA", 1, ""),
        (EvpHash::new_sha1, "2C2ABACE4BD8BB19F67113DA146DBB8C", 1, ""),
    ];

    for (hash, expected, iter, pass) in cases {
        let out = derive(*hash, pass.as_bytes(), b"saltsalt", *iter, 16).unwrap();
        assert_eq!(out, hex_to_bytes(expected), "iter {iter} pass {pass:?}");
    }

    // The long-password vector uses salt "saltSALT".
    let out = derive(
        EvpHash::new_sha1,
        b"passwordPASSWORDpassword",
        b"saltSALT",
        65537,
        16,
    )
    .unwrap();
    assert_eq!(out, hex_to_bytes("B2B4635718AAAD9FEF23FE328EB83ECF"));
}

#[test]
fn rejects_invalid_parameters() {
    // key_len larger than the digest output is impossible for PBKDF1.
    assert!(derive(EvpHash::new_sha1, b"pass", b"salt", 1, 21).is_err());
    assert!(derive(EvpHash::new_sha1, b"pass", b"salt", 0, 16).is_err());
    assert!(derive(EvpHash::new_sha1, b"pass", b"salt", 1, 0).is_err());
}
