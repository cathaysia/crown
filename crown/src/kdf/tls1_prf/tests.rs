use super::*;
use crate::envelope::EvpHash;

fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// NIST vectors from OpenSSL evpkdf_tls12_prf.txt / evpkdf_tls11_prf.txt.
#[test]
fn nist_vectors() {
    // TLS 1.2, SHA-256, seed = "master secret" || client_random || server_random
    let seed = b"master secret";
    let seed = [
        seed.as_slice(),
        &hex_to_bytes("36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c")[..],
        &hex_to_bytes("f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce")[..],
    ]
    .concat();
    let out = derive(
        EvpHash::new_sha256_hmac,
        &hex_to_bytes("f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc"),
        &seed,
        48,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf")
    );

    // TLS 1.2, SHA-256, seed = "key expansion" || server_random || client_random
    let seed = b"key expansion";
    let seed = [
        seed.as_slice(),
        &hex_to_bytes("ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868")[..],
        &hex_to_bytes("62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616")[..],
    ]
    .concat();
    let secret = hex_to_bytes("202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf");
    let out = derive(EvpHash::new_sha256_hmac, &secret, &seed, 128).unwrap();
    assert_eq!(
        out,
        hex_to_bytes("d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928")
    );

    // TLS 1.0/1.1 MD5-SHA1 combination.
    let seed = b"master secret";
    let seed = [
        seed.as_slice(),
        &hex_to_bytes("e5acaf549cd25c22d964c0d930fa4b5261d2507fad84c33715b7b9a864020693")[..],
        &hex_to_bytes("135e4d557fdf3aa6406d82975d5c606a9734c9334b42136e96990fbd5358cdb2")[..],
    ]
    .concat();
    let out = derive_md5_sha1(
        &hex_to_bytes("bded7fa5c1699c010be23dd06ada3a48349f21e5f86263d512c0c5cc379f0e780ec55d9844b2f1db02a96453513568d0"),
        &seed,
        48,
    )
    .unwrap();
    assert_eq!(
        out,
        hex_to_bytes("2f6962dfbc744c4b2138bb6b3d33054c5ecc14f24851d9896395a44ab3964efc2090c5bf51a0891209f46c1e1e998f62")
    );
}

#[test]
fn rejects_invalid_length() {
    assert!(derive(EvpHash::new_sha256_hmac, b"s", b"seed", 0).is_err());
    assert!(derive_md5_sha1(b"s", b"seed", 0).is_err());
}
