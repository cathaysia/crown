use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

struct BenchRng;

impl crown::rsa::Rng for BenchRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        rand::fill(out);
    }
}

fn bench_rsa(c: &mut Criterion) {
    let msg: [u8; 32] = core::array::from_fn(|i| i as u8);

    // RSA-2048. Keys are generated once; both sides use independently
    // generated 2048-bit keys (the private exponent is not exported by
    // crown's key object, and the modexp dominates the cost either way).
    let key2048 = crown::rsa::RsaPrivateKey::generate(2048, 65537, &mut BenchRng).unwrap();
    let pub2048 = key2048.public();

    let mut group = c.benchmark_group("rsa2048");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_encrypt_raw", |b| {
        b.iter(|| black_box(pub2048.encrypt_raw(black_box(&msg)).unwrap()))
    });
    group.bench_function("crown_sign_pkcs1v15", |b| {
        b.iter(|| {
            black_box(
                key2048
                    .sign_pkcs1v15(crown::envelope::EvpHash::new_sha256, black_box(&msg))
                    .unwrap(),
            )
        })
    });

    // A padded ciphertext produced by crown itself, for the decrypt paths.
    let crown_rng = &mut BenchRng;
    let crown_ct = pub2048.encrypt_pkcs1v15(crown_rng, &msg).unwrap();
    let crown_sig = key2048
        .sign_pkcs1v15(crown::envelope::EvpHash::new_sha256, &msg)
        .unwrap();

    group.bench_function("crown_encrypt_pkcs1v15", |b| {
        let rng = &mut BenchRng;
        b.iter(|| black_box(pub2048.encrypt_pkcs1v15(rng, black_box(&msg)).unwrap()))
    });
    group.bench_function("crown_decrypt_pkcs1v15", |b| {
        b.iter(|| black_box(key2048.decrypt_pkcs1v15(black_box(&crown_ct)).unwrap()))
    });
    group.bench_function("crown_verify_pkcs1v15", |b| {
        b.iter(|| {
            black_box(
                pub2048
                    .verify_pkcs1v15(
                        crown::envelope::EvpHash::new_sha256,
                        black_box(&msg),
                        &crown_sig,
                    )
                    .unwrap(),
            )
        })
    });
    group.bench_function("crown_keygen", |b| {
        b.iter(|| {
            black_box(crown::rsa::RsaPrivateKey::generate(2048, 65537, &mut BenchRng).unwrap())
        })
    });

    // RustCrypto comparison.
    use rsa::pkcs1v15::{Pkcs1v15Encrypt, Signature, SigningKey};
    use rsa::signature::{Keypair, Signer, Verifier};
    use sha2::Sha256;

    let mut rng = rsa::rand_core::OsRng;
    let rust_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rust_pub = rsa::RsaPublicKey::from(&rust_key);
    let rust_ct = rust_pub.encrypt(&mut rng, Pkcs1v15Encrypt, &msg).unwrap();
    let rust_signing = SigningKey::<Sha256>::new(rust_key.clone());
    let rust_sig: Signature = rust_signing.sign(&msg);
    let rust_verifying = rust_signing.verifying_key();

    group.bench_function("rustcrypto_encrypt_pkcs1v15", |b| {
        b.iter(|| {
            black_box(
                rust_pub
                    .encrypt(&mut rng, Pkcs1v15Encrypt, black_box(&msg))
                    .unwrap(),
            )
        })
    });
    group.bench_function("rustcrypto_decrypt_pkcs1v15", |b| {
        b.iter(|| {
            black_box(
                rust_key
                    .decrypt(Pkcs1v15Encrypt, black_box(&rust_ct))
                    .unwrap(),
            )
        })
    });
    group.bench_function("rustcrypto_sign_pkcs1v15", |b| {
        b.iter(|| black_box(rust_signing.sign(black_box(&msg))))
    });
    group.bench_function("rustcrypto_verify_pkcs1v15", |b| {
        b.iter(|| black_box(rust_verifying.verify(black_box(&msg), &rust_sig).is_ok()))
    });
    group.bench_function("rustcrypto_keygen", |b| {
        b.iter(|| black_box(rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap()))
    });

    group.finish();

    // RSA-4096 private operations only (key generation is too slow to bench).
    let key4096 = crown::rsa::RsaPrivateKey::generate(4096, 65537, &mut BenchRng).unwrap();
    let pub4096 = key4096.public();
    let ct4096 = pub4096.encrypt_raw(&msg).unwrap();
    let mut group = c.benchmark_group("rsa4096");
    group.throughput(Throughput::Elements(1));
    group.bench_function("crown_encrypt_raw", |b| {
        b.iter(|| black_box(pub4096.encrypt_raw(black_box(&msg)).unwrap()))
    });
    group.bench_function("crown_decrypt_raw", |b| {
        b.iter(|| black_box(key4096.decrypt_raw(black_box(&ct4096)).unwrap()))
    });
    group.finish();
}

criterion_group!(benches, bench_rsa);
criterion_main!(benches);
