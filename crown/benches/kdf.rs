use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use crown::core::CoreRead;
use std::hint::black_box;

fn bench_hkdf(c: &mut Criterion) {
    let ikm = [0x42u8; 32];
    let salt = [0x24u8; 32];
    let info = [0x11u8; 16];

    let mut group = c.benchmark_group("hkdf_sha256");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_32", |b| {
        b.iter(|| {
            let mut okm =
                crown::kdf::hkdf::new::<32, _, _>(crown::hash::sha256::new256, &ikm, &salt, &info);
            let mut out = [0u8; 32];
            let _ = okm.read(&mut out).unwrap();
            black_box(out)
        })
    });
    group.bench_function("rustcrypto_32", |b| {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut out = [0u8; 32];
        b.iter(|| {
            hk.expand(black_box(&info), &mut out).unwrap();
            black_box(out)
        })
    });

    group.finish();
}

fn bench_pbkdf2(c: &mut Criterion) {
    let password = b"correct horse battery staple";
    let salt = [0x24u8; 16];

    let mut group = c.benchmark_group("pbkdf2_sha256_1000");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_32", |b| {
        b.iter(|| {
            black_box(crown::password_hash::pbkdf2::key::<32, _, _>(
                password,
                &salt,
                1000,
                32,
                crown::hash::sha256::new256,
            ))
        })
    });
    group.bench_function("rustcrypto_32", |b| {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;
        let mut out = [0u8; 32];
        b.iter(|| {
            pbkdf2_hmac::<Sha256>(password, &salt, 1000, &mut out);
            black_box(out)
        })
    });

    group.finish();
}

fn bench_scrypt(c: &mut Criterion) {
    let password = b"correct horse battery staple";
    let salt = [0x24u8; 16];

    let mut group = c.benchmark_group("scrypt_n16384_r8_p1");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_32", |b| {
        b.iter(|| {
            black_box(crown::password_hash::scrypt::key(password, &salt, 16384, 8, 1, 32).unwrap())
        })
    });
    group.bench_function("rustcrypto_32", |b| {
        use scrypt::{scrypt, Params};
        let params = Params::new(14, 8, 1, 32).unwrap();
        let mut out = [0u8; 32];
        b.iter(|| {
            scrypt(password, &salt, &params, &mut out).unwrap();
            black_box(out)
        })
    });

    group.finish();
}

fn bench_argon2(c: &mut Criterion) {
    let password = b"correct horse battery staple";
    let salt = [0x24u8; 16];

    let mut group = c.benchmark_group("argon2id_t1_m64mib");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_32", |b| {
        b.iter(|| {
            black_box(
                crown::password_hash::argon2::id_key(password, &salt, 1, 65536, 1, 32).unwrap(),
            )
        })
    });
    group.bench_function("rustcrypto_32", |b| {
        use argon2::{Algorithm, Argon2, Params, Version};
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(65536, 1, 1, None).unwrap(),
        );
        let mut out = [0u8; 32];
        b.iter(|| {
            argon.hash_password_into(password, &salt, &mut out).unwrap();
            black_box(out)
        })
    });

    group.finish();
}

/// Certificate-style / protocol KDFs. No RustCrypto equivalent ships most
/// of these, so they are crown-only throughput baselines.
fn bench_kdf_variants(c: &mut Criterion) {
    use crown::block::aes::Aes;
    use crown::envelope::EvpHash;
    use crown::kdf::kbkdf::{FixedInput, Mode};

    let key = [0x42u8; 32];
    let key16 = [0x42u8; 16];
    let salt = [0x24u8; 16];
    let info = [0x11u8; 16];
    let secret = [0x33u8; 32];

    let mut group = c.benchmark_group("kdf_variants");
    group.throughput(Throughput::Elements(1));

    group.bench_function("tls1_prf_sha256_32", |b| {
        b.iter(|| {
            black_box(
                crown::kdf::tls1_prf::derive(EvpHash::new_sha256_hmac, &secret, &info, 32).unwrap(),
            )
        })
    });
    group.bench_function("sskdf_hmac_sha256_32", |b| {
        b.iter(|| {
            black_box(
                crown::kdf::sskdf::derive_hmac(EvpHash::new_sha256_hmac, &salt, &secret, &info, 32)
                    .unwrap(),
            )
        })
    });
    group.bench_function("x963_sha256_32", |b| {
        b.iter(|| {
            black_box(
                crown::kdf::sskdf::x963_derive_hash(EvpHash::new_sha256, &secret, &info, 32)
                    .unwrap(),
            )
        })
    });
    group.bench_function("kbkdf_counter_hmac_sha256_32", |b| {
        let fi = FixedInput {
            label: b"label",
            context: &info,
            iv: &[],
            use_l: true,
            use_separator: true,
            r: 32,
        };
        b.iter(|| {
            black_box(
                crown::kdf::kbkdf::derive_hmac(
                    EvpHash::new_sha256_hmac,
                    Mode::Counter,
                    &key,
                    &fi,
                    32,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("krb5kdf_aes128_32", |b| {
        let aes = Aes::new(&key16).unwrap();
        b.iter(|| black_box(crown::kdf::krb5kdf::derive(&aes, 32, b"constant").unwrap()))
    });
    group.bench_function("sshkdf_sha256_32", |b| {
        b.iter(|| {
            black_box(
                crown::kdf::sshkdf::derive(
                    EvpHash::new_sha256,
                    &secret,
                    &info,
                    &salt,
                    crown::kdf::sshkdf::SshKdfType::A,
                    32,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("srtpkdf_aes_cm_32", |b| {
        let master_salt = [0x24u8; 14];
        let index = [0x11u8; 6];
        b.iter(|| {
            black_box(
                crown::kdf::srtpkdf::derive_aes_cm(&key16, &master_salt, &index, 0, 0).unwrap(),
            )
        })
    });
    group.bench_function("ikev2_dkm_hmac_sha256_32", |b| {
        let ni = [0x24u8; 32];
        let nr = [0x42u8; 32];
        b.iter(|| {
            black_box(
                crown::kdf::ikev2kdf::dkm(
                    EvpHash::new_sha256_hmac,
                    &secret,
                    &ni,
                    &nr,
                    None,
                    None,
                    Some(&key),
                    32,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("x942_sha256_32", |b| {
        b.iter(|| {
            black_box(
                crown::kdf::x942kdf::derive(
                    EvpHash::new_sha256,
                    &secret,
                    crown::kdf::x942kdf::CekAlg::Aes128Wrap,
                    &info,
                    &salt,
                    &[],
                    &[],
                    true,
                    32,
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("pkcs12kdf_sha256_1000", |b| {
        b.iter(|| {
            black_box(
                crown::kdf::pkcs12kdf::derive(EvpHash::new_sha256, b"password", &salt, 1, 1000, 32)
                    .unwrap(),
            )
        })
    });
    group.bench_function("pbkdf1_sha256_1000", |b| {
        b.iter(|| {
            black_box(
                crown::kdf::pbkdf1::derive(EvpHash::new_sha256, b"password", &salt, 1000, 20)
                    .unwrap(),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hkdf,
    bench_pbkdf2,
    bench_scrypt,
    bench_argon2,
    bench_kdf_variants
);
criterion_main!(benches);
