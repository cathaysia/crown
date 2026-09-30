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

criterion_group!(
    benches,
    bench_hkdf,
    bench_pbkdf2,
    bench_scrypt,
    bench_argon2
);
criterion_main!(benches);
