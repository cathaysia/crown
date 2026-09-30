use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

fn bench_ed25519(c: &mut Criterion) {
    let mut secret = [0u8; 32];
    rand::fill(&mut secret);
    let public = crown::ed25519::public_from_secret(&secret);
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);
    let sig = crown::ed25519::sign(&secret, &msg);

    let mut group = c.benchmark_group("ed25519");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_public_from_secret", |b| {
        b.iter(|| black_box(crown::ed25519::public_from_secret(black_box(&secret))))
    });
    group.bench_function("crown_sign", |b| {
        b.iter(|| black_box(crown::ed25519::sign(black_box(&secret), black_box(&msg))))
    });
    group.bench_function("crown_verify", |b| {
        b.iter(|| {
            black_box(crown::ed25519::verify(
                black_box(&public),
                black_box(&sig),
                &msg,
            ))
        })
    });

    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    let sk = SigningKey::from_bytes(&secret);
    let dalek_sig = sk.sign(&msg);
    let vk = VerifyingKey::from(&sk);

    group.bench_function("rustcrypto_public_from_secret", |b| {
        b.iter(|| black_box(VerifyingKey::from(black_box(&sk))))
    });
    group.bench_function("rustcrypto_sign", |b| {
        b.iter(|| black_box(sk.sign(black_box(&msg))))
    });
    group.bench_function("rustcrypto_verify", |b| {
        b.iter(|| black_box(vk.verify(black_box(&msg), &dalek_sig).is_ok()))
    });

    group.finish();
}

fn bench_x25519(c: &mut Criterion) {
    let mut private = [0u8; 32];
    rand::fill(&mut private);
    let _public = crown::x25519::public_from_private(&private);
    let mut peer = [0u8; 32];
    rand::fill(&mut peer);

    let mut group = c.benchmark_group("x25519");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_public_from_private", |b| {
        b.iter(|| black_box(crown::x25519::public_from_private(black_box(&private))))
    });
    group.bench_function("crown_x25519", |b| {
        b.iter(|| black_box(crown::x25519::x25519(black_box(&private), black_box(&peer))))
    });

    use x25519_dalek::x25519;
    group.bench_function("rustcrypto_public_from_private", |b| {
        b.iter(|| black_box(x25519(black_box(private), [9u8; 32])))
    });
    group.bench_function("rustcrypto_x25519", |b| {
        b.iter(|| black_box(x25519(black_box(private), black_box(peer))))
    });

    group.finish();
}

criterion_group!(benches, bench_ed25519, bench_x25519);
criterion_main!(benches);
