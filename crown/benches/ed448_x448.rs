use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

fn bench_x448(c: &mut Criterion) {
    let mut priv_key = [0u8; 56];
    rand::fill(&mut priv_key);
    let peer_pub = crown::x448::public_from_private(&priv_key);

    let mut group = c.benchmark_group("x448");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_public_from_private", |b| {
        b.iter(|| black_box(crown::x448::public_from_private(black_box(&priv_key))))
    });
    group.bench_function("crown_agree", |b| {
        b.iter(|| black_box(crown::x448::x448(black_box(&priv_key), &peer_pub).unwrap()))
    });

    group.finish();
}

fn bench_ed448(c: &mut Criterion) {
    let mut seed = [0u8; 57];
    rand::fill(&mut seed);
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);

    let public = crown::ed448::public_from_secret(&seed);
    let sig = crown::ed448::sign(&seed, &msg, &[]);
    assert!(crown::ed448::verify(&public, &sig, &msg, &[]));

    let mut group = c.benchmark_group("ed448");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_public_from_secret", |b| {
        b.iter(|| black_box(crown::ed448::public_from_secret(black_box(&seed))))
    });
    group.bench_function("crown_sign", |b| {
        b.iter(|| black_box(crown::ed448::sign(black_box(&seed), &msg, &[])))
    });
    group.bench_function("crown_verify", |b| {
        b.iter(|| black_box(crown::ed448::verify(black_box(&public), &sig, &msg, &[])))
    });
    group.bench_function("crown_sign_ph", |b| {
        let prehash = crown::ed448::prehash(&msg);
        b.iter(|| black_box(crown::ed448::sign_ph(black_box(&seed), &prehash, &[])))
    });
    group.bench_function("crown_verify_ph", |b| {
        let prehash = crown::ed448::prehash(&msg);
        let sig_ph = crown::ed448::sign_ph(&seed, &prehash, &[]);
        b.iter(|| {
            black_box(crown::ed448::verify_ph(
                black_box(&public),
                &sig_ph,
                &prehash,
                &[],
            ))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_x448, bench_ed448);
criterion_main!(benches);
