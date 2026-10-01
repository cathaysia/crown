use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

struct BenchRng;

impl crown::rng::Rng for BenchRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        rand::fill(out);
    }
}

fn bench_dsa(c: &mut Criterion) {
    let params = crown::dsa::dsa_2048_256();
    let key = crown::dsa::generate(&params, &mut BenchRng).unwrap();
    let msg: [u8; 32] = core::array::from_fn(|i| i as u8);

    let (r, s) = crown::dsa::sign_sha256(&key, &msg, &mut BenchRng).unwrap();
    assert!(crown::dsa::verify_sha256(&params, &key.y, &msg, &r, &s).unwrap());

    let mut group = c.benchmark_group("dsa_2048_256");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_keygen", |b| {
        b.iter(|| black_box(crown::dsa::generate(black_box(&params), &mut BenchRng).unwrap()))
    });
    group.bench_function("crown_sign", |b| {
        b.iter(|| black_box(crown::dsa::sign_sha256(black_box(&key), &msg, &mut BenchRng).unwrap()))
    });
    group.bench_function("crown_verify", |b| {
        b.iter(|| {
            black_box(
                crown::dsa::verify_sha256(black_box(&params), &key.y, &msg, black_box(&r), &s)
                    .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_dh(c: &mut Criterion) {
    let (p, g) = crown::dh::modp2048();
    let (x, _y) = crown::dh::generate(&p, &g, &mut BenchRng).unwrap();
    let peer_y = crown::dh::generate(&p, &g, &mut BenchRng).unwrap().1;

    let mut group = c.benchmark_group("dh_modp2048");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_generate", |b| {
        b.iter(|| black_box(crown::dh::generate(black_box(&p), &g, &mut BenchRng).unwrap()))
    });
    group.bench_function("crown_agree", |b| {
        b.iter(|| black_box(crown::dh::agree(black_box(&p), black_box(&x), &peer_y).unwrap()))
    });

    group.finish();
}

criterion_group!(benches, bench_dsa, bench_dh);
criterion_main!(benches);
