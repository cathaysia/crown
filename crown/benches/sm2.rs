use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::bn::Bn;

struct BenchRng;

impl crown::rng::Rng for BenchRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        rand::fill(out);
    }
}

/// Private scalar below 2^253 (SM2 order is a 256-bit prime).
fn rand_scalar() -> Bn {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    b[0] &= 0x0f;
    b[31] |= 1;
    Bn::from_be_bytes(&b)
}

fn bench_sm2(c: &mut Criterion) {
    let d = rand_scalar();
    let curve = crown::sm2::sm2_curve();
    let public = crown::ec::mul_base(&curve, &d);
    let msg: [u8; 64] = core::array::from_fn(|i| i as u8);

    let (r, s) = crown::sm2::sign_default_id(&d, &msg, &mut BenchRng).unwrap();
    assert!(crown::sm2::verify_default_id(&public, &msg, &r, &s).unwrap());

    let mut group = c.benchmark_group("sm2");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_sign", |b| {
        b.iter(|| {
            black_box(crown::sm2::sign_default_id(black_box(&d), &msg, &mut BenchRng).unwrap())
        })
    });
    group.bench_function("crown_verify", |b| {
        b.iter(|| {
            black_box(
                crown::sm2::verify_default_id(black_box(&public), &msg, black_box(&r), &s).unwrap(),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_sm2);
criterion_main!(benches);
