use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use openssl::hash::MessageDigest;
use std::hint::black_box;

fn bench_md5(c: &mut Criterion) {
    let case = [
        (8, false),
        (64, false),
        (128, false),
        (256, false),
        (512, false),
        (1024, false),
        (8192, false),
        (1024 * 1024, false),
        (8 * 1024 * 1024, false),
    ];
    for (size, unaligned) in case {
        let mut buf = vec![0u8; size + 1];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let data = if unaligned && buf.len() > 1 {
            &buf[1..size + 1]
        } else {
            &buf[..size]
        };

        let mut group = c.benchmark_group("md5");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(
            format!(
                "kittytls_md5_{size}_{}",
                if unaligned { "unaligned" } else { "aligned" }
            ),
            |b| {
                b.iter(|| {
                    let _ = kittytls::md5::sum(black_box(data));
                })
            },
        );

        group.bench_function(
            format!(
                "rustcrypto_md5_{size}_{}",
                if unaligned { "unaligned" } else { "aligned" }
            ),
            |b| {
                b.iter(|| {
                    let digest = md5::compute(black_box(data));
                    let _ = digest.to_vec();
                })
            },
        );

        group.bench_function(
            format!(
                "openssl_md5_{size}_{}",
                if unaligned { "unaligned" } else { "aligned" }
            ),
            |b| {
                b.iter(|| {
                    let hash = openssl::hash::hash(MessageDigest::md5(), black_box(data)).unwrap();
                    let _ = hash.to_vec();
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_md5);

criterion_main!(benches);
