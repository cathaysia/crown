use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use openssl::hash::MessageDigest;
use sha3::Digest;
use std::hint::black_box;

fn bench_sha3(c: &mut Criterion) {
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

        let mut group = c.benchmark_group("sha3");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(
            format!(
                "kittytls_sha3_{size}_{}",
                if unaligned { "unaligned" } else { "aligned" }
            ),
            |b| {
                b.iter(|| {
                    let _ = kittytls::sha3::sum256(black_box(data));
                })
            },
        );

        group.bench_function(
            format!(
                "rustcrypto_sha3_{size}_{}",
                if unaligned { "unaligned" } else { "aligned" }
            ),
            |b| {
                b.iter(|| {
                    let digest = sha3::Sha3_256::digest(black_box(data));
                    let _ = digest.to_vec();
                })
            },
        );

        group.bench_function(
            format!(
                "openssl_sha3_{size}_{}",
                if unaligned { "unaligned" } else { "aligned" }
            ),
            |b| {
                b.iter(|| {
                    let hash =
                        openssl::hash::hash(MessageDigest::sha3_256(), black_box(data)).unwrap();
                    let _ = hash.to_vec();
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_sha3);

criterion_main!(benches);
