use cipher::KeyIvInit;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittycrypto::cipher::StreamCipher;
use std::hint::black_box;

fn bench_chacha20(c: &mut Criterion) {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;

    let case = [128, 1024];

    for size in case {
        let mut buf = vec![0u8; size + 1];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        let data = vec![0u8; size];

        let mut group = c.benchmark_group("chacha20");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("kittycrypto_chacha20_{size}",), |b| {
            let mut cipher =
                kittycrypto::chacha20::Chacha20Cipher::new_unauthenticated_cipher(&key, &[0u8; 12])
                    .unwrap();
            let mut dst = data.clone();
            b.iter(|| {
                let _ = cipher.xor_key_stream(black_box(&mut dst), black_box(&data));
            })
        });

        group.bench_function(format!("rustcrypto_chacha20_{size}",), |b| {
            let mut cipher = chacha20::ChaCha20::new_from_slices(&key, &[0u8; 12]).unwrap();
            b.iter(|| {
                let mut data = data.clone();
                cipher::StreamCipher::apply_keystream(&mut cipher, black_box(&mut data));
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_chacha20);

criterion_main!(benches);
