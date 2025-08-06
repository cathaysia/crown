use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittycrypto::cipher::StreamCipher;
use rc4::KeyInit;
use std::hint::black_box;

fn bench_rc4(c: &mut Criterion) {
    let case = [128, 1024];
    const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    for size in case {
        let mut buf = vec![0u8; size + 1];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        let data = vec![0u8; size];

        let mut group = c.benchmark_group("rc4");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("kittycrypto_rc4_{size}",), |b| {
            let mut cipher = kittycrypto::rc4::Cipher::new(&KEY).unwrap();
            let mut dst = data.clone();
            b.iter(|| {
                let _ = cipher.xor_key_stream(black_box(&mut dst), black_box(&data));
            })
        });

        group.bench_function(format!("rustcrypto_rc4_{size}",), |b| {
            let mut cipher = rc4::Rc4::new(&KEY.into());
            b.iter(|| {
                let mut data = data.clone();
                rc4::StreamCipher::apply_keystream(&mut cipher, black_box(&mut data));
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_rc4);

criterion_main!(benches);
