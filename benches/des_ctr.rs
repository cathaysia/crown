use cipher::KeyIvInit;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittycrypto::{cipher::ctr::CtrAble, des::BLOCK_SIZE};
use std::hint::black_box;

fn bench_des_ctr(c: &mut Criterion) {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    let case = [128, 1024];

    for size in case {
        let mut buf = vec![0u8; size + 1];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        let src = vec![0u8; size];

        let mut group = c.benchmark_group("des_ctr");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("kittycrypto_des_ctr_{size}"), |b| {
            let mut cipher = kittycrypto::des::DesCipher::new(&key)
                .unwrap()
                .to_ctr(&[0u8; BLOCK_SIZE])
                .unwrap();
            let mut dst = src.clone();
            b.iter(|| {
                let _ = cipher.xor_key_stream(black_box(&mut dst), black_box(&src));
            })
        });

        group.bench_function(format!("rustcrypto_des_ctr_{size}",), |b| {
            type Des256ctr64be = ctr::Ctr64BE<des::Des>;
            let mut cipher = Des256ctr64be::new_from_slices(&key, &[0u8; BLOCK_SIZE]).unwrap();
            b.iter(|| {
                let mut data = src.clone();
                cipher::StreamCipher::apply_keystream(&mut cipher, black_box(&mut data));
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_des_ctr);

criterion_main!(benches);
