use cipher::KeyIvInit;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittycrypto::cipher::ctr::CtrAble;
use std::hint::black_box;

fn bench_aes_ctr(c: &mut Criterion) {
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

        let mut group = c.benchmark_group("aes_ctr");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("kittycrypto_aes_ctr_{size}",), |b| {
            let mut cipher = kittycrypto::aes::AesCipher::new(&key)
                .unwrap()
                .to_ctr(&[0u8; 16])
                .unwrap();
            let mut dst = data.clone();
            b.iter(|| {
                let _ = cipher.xor_key_stream(black_box(&mut dst), black_box(&data));
            })
        });

        group.bench_function(format!("rustcrypto_aes_ctr_{size}",), |b| {
            type Aes256Ctr64Be = ctr::Ctr64BE<aes::Aes256>;
            let mut cipher = Aes256Ctr64Be::new_from_slices(&key, &[0u8; 16]).unwrap();
            b.iter(|| {
                let mut data = data.clone();
                cipher::StreamCipher::apply_keystream(&mut cipher, black_box(&mut data));
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_aes_ctr);

criterion_main!(benches);
