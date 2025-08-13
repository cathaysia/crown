use cipher::KeyInit;
use cipher::{generic_array::GenericArray, BlockEncrypt};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittycrypto::cipher::BlockCipher;
use kittycrypto::des::Des;
use std::hint::black_box;

fn bench_des(c: &mut Criterion) {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    let mut block = [0u8; 4];
    rand::fill(&mut block);

    let mut group = c.benchmark_group("des");
    group.throughput(Throughput::Bytes(4));

    group.bench_function("kittycrypto_des".to_string(), |b| {
        let cipher = kittycrypto::des::Des::new(&key).unwrap();
        b.iter(|| {
            let mut dst = block;
            for i in (0..block.len()).step_by(Des::BLOCK_SIZE) {
                let end = (i + Des::BLOCK_SIZE).min(block.len());
                if end - i == Des::BLOCK_SIZE {
                    cipher.encrypt(black_box(&mut dst[i..end]));
                }
            }
        })
    });

    group.bench_function("rustcrypto_des".to_string(), |b| {
        let cipher = des::Des::new(&key.into());

        b.iter(|| {
            let mut dst = block;
            for chunk in dst.chunks_exact_mut(Des::BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.encrypt_block(black_box(block));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_des);

criterion_main!(benches);
