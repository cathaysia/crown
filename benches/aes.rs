use cipher::{generic_array::GenericArray, BlockEncrypt};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use kittycrypto::aes::BLOCK_SIZE;
use rc4::KeyInit;
use std::hint::black_box;

fn bench_aes(c: &mut Criterion) {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;

    let mut block = [0u8; 4];
    rand::fill(&mut block);

    let mut group = c.benchmark_group("aes");
    group.throughput(Throughput::Bytes(4));

    group.bench_function("kittycrypto_aes".to_string(), |b| {
        let cipher = kittycrypto::aes::new_cipher(&key).unwrap();
        b.iter(|| {
            let mut dst = block;
            for i in (0..block.len()).step_by(BLOCK_SIZE) {
                let end = (i + BLOCK_SIZE).min(block.len());
                if end - i == BLOCK_SIZE {
                    cipher.encrypt(black_box(&mut dst[i..end]), black_box(&block[i..end]));
                }
            }
        })
    });

    group.bench_function("rustcrypto_aes".to_string(), |b| {
        let cipher = aes::Aes256::new(&key.into());

        b.iter(|| {
            let mut dst = block;
            for chunk in dst.chunks_exact_mut(BLOCK_SIZE) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.encrypt_block(black_box(block));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_aes);

criterion_main!(benches);
