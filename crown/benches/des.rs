use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn bench_des(c: &mut Criterion) {
    let mut key = [0u8; 8];
    rand::fill(&mut key);
    let key = key;

    let mut block = [0u8; 4];
    rand::fill(&mut block);

    let mut iv = [0u8; 8];
    rand::fill(&mut iv);

    let cases = [128, 512, 1024];

    for i in cases {
        let mut block = vec![0u8; i];
        rand::fill(block.as_mut_slice());

        let mut group = c.benchmark_group(format!("des_cbc_{i}"));
        group.throughput(Throughput::Bytes(i as u64));

        group.bench_function("crown".to_string(), |b| {
            let mut cipher = crown::envelope::EvpBlockCipher::new_des_cbc(&key, &iv).unwrap();
            let mut block = block.to_vec();
            b.iter(|| {
                let _ = cipher.encrypt_alloc(&mut block);
            })
        });

        group.finish();
    }

    for i in cases {
        let mut block = vec![0u8; i];
        rand::fill(block.as_mut_slice());

        let mut group = c.benchmark_group(format!("des_ctr_{i}"));
        group.throughput(Throughput::Bytes(i as u64));

        group.bench_function("crown".to_string(), |b| {
            let mut cipher = crown::envelope::EvpStreamCipher::new_des_ctr(&key, &iv).unwrap();
            let block = block.as_mut_slice();
            b.iter(|| {
                let _ = cipher.encrypt(block);
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_des);

criterion_main!(benches);
