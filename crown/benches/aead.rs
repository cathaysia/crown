use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::aead::ccm::Ccm;
use crown::aead::eax::Eax;
use crown::aead::gcm::Gcm;
use crown::aead::ocb3::Ocb3;
use crown::aead::Aead;
use crown::block::aes::Aes;

fn bench_gcm(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];

    for size in [16, 64, 256, 1024, 8192, 65536] {
        let mut data = vec![0u8; size];
        rand::fill(data.as_mut_slice());
        let mut group = c.benchmark_group("aes256_gcm");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_seal_{size}"), |b| {
            let gcm = Aes::new(&key).unwrap().to_gcm().unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = gcm
                    .seal_in_place_separate_tag(&mut buf, &nonce, &[])
                    .unwrap();
                black_box(tag);
            })
        });
        group.bench_function(format!("rustcrypto_seal_{size}"), |b| {
            use aes_gcm::aead::AeadMutInPlace;
            use cipher::KeyInit;
            let mut gcm = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                gcm.encrypt_in_place(nonce.as_slice().into(), &[], &mut buf)
                    .unwrap();
                black_box(&buf);
            })
        });
        group.bench_function(format!("ring_seal_{size}"), |b| {
            let gcm = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key).unwrap(),
            );
            let mut buf = data.clone();
            b.iter(|| {
                let tag = gcm
                    .seal_in_place_separate_tag(
                        ring::aead::Nonce::assume_unique_for_key(nonce),
                        ring::aead::Aad::empty(),
                        &mut buf,
                    )
                    .unwrap();
                black_box(tag.as_ref());
            })
        });

        group.finish();
    }
}

fn bench_poly1305(c: &mut Criterion) {
    let key = [0x42u8; 32];

    for size in [64, 1024, 16384] {
        let data = vec![0u8; size];
        let mut group = c.benchmark_group("poly1305");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("crown_{size}"), |b| {
            b.iter(|| black_box(crown::mac::poly1305::sum(black_box(&data), &key)))
        });
        group.bench_function(format!("rustcrypto_{size}"), |b| {
            use poly1305::universal_hash::{KeyInit, UniversalHash};
            #[allow(deprecated)]
            let key = poly1305::Key::from_slice(&key);
            b.iter(|| {
                let mut mac = poly1305::Poly1305::new(key);
                mac.update_padded(black_box(&data));
                black_box(mac.finalize())
            })
        });

        group.finish();
    }
}

/// The AEAD constructions added on top of plain GCM, compared against their
/// RustCrypto counterparts. CCM is limited to 128-byte payloads (12-byte
/// nonce => 3-byte length field).
fn bench_aead_variants(c: &mut Criterion) {
    let key128 = [0x42u8; 16];
    let key256 = [0x42u8; 32];
    let nonce12 = [0x24u8; 12];
    let nonce16 = [0x24u8; 16];
    let size = 1024;

    // --- AES-GCM-SIV ------------------------------------------------------
    {
        let mut group = c.benchmark_group("aes128_gcm_siv");
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];
        group.bench_function("crown_seal_1024", |b| {
            let aead = crown::aead::gcm_siv::AesGcmSiv::new(&key128).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .seal_in_place_separate_tag(&mut buf, &nonce12, &[])
                    .unwrap();
                black_box(tag)
            })
        });
        group.bench_function("rustcrypto_seal_1024", |b| {
            use aes_gcm_siv::aead::{AeadInPlace, KeyInit};
            let aead = aes_gcm_siv::Aes128GcmSiv::new_from_slice(&key128).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .encrypt_in_place_detached(nonce12.as_slice().into(), &[], &mut buf)
                    .unwrap();
                black_box(tag)
            })
        });
        group.finish();
    }

    // --- Ascon-AEAD128 ------------------------------------------------------
    {
        let mut group = c.benchmark_group("ascon_aead128");
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];
        group.bench_function("crown_seal_1024", |b| {
            let aead = crown::aead::ascon::AsconAead128::new(&key128);
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .seal_in_place_separate_tag(&mut buf, &nonce16, &[])
                    .unwrap();
                black_box(tag)
            })
        });
        group.bench_function("rustcrypto_seal_1024", |b| {
            use ascon_aead::aead::{AeadInPlace, KeyInit};
            let aead = ascon_aead::AsconAead128::new_from_slice(&key128).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .encrypt_in_place_detached(nonce16.as_slice().into(), &[], &mut buf)
                    .unwrap();
                black_box(tag)
            })
        });
        group.finish();
    }

    // --- AES-SIV (CMAC + CTR) ----------------------------------------------
    {
        let mut group = c.benchmark_group("aes128_siv");
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];
        group.bench_function("crown_seal_1024", |b| {
            let mut siv = crown::aead::siv::AesSiv::new(&key256).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = siv.seal_in_place(&mut buf, &[]).unwrap();
                black_box(tag)
            })
        });
        group.bench_function("rustcrypto_seal_1024", |b| {
            use aes_siv::siv::Aes128Siv;
            use aes_siv::KeyInit as _;
            let mut siv = Aes128Siv::new_from_slice(&key256).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = siv
                    .encrypt_in_place_detached([&[] as &[u8]], &mut buf)
                    .unwrap();
                black_box(tag)
            })
        });
        group.finish();
    }

    // --- AES-CCM (8-byte tag, 12-byte nonce, <=255-byte payload) -----------
    {
        let ccm_size = 128;
        let mut group = c.benchmark_group("aes128_ccm");
        group.throughput(Throughput::Bytes(ccm_size as u64));
        let data = vec![0u8; ccm_size];
        group.bench_function("crown_seal_128", |b| {
            let aead = Aes::new(&key128).unwrap().to_ccm::<8, 12>().unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .seal_in_place_separate_tag(&mut buf, &nonce12, &[])
                    .unwrap();
                black_box(tag)
            })
        });
        group.bench_function("rustcrypto_seal_128", |b| {
            use ccm::aead::{AeadInPlace, KeyInit};
            use ccm::consts::{U12, U8};
            let aead = ccm::Ccm::<aes::Aes128, U8, U12>::new_from_slice(&key128).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .encrypt_in_place_detached(nonce12.as_slice().into(), &[], &mut buf)
                    .unwrap();
                black_box(tag)
            })
        });
        group.finish();
    }

    // --- EAX ----------------------------------------------------------------
    {
        let mut group = c.benchmark_group("aes128_eax");
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];
        group.bench_function("crown_seal_1024", |b| {
            let aead = Aes::new(&key128).unwrap().to_eax::<16>(12).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .seal_in_place_separate_tag(&mut buf, &nonce12, &[])
                    .unwrap();
                black_box(tag)
            })
        });
        group.bench_function("rustcrypto_seal_1024", |b| {
            use eax::aead::{AeadInPlace, KeyInit};
            let aead = eax::Eax::<aes::Aes128>::new_from_slice(&key128).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .encrypt_in_place_detached(nonce16.as_slice().into(), &[], &mut buf)
                    .unwrap();
                black_box(tag)
            })
        });
        group.finish();
    }

    // --- OCB3 ----------------------------------------------------------------
    {
        let mut group = c.benchmark_group("aes128_ocb3");
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];
        group.bench_function("crown_seal_1024", |b| {
            let aead = Aes::new(&key128).unwrap().to_ocb3::<16, 12>().unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .seal_in_place_separate_tag(&mut buf, &nonce12, &[])
                    .unwrap();
                black_box(tag)
            })
        });
        group.bench_function("rustcrypto_seal_1024", |b| {
            use ocb3::aead::{AeadInPlace, KeyInit};
            use ocb3::consts::U12;
            let aead = ocb3::Ocb3::<aes::Aes128, U12>::new_from_slice(&key128).unwrap();
            let mut buf = data.clone();
            b.iter(|| {
                let tag = aead
                    .encrypt_in_place_detached(nonce12.as_slice().into(), &[], &mut buf)
                    .unwrap();
                black_box(tag)
            })
        });
        group.finish();
    }
}

criterion_group!(benches, bench_gcm, bench_poly1305, bench_aead_variants);
criterion_main!(benches);
