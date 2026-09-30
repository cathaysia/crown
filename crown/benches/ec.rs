use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use crown::bn::Bn;
use crown::ec::CurveId;

struct BenchRng;

impl crown::rsa::Rng for BenchRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        rand::fill(out);
    }
}

/// r||s big-endian, each padded to 32 bytes.
fn sig64(r: &Bn, s: &Bn) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, v) in [r, s].into_iter().enumerate() {
        let b = v.to_be_bytes();
        out[i * 32 + 32 - b.len()..(i + 1) * 32].copy_from_slice(&b);
    }
    out
}

/// Random scalar below 2^253 (fits the P-256/P-384 group order).
fn rand_scalar() -> Bn {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    b[0] &= 0x0f;
    b[31] |= 1;
    Bn::from_be_bytes(&b)
}

fn bench_p256_mul_base(c: &mut Criterion) {
    let curve = crown::ec::curve(CurveId::P256);
    let k = rand_scalar();

    let mut group = c.benchmark_group("p256");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_mul_base", |b| {
        b.iter(|| black_box(crown::ec::mul_base(black_box(&curve), black_box(&k))))
    });
    group.bench_function("rustcrypto_public_from_secret", |b| {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey;
        let secret = SecretKey::from_slice(&k.to_be_bytes()).unwrap();
        b.iter(|| black_box(secret.public_key().to_encoded_point(false)))
    });

    group.finish();
}

fn bench_p256_ecdh(c: &mut Criterion) {
    let curve = crown::ec::curve(CurveId::P256);
    let priv_key = rand_scalar();
    let peer = crown::ec::mul_base(&curve, &rand_scalar());
    let peer_sec1 = peer.to_bytes_with(&curve);

    let mut group = c.benchmark_group("p256");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_agree", |b| {
        b.iter(|| {
            black_box(crown::ecdh::agree(CurveId::P256, black_box(&priv_key), &peer).unwrap())
        })
    });
    group.bench_function("rustcrypto_diffie_hellman", |b| {
        use p256::ecdh::EphemeralSecret;
        use p256::elliptic_curve::rand_core::OsRng;
        use p256::PublicKey;
        let peer = PublicKey::from_sec1_bytes(&peer_sec1).unwrap();
        let secret = EphemeralSecret::random(&mut OsRng);
        b.iter(|| black_box(secret.diffie_hellman(&peer)))
    });

    group.finish();
}

fn bench_p256_ecdsa(c: &mut Criterion) {
    let msg: [u8; 32] = core::array::from_fn(|i| i as u8);
    let d = rand_scalar();
    let pub_point = crown::ec::mul_base(&crown::ec::curve(CurveId::P256), &d);
    let (r, s) = crown::ecdsa::sign_sha256(&d, &msg, &mut BenchRng).unwrap();
    let sig_bytes = sig64(&r, &s);

    let mut group = c.benchmark_group("p256");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crown_sign", |b| {
        b.iter(|| black_box(crown::ecdsa::sign_sha256(black_box(&d), &msg, &mut BenchRng).unwrap()))
    });
    group.bench_function("crown_verify", |b| {
        b.iter(|| {
            black_box(
                crown::ecdsa::verify_sha256(black_box(&pub_point), &msg, black_box(&r), &s)
                    .unwrap(),
            )
        })
    });
    group.bench_function("rustcrypto_sign", |b| {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&d.to_be_bytes()).unwrap();
        b.iter(|| {
            let sig: p256::ecdsa::Signature = sk.sign(black_box(&msg));
            black_box(sig)
        })
    });
    group.bench_function("rustcrypto_verify", |b| {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
        let sk = SigningKey::from_slice(&d.to_be_bytes()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        b.iter(|| black_box(vk.verify(black_box(&msg), &sig).is_ok()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_p256_mul_base,
    bench_p256_ecdh,
    bench_p256_ecdsa
);
criterion_main!(benches);
