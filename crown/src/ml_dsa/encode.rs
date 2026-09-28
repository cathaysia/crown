//! Bit packing / unpacking for ML-DSA keys and signatures (FIPS 204 §7.2).

use super::ntt::mod_sub;
use super::params::{
    ETA_4, GAMMA1_19, GAMMA2_Q_MINUS1_DIV32, RHO_BYTES, TR_BYTES, K_BYTES,
};
use super::poly::Poly;

/// Pack 4-bit coefficients (0..15) — `w1` when γ2 = (q−1)/32 (FIPS 204 Alg 16).
pub(crate) fn encode_4_bits(p: &Poly, out: &mut Vec<u8>) {
    for c in p.coeff.chunks_exact(2) {
        out.push((c[0] | (c[1] << 4)) as u8);
    }
}

/// Pack 6-bit coefficients (0..43) — `w1` when γ2 = (q−1)/88 (FIPS 204 Alg 16).
pub(crate) fn encode_6_bits(p: &Poly, out: &mut Vec<u8>) {
    for c in p.coeff.chunks_exact(4) {
        out.push((c[0] | (c[1] << 6)) as u8);
        out.push(((c[1] >> 2) | (c[2] << 4)) as u8);
        out.push(((c[2] >> 4) | (c[3] << 2)) as u8);
    }
}

/// Pack 10-bit coefficients (0..1023) — `t1` (FIPS 204 Alg 16).
pub(crate) fn encode_10_bits(p: &Poly, out: &mut Vec<u8>) {
    for c in p.coeff.chunks_exact(4) {
        out.push(c[0] as u8);
        out.push(((c[0] >> 8) | (c[1] << 2)) as u8);
        out.push(((c[1] >> 6) | (c[2] << 4)) as u8);
        out.push(((c[2] >> 4) | (c[3] << 6)) as u8);
        out.push((c[3] >> 2) as u8);
    }
}

/// Unpack 10-bit coefficients.
pub(crate) fn decode_10_bits(input: &[u8]) -> Option<Poly> {
    if input.len() < 320 {
        return None;
    }
    let mut out = Poly::zero();
    const MASK: u32 = 0x3ff;
    for (i, chunk) in input.chunks_exact(5).take(64).enumerate() {
        let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let w = chunk[4] as u32;
        let base = i * 4;
        out.coeff[base] = v & MASK;
        out.coeff[base + 1] = (v >> 10) & MASK;
        out.coeff[base + 2] = (v >> 20) & MASK;
        out.coeff[base + 3] = (v >> 30) | (w << 2);
    }
    Some(out)
}

/// Pack η = 4 coefficients in −4..4 (FIPS 204 Alg 17, a = b = 4).
pub(crate) fn encode_signed_4(p: &Poly, out: &mut Vec<u8>) {
    for c in p.coeff.chunks_exact(2) {
        let z0 = mod_sub(4, c[0]);
        let z1 = mod_sub(4, c[1]);
        out.push((z0 | (z1 << 4)) as u8);
    }
}

/// Unpack η = 4 coefficients; rejects out-of-range nibbles (≥ 9).
pub(crate) fn decode_signed_4(input: &[u8]) -> Option<Poly> {
    if input.len() < 128 {
        return None;
    }
    let mut out = Poly::zero();
    for i in 0..32 {
        let v = u32::from_le_bytes([
            input[i * 4],
            input[i * 4 + 1],
            input[i * 4 + 2],
            input[i * 4 + 3],
        ]);
        // Any nibble with its MSB set must have the other bits clear (nibble < 9).
        let msbs = v & 0x8888_8888;
        let mask = (msbs >> 1) | (msbs >> 2) | (msbs >> 3);
        if mask & v != 0 {
            return None;
        }
        let base = i * 8;
        for j in 0..8 {
            out.coeff[base + j] = mod_sub(4, (v >> (4 * j)) & 15);
        }
    }
    Some(out)
}

/// Pack η = 2 coefficients in −2..2 (FIPS 204 Alg 17, a = b = 2), 3 bits each.
pub(crate) fn encode_signed_2(p: &Poly, out: &mut Vec<u8>) {
    for c in p.coeff.chunks_exact(8) {
        let mut z = 0u32;
        for (j, &coeff) in c.iter().enumerate() {
            z |= mod_sub(2, coeff) << (3 * j);
        }
        out.push(z as u8);
        out.push((z >> 8) as u8);
        out.push((z >> 16) as u8);
    }
}

/// Unpack η = 2 coefficients; rejects octal values > 4.
pub(crate) fn decode_signed_2(input: &[u8]) -> Option<Poly> {
    if input.len() < 96 {
        return None;
    }
    let mut out = Poly::zero();
    for i in 0..32 {
        let v = u32::from_le_bytes([input[i * 3], input[i * 3 + 1], input[i * 3 + 2], 0]);
        // Octal MSB set ⇒ lower two bits must be clear (value ≤ 4).
        let msbs = v & 0o4444_4444;
        let mask = (msbs >> 1) | (msbs >> 2);
        if mask & v != 0 {
            return None;
        }
        let base = i * 8;
        for j in 0..8 {
            out.coeff[base + j] = mod_sub(2, (v >> (3 * j)) & 7);
        }
    }
    Some(out)
}

/// Pack 13-bit coefficients in −2^12+1..2^12 — `t0` (FIPS 204 Alg 17).
pub(crate) fn encode_signed_2_12(p: &Poly, out: &mut Vec<u8>) {
    const RANGE: u32 = 1 << 12;
    for c in p.coeff.chunks_exact(8) {
        let mut a1 = 0u64;
        a1 |= mod_sub(RANGE, c[0]) as u64;
        a1 |= (mod_sub(RANGE, c[1]) as u64) << 13;
        a1 |= (mod_sub(RANGE, c[2]) as u64) << 26;
        a1 |= (mod_sub(RANGE, c[3]) as u64) << 39;
        let a2_0 = mod_sub(RANGE, c[4]) as u64;
        a1 |= a2_0 << 52;
        let mut a2 = (a2_0 >> 12) | ((mod_sub(RANGE, c[5]) as u64) << 1);
        a2 |= (mod_sub(RANGE, c[6]) as u64) << 14;
        a2 |= (mod_sub(RANGE, c[7]) as u64) << 27;
        out.extend_from_slice(&a1.to_le_bytes());
        out.extend_from_slice(&(a2 as u32).to_le_bytes());
        out.push((a2 >> 32) as u8);
    }
}

/// Unpack 13-bit coefficients (`t0`).
pub(crate) fn decode_signed_2_12(input: &[u8]) -> Option<Poly> {
    if input.len() < 416 {
        return None;
    }
    let mut out = Poly::zero();
    const RANGE: u32 = 1 << 12;
    const MASK: u32 = (1 << 13) - 1;
    for i in 0..32 {
        let off = i * 13;
        let a1 = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        let a2 = u32::from_le_bytes(input[off + 8..off + 12].try_into().unwrap()) as u64;
        let b13 = input[off + 12] as u64;
        let base = i * 8;
        out.coeff[base] = mod_sub(RANGE, (a1 as u32) & MASK);
        out.coeff[base + 1] = mod_sub(RANGE, ((a1 >> 13) as u32) & MASK);
        out.coeff[base + 2] = mod_sub(RANGE, ((a1 >> 26) as u32) & MASK);
        out.coeff[base + 3] = mod_sub(RANGE, ((a1 >> 39) as u32) & MASK);
        out.coeff[base + 4] = mod_sub(RANGE, ((a1 >> 52) as u32) | (((a2 as u32) << 12) & MASK));
        out.coeff[base + 5] = mod_sub(RANGE, ((a2 >> 1) as u32) & MASK);
        out.coeff[base + 6] = mod_sub(RANGE, ((a2 >> 14) as u32) & MASK);
        out.coeff[base + 7] = mod_sub(RANGE, ((a2 >> 27) as u32) | ((b13 as u32) << 5));
    }
    Some(out)
}

/// Pack 20-bit coefficients in −2^19+1..2^19 — `z` for γ1 = 2^19.
pub(crate) fn encode_signed_2_19(p: &Poly, out: &mut Vec<u8>) {
    const RANGE: u32 = 1 << 19;
    for c in p.coeff.chunks_exact(4) {
        let mut z0 = mod_sub(RANGE, c[0]);
        let z1_0 = mod_sub(RANGE, c[1]);
        z0 |= z1_0 << 20;
        let mut z1 = (z1_0 >> 12) | (mod_sub(RANGE, c[2]) << 8);
        let z2 = mod_sub(RANGE, c[3]);
        z1 |= z2 << 28;
        out.extend_from_slice(&z0.to_le_bytes());
        out.extend_from_slice(&z1.to_le_bytes());
        out.extend_from_slice(&((z2 >> 4) as u16).to_le_bytes());
    }
}

/// Unpack 20-bit coefficients (`z` for γ1 = 2^19).
pub(crate) fn decode_signed_2_19(input: &[u8]) -> Option<Poly> {
    if input.len() < 640 {
        return None;
    }
    let mut out = Poly::zero();
    const RANGE: u32 = 1 << 19;
    const MASK: u32 = (1 << 20) - 1;
    for i in 0..64 {
        let off = i * 10;
        let a1 = u32::from_le_bytes(input[off..off + 4].try_into().unwrap());
        let a2 = u32::from_le_bytes(input[off + 4..off + 8].try_into().unwrap());
        let a3 = u16::from_le_bytes(input[off + 8..off + 10].try_into().unwrap()) as u32;
        let base = i * 4;
        out.coeff[base] = mod_sub(RANGE, a1 & MASK);
        out.coeff[base + 1] = mod_sub(RANGE, (a1 >> 20) | ((a2 & 0xff) << 12));
        out.coeff[base + 2] = mod_sub(RANGE, (a2 >> 8) & MASK);
        out.coeff[base + 3] = mod_sub(RANGE, (a2 >> 28) | (a3 << 4));
    }
    Some(out)
}

/// Pack 18-bit coefficients in −2^17+1..2^17 — `z` for γ1 = 2^17.
pub(crate) fn encode_signed_2_17(p: &Poly, out: &mut Vec<u8>) {
    const RANGE: u32 = 1 << 17;
    for c in p.coeff.chunks_exact(4) {
        let mut z0 = mod_sub(RANGE, c[0]);
        let z1_0 = mod_sub(RANGE, c[1]);
        z0 |= z1_0 << 18;
        let mut z1 = (z1_0 >> 14) | (mod_sub(RANGE, c[2]) << 4);
        let z2 = mod_sub(RANGE, c[3]);
        z1 |= z2 << 22;
        out.extend_from_slice(&z0.to_le_bytes());
        out.extend_from_slice(&z1.to_le_bytes());
        out.push((z2 >> 10) as u8);
    }
}

/// Unpack 18-bit coefficients (`z` for γ1 = 2^17).
pub(crate) fn decode_signed_2_17(input: &[u8]) -> Option<Poly> {
    if input.len() < 576 {
        return None;
    }
    let mut out = Poly::zero();
    const RANGE: u32 = 1 << 17;
    const MASK: u32 = (1 << 18) - 1;
    for i in 0..64 {
        let off = i * 9;
        let a1 = u32::from_le_bytes(input[off..off + 4].try_into().unwrap());
        let a2 = u32::from_le_bytes(input[off + 4..off + 8].try_into().unwrap());
        let a3 = input[off + 8] as u32;
        let base = i * 4;
        out.coeff[base] = mod_sub(RANGE, a1 & MASK);
        out.coeff[base + 1] = mod_sub(RANGE, (a1 >> 18) | ((a2 & 0xf) << 14));
        out.coeff[base + 2] = mod_sub(RANGE, (a2 >> 4) & MASK);
        out.coeff[base + 3] = mod_sub(RANGE, (a2 >> 22) | (a3 << 10));
    }
    Some(out)
}

/// FIPS 204 Algorithm 28 `w1Encode`.
pub(crate) fn w1_encode(w1: &[Poly], gamma2: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(w1.len() * if gamma2 == GAMMA2_Q_MINUS1_DIV32 { 128 } else { 192 });
    for p in w1 {
        if gamma2 == GAMMA2_Q_MINUS1_DIV32 {
            encode_4_bits(p, &mut out);
        } else {
            encode_6_bits(p, &mut out);
        }
    }
    out
}

/// FIPS 204 Algorithm 22 `pkEncode`.
pub(crate) fn pk_encode(rho: &[u8; RHO_BYTES], t1: &[Poly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RHO_BYTES + t1.len() * 320);
    out.extend_from_slice(rho);
    for p in t1 {
        encode_10_bits(p, &mut out);
    }
    out
}

/// FIPS 204 Algorithm 23 `pkDecode`.
pub(crate) fn pk_decode(bytes: &[u8], k: usize) -> Option<([u8; RHO_BYTES], Vec<Poly>)> {
    if bytes.len() != RHO_BYTES + k * 320 {
        return None;
    }
    let mut rho = [0u8; RHO_BYTES];
    rho.copy_from_slice(&bytes[..RHO_BYTES]);
    let mut t1 = Vec::with_capacity(k);
    for i in 0..k {
        t1.push(decode_10_bits(&bytes[RHO_BYTES + i * 320..])?);
    }
    Some((rho, t1))
}

/// FIPS 204 Algorithm 24 `skEncode`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sk_encode(
    rho: &[u8; RHO_BYTES],
    k_seed: &[u8; K_BYTES],
    tr: &[u8; TR_BYTES],
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
    eta: u32,
) -> Vec<u8> {
    let s_bytes = if eta == ETA_4 { 128 } else { 96 };
    let mut out =
        Vec::with_capacity(RHO_BYTES + K_BYTES + TR_BYTES + (s1.len() + s2.len()) * s_bytes + t0.len() * 416);
    out.extend_from_slice(rho);
    out.extend_from_slice(k_seed);
    out.extend_from_slice(tr);
    let encode_s = if eta == ETA_4 {
        encode_signed_4 as fn(&Poly, &mut Vec<u8>)
    } else {
        encode_signed_2
    };
    for p in s1 {
        encode_s(p, &mut out);
    }
    for p in s2 {
        encode_s(p, &mut out);
    }
    for p in t0 {
        encode_signed_2_12(p, &mut out);
    }
    out
}

/// FIPS 204 Algorithm 25 `skDecode`.
#[allow(clippy::type_complexity)]
pub(crate) fn sk_decode(
    bytes: &[u8],
    eta: u32,
    l: usize,
    k: usize,
) -> Option<(
    [u8; RHO_BYTES],
    [u8; K_BYTES],
    [u8; TR_BYTES],
    Vec<Poly>,
    Vec<Poly>,
    Vec<Poly>,
)> {
    let s_bytes = if eta == ETA_4 { 128 } else { 96 };
    let expected = RHO_BYTES + K_BYTES + TR_BYTES + (l + k) * s_bytes + k * 416;
    if bytes.len() != expected {
        return None;
    }
    let mut rho = [0u8; RHO_BYTES];
    rho.copy_from_slice(&bytes[..RHO_BYTES]);
    let mut k_seed = [0u8; K_BYTES];
    k_seed.copy_from_slice(&bytes[RHO_BYTES..RHO_BYTES + K_BYTES]);
    let mut tr = [0u8; TR_BYTES];
    tr.copy_from_slice(&bytes[RHO_BYTES + K_BYTES..RHO_BYTES + K_BYTES + TR_BYTES]);

    let decode_s = if eta == ETA_4 {
        decode_signed_4 as fn(&[u8]) -> Option<Poly>
    } else {
        decode_signed_2
    };
    let mut off = RHO_BYTES + K_BYTES + TR_BYTES;
    let mut s1 = Vec::with_capacity(l);
    for _ in 0..l {
        s1.push(decode_s(&bytes[off..off + s_bytes])?);
        off += s_bytes;
    }
    let mut s2 = Vec::with_capacity(k);
    for _ in 0..k {
        s2.push(decode_s(&bytes[off..off + s_bytes])?);
        off += s_bytes;
    }
    let mut t0 = Vec::with_capacity(k);
    for _ in 0..k {
        t0.push(decode_signed_2_12(&bytes[off..off + 416])?);
        off += 416;
    }
    Some((rho, k_seed, tr, s1, s2, t0))
}

/// FIPS 204 Algorithm 20 `HintBitPack`.
pub(crate) fn hint_encode(hint: &[Poly], omega: u32) -> Vec<u8> {
    let k = hint.len();
    let mut data = vec![0u8; omega as usize + k];
    let mut coeff_index = 0usize;
    for (i, p) in hint.iter().enumerate() {
        for (j, &c) in p.coeff.iter().enumerate() {
            if c != 0 {
                data[coeff_index] = j as u8;
                coeff_index += 1;
            }
        }
        data[omega as usize + i] = coeff_index as u8;
    }
    data
}

/// FIPS 204 Algorithm 21 `HintBitUnpack`. Rejects malformed encodings.
pub(crate) fn hint_decode(data: &[u8], omega: u32, k: usize) -> Option<Vec<Poly>> {
    let omega = omega as usize;
    if data.len() < omega + k {
        return None;
    }
    let (indices, limits) = data.split_at(omega);
    let mut hint: Vec<Poly> = (0..k).map(|_| Poly::zero()).collect();
    let mut coeff_index = 0usize;
    for i in 0..k {
        let limit = limits[i] as usize;
        if limit < coeff_index || limit > omega {
            return None;
        }
        let mut last: i32 = -1;
        while coeff_index < limit {
            let byte = indices[coeff_index] as i32;
            coeff_index += 1;
            if last >= 0 && byte <= last {
                return None;
            }
            last = byte;
            hint[i].coeff[byte as usize] = 1;
        }
    }
    // Trailing index bytes must be zero.
    if indices[coeff_index..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(hint)
}

/// FIPS 204 Algorithm 26 `sigEncode`.
pub(crate) fn sig_encode(
    c_tilde: &[u8],
    z: &[Poly],
    hint: &[Poly],
    gamma1: u32,
    omega: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(c_tilde);
    for p in z {
        if gamma1 == GAMMA1_19 {
            encode_signed_2_19(p, &mut out);
        } else {
            encode_signed_2_17(p, &mut out);
        }
    }
    out.extend_from_slice(&hint_encode(hint, omega));
    out
}

/// FIPS 204 Algorithm 27 `sigDecode`. Returns `(c_tilde, z, hint)`.
pub(crate) fn sig_decode(
    bytes: &[u8],
    gamma1: u32,
    omega: u32,
    k: usize,
    l: usize,
    c_tilde_len: usize,
) -> Option<(Vec<u8>, Vec<Poly>, Vec<Poly>)> {
    let z_bytes = if gamma1 == GAMMA1_19 { 640 } else { 576 };
    let expected = c_tilde_len + l * z_bytes + omega as usize + k;
    if bytes.len() != expected {
        return None;
    }
    let mut c_tilde = vec![0u8; c_tilde_len];
    c_tilde.copy_from_slice(&bytes[..c_tilde_len]);
    let mut off = c_tilde_len;
    let mut z = Vec::with_capacity(l);
    for _ in 0..l {
        let p = if gamma1 == GAMMA1_19 {
            decode_signed_2_19(&bytes[off..off + z_bytes])?
        } else {
            decode_signed_2_17(&bytes[off..off + z_bytes])?
        };
        z.push(p);
        off += z_bytes;
    }
    let hint = hint_decode(&bytes[off..], omega, k)?;
    Some((c_tilde, z, hint))
}
