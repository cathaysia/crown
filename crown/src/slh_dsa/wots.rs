//! WOTS+ one-time signatures (FIPS 205 Section 5).
//!
//! With `w = 16` (`lg_w = 4`) an `n`-byte message expands to `2n` base-16
//! digits followed by a 12-bit checksum in 3 more digits, so a WOTS+
//! signature holds `len = 2n + 3` chain outputs of `n` bytes each.

use super::adrs::{Adrs, TYPE_WOTS_PK, TYPE_WOTS_PRF};
use super::hash;
use super::params::{Params, MAX_N, WOTS_W};

/// Split an `n`-byte message into `2n` base-w digits and append the 3-digit
/// checksum (FIPS 205 Algorithm 7, steps 3–6).
///
/// `out` must hold `2n + 3` digits.
fn msg_and_checksum_digits(p: &Params, msg: &[u8], out: &mut [u8]) {
    let n = p.n;
    let len1 = 2 * n;
    let mut csum: u32 = 0;
    for (i, &b) in msg[..n].iter().enumerate() {
        out[2 * i] = b >> 4;
        out[2 * i + 1] = b & 0x0f;
        csum += (b >> 4) as u32 + (b & 0x0f) as u32;
    }
    csum = (WOTS_W as u32 - 1) * len1 as u32 - csum;
    out[len1] = ((csum >> 8) & 0x0f) as u8;
    out[len1 + 1] = ((csum >> 4) & 0x0f) as u8;
    out[len1 + 2] = (csum & 0x0f) as u8;
}

/// FIPS 205 Algorithm 5 `chain(X, i, s, PK.seed, ADRS)`.
///
/// Writes `n` bytes to `out`.
fn chain(
    p: &Params,
    x: &[u8],
    start: u32,
    steps: u8,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n;
    let mut buf_a = [0u8; MAX_N];
    let mut buf_b = [0u8; MAX_N];
    buf_a[..n].copy_from_slice(&x[..n]);
    let (mut cur, mut next) = (&mut buf_a[..], &mut buf_b[..]);
    for j in 0..steps {
        adrs.set_hash_address(start + j as u32);
        hash::f(p, pk_seed, adrs, &cur[..n], &mut next[..n]);
        core::mem::swap(&mut cur, &mut next);
    }
    out[..n].copy_from_slice(&cur[..n]);
}

/// Build the WOTS_PRF address used to derive chain secret `i`.
///
/// This mirrors OpenSSL's `sk_adrs`: a copy of the WOTS_HASH address with the
/// type switched to WOTS_PRF and the chain address set to `i`. The caller's
/// address keeps its type WOTS_HASH for the chain steps.
fn sk_adrs(base: &Adrs, i: u32) -> Adrs {
    let mut a = *base;
    a.set_type_and_clear(TYPE_WOTS_PRF);
    a.copy_keypair_address(base);
    a.set_chain_address(i);
    a
}

/// Stack buffers sized for the largest parameter set (`len = 2*32+3 = 67`
/// chains of 32 bytes).
type TmpChains = [u8; (2 * MAX_N + 3) * MAX_N];
type Digits = [u8; 2 * MAX_N + 3];

/// FIPS 205 Algorithm 6 `wots_pkGen`.
pub(crate) fn wots_pk_gen(
    p: &Params,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    pk_out: &mut [u8],
) {
    let n = p.n;
    let len = p.wots_len();
    let mut tmp: TmpChains = [0u8; (2 * MAX_N + 3) * MAX_N];
    let mut sk = [0u8; MAX_N];
    let mut wots_pk_adrs = *adrs;

    for i in 0..len {
        let s_adrs = sk_adrs(adrs, i as u32);
        hash::prf(p, pk_seed, &s_adrs, sk_seed, &mut sk[..n]);
        adrs.set_chain_address(i as u32);
        chain(
            p,
            &sk[..n],
            0,
            WOTS_W - 1,
            pk_seed,
            adrs,
            &mut tmp[(i * n)..(i + 1) * n],
        );
    }

    wots_pk_adrs.set_type_and_clear(TYPE_WOTS_PK);
    wots_pk_adrs.copy_keypair_address(adrs);
    hash::t_l(p, pk_seed, &wots_pk_adrs, &tmp[..len * n], pk_out);
}

/// FIPS 205 Algorithm 7 `wots_sign`.
///
/// Appends `len` chain outputs of `n` bytes to `out` at `out_off`; returns the
/// offset just past the signature.
pub(crate) fn wots_sign(
    p: &Params,
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    out: &mut [u8],
    out_off: usize,
) -> usize {
    let n = p.n;
    let len = p.wots_len();
    let mut digits: Digits = [0u8; 2 * MAX_N + 3];
    let mut sk = [0u8; MAX_N];
    msg_and_checksum_digits(p, msg, &mut digits[..len]);

    let mut off = out_off;
    for i in 0..len {
        let s_adrs = sk_adrs(adrs, i as u32);
        hash::prf(p, pk_seed, &s_adrs, sk_seed, &mut sk[..n]);
        adrs.set_chain_address(i as u32);
        chain(
            p,
            &sk[..n],
            0,
            digits[i],
            pk_seed,
            adrs,
            &mut out[off..off + n],
        );
        off += n;
    }
    off
}

/// FIPS 205 Algorithm 8 `wots_pkFromSig`.
///
/// Reads `len * n` signature bytes from `sig` at `sig_off`; returns the offset
/// just past them and writes the candidate key to `pk_out`.
pub(crate) fn wots_pk_from_sig(
    p: &Params,
    sig: &[u8],
    sig_off: usize,
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    pk_out: &mut [u8],
) -> usize {
    let n = p.n;
    let len = p.wots_len();
    let mut digits: Digits = [0u8; 2 * MAX_N + 3];
    msg_and_checksum_digits(p, msg, &mut digits[..len]);
    let mut tmp: TmpChains = [0u8; (2 * MAX_N + 3) * MAX_N];
    let mut wots_pk_adrs = *adrs;

    let mut off = sig_off;
    for i in 0..len {
        adrs.set_chain_address(i as u32);
        let digit = digits[i];
        chain(
            p,
            &sig[off..off + n],
            digit as u32,
            WOTS_W - 1 - digit,
            pk_seed,
            adrs,
            &mut tmp[(i * n)..(i + 1) * n],
        );
        off += n;
    }

    wots_pk_adrs.set_type_and_clear(TYPE_WOTS_PK);
    wots_pk_adrs.copy_keypair_address(adrs);
    hash::t_l(p, pk_seed, &wots_pk_adrs, &tmp[..len * n], pk_out);
    off
}

/// Re-exported for tests: message + checksum digit expansion.
#[cfg(test)]
pub(crate) fn digits_for_test(p: &Params, msg: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; 2 * p.n + 3];
    msg_and_checksum_digits(p, msg, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::SlhDsaVariant;

    #[test]
    fn checksum_digits() {
        let p = SlhDsaVariant::Sha2_128s.params();
        let msg = [0xffu8; 16];
        let d = digits_for_test(p, &msg);
        assert_eq!(d.len(), 35);
        assert!(d[..32].iter().all(|&x| x == 0x0f));
        // csum = 15*32 - 15*32 = 0
        assert_eq!(&d[32..35], &[0, 0, 0]);

        let msg2 = [0x00u8; 16];
        let d2 = digits_for_test(p, &msg2);
        // csum = 15*32 = 480 = 0x1E0 -> digits 1, 14, 0
        assert_eq!(&d2[32..35], &[1, 14, 0]);
    }

    #[test]
    fn mixed_digits() {
        let p = SlhDsaVariant::Sha2_128s.params();
        let msg = [0x12u8; 16];
        let d = digits_for_test(p, &msg);
        assert_eq!(&d[..4], &[1, 2, 1, 2]);
        // sum digits = 16*3 = 48; csum = 480 - 48 = 432 = 0x1B0 -> 1, 11, 0
        assert_eq!(&d[32..35], &[1, 11, 0]);
    }
}
