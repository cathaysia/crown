//! FORS few-time signature scheme (FIPS 205 Section 8).
//!
//! A FORS signature is `k` secret values plus `k` authentication paths of
//! `a` nodes each: `k * (1 + a) * n` bytes.

use super::adrs::{Adrs, TYPE_FORS_PRF, TYPE_FORS_ROOTS};
use super::hash;
use super::params::{Params, MAX_N};

/// FIPS 205 Algorithm 4 `base_2b`.
///
/// Splits `in` into `out_len` base-`2^b` digits.
fn base_2b(input: &[u8], b: u32, out: &mut [u32]) {
    let mut consumed = 0usize;
    let mut bits: u32 = 0;
    let mut total: u32 = 0;
    let mask = (1u32 << b) - 1;
    for slot in out.iter_mut() {
        while bits < b {
            total = (total << 8) + input[consumed] as u32;
            consumed += 1;
            bits += 8;
        }
        bits -= b;
        *slot = (total >> bits) & mask;
    }
}

/// FIPS 205 Algorithm 14 `fors_skGen`.
fn fors_sk_gen(
    p: &Params,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    id: u32,
    out: &mut [u8],
) {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(TYPE_FORS_PRF);
    sk_adrs.copy_keypair_address(adrs);
    sk_adrs.set_tree_index(id);
    hash::prf(p, pk_seed, &sk_adrs, sk_seed, out);
}

/// FIPS 205 Algorithm 18 `fors_node` — node at `(node_id, height)`.
fn fors_node(
    p: &Params,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    node_id: u32,
    height: u32,
    out: &mut [u8],
) {
    let n = p.n;
    if height == 0 {
        let mut sk = [0u8; MAX_N];
        fors_sk_gen(p, sk_seed, pk_seed, adrs, node_id, &mut sk[..n]);
        adrs.set_tree_height(0);
        adrs.set_tree_index(node_id);
        hash::f(p, pk_seed, adrs, &sk[..n], out);
    } else {
        let mut lnode = [0u8; MAX_N];
        let mut rnode = [0u8; MAX_N];
        fors_node(
            p,
            sk_seed,
            pk_seed,
            adrs,
            2 * node_id,
            height - 1,
            &mut lnode,
        );
        fors_node(
            p,
            sk_seed,
            pk_seed,
            adrs,
            2 * node_id + 1,
            height - 1,
            &mut rnode,
        );
        adrs.set_tree_height(height);
        adrs.set_tree_index(node_id);
        hash::h(p, pk_seed, adrs, &lnode, &rnode, out);
    }
}

/// FIPS 205 Algorithm 15 `fors_sign`.
///
/// Appends the FORS signature to `out` at `out_off`; returns the offset just
/// past it. `md` is `ceil(k*a/8)` bytes.
pub(crate) fn fors_sign(
    p: &Params,
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    out: &mut [u8],
    out_off: usize,
) -> usize {
    let n = p.n;
    let k = p.k as usize;
    let a = p.a;
    let mut ids = [0u32; super::params::MAX_K];
    base_2b(md, a, &mut ids[..k]);

    let mut off = out_off;
    let mut node = [0u8; MAX_N];
    for i in 0..k as u32 {
        // Secret of tree i at index i*2^a + ids[i].
        let mut id = ids[i as usize];
        let mut tree_offset = i << a;
        fors_sk_gen(
            p,
            sk_seed,
            pk_seed,
            adrs,
            id.wrapping_add(tree_offset),
            &mut node[..n],
        );
        out[off..off + n].copy_from_slice(&node[..n]);
        off += n;

        for layer in 0..a {
            let s = id ^ 1;
            fors_node(
                p,
                sk_seed,
                pk_seed,
                adrs,
                s.wrapping_add(tree_offset),
                layer,
                &mut node[..n],
            );
            out[off..off + n].copy_from_slice(&node[..n]);
            off += n;
            id >>= 1;
            tree_offset >>= 1;
        }
    }
    off
}

/// FIPS 205 Algorithm 16 `fors_pkFromSig`.
///
/// Reads a FORS signature from `sig` at `sig_off`; returns the offset just
/// past it and writes the candidate key to `pk_out`.
pub(crate) fn fors_pk_from_sig(
    p: &Params,
    sig: &[u8],
    sig_off: usize,
    md: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    pk_out: &mut [u8],
) -> usize {
    let n = p.n;
    let k = p.k as usize;
    let a = p.a;
    let mut ids = [0u32; super::params::MAX_K];
    base_2b(md, a, &mut ids[..k]);

    // k roots of n bytes each, then T_l with type FORS_ROOTS.
    let mut roots = [0u8; super::params::MAX_K * MAX_N];
    let mut node0 = [0u8; MAX_N];
    let mut node1 = [0u8; MAX_N];
    let mut off = sig_off;

    for i in 0..k {
        let mut id = ids[i];
        let mut node_id = id + ((i as u32) << a);
        adrs.set_tree_height(0);
        adrs.set_tree_index(node_id);
        hash::f(p, pk_seed, adrs, &sig[off..off + n], &mut node0[..n]);
        off += n;

        for j in 0..a {
            let auth = &sig[off..off + n];
            off += n;
            adrs.set_tree_height(j + 1);
            if id & 1 == 0 {
                node_id >>= 1;
                adrs.set_tree_index(node_id);
                hash::h(p, pk_seed, adrs, &node0[..n], auth, &mut node1[..n]);
            } else {
                node_id = (node_id - 1) >> 1;
                adrs.set_tree_index(node_id);
                hash::h(p, pk_seed, adrs, auth, &node0[..n], &mut node1[..n]);
            }
            node0[..n].copy_from_slice(&node1[..n]);
            id >>= 1;
        }
        roots[i * n..(i + 1) * n].copy_from_slice(&node0[..n]);
    }

    let mut roots_adrs = *adrs;
    roots_adrs.set_type_and_clear(TYPE_FORS_ROOTS);
    roots_adrs.copy_keypair_address(adrs);
    hash::t_l(p, pk_seed, &roots_adrs, &roots[..k * n], pk_out);
    off
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::SlhDsaVariant;

    #[test]
    fn base_2b_basic() {
        // b = 4: each byte is two digits, high nibble first.
        let mut out = [0u32; 4];
        base_2b(&[0xAB, 0xCD], 4, &mut out);
        assert_eq!(out, [0xA, 0xB, 0xC, 0xD]);

        // b = 12 (a = 12 for SHA2-128s): 12-bit digits.
        let mut out = [0u32; 2];
        base_2b(&[0x12, 0x34, 0x56], 12, &mut out);
        assert_eq!(out[0], 0x123);
        assert_eq!(out[1], 0x456);
    }

    #[test]
    fn base_2b_params() {
        let p = SlhDsaVariant::Sha2_128s.params();
        let md = [0xFFu8; 21]; // ceil(14*12/8) = 21
        let mut ids = [0u32; 14];
        base_2b(&md, p.a, &mut ids);
        assert!(ids.iter().all(|&x| x == 0xFFF));
    }
}
