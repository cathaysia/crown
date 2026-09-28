//! SLH-DSA hypertree (FIPS 205 Section 7).
//!
//! A hypertree signature is `d` XMSS signatures, one per layer. Each layer's
//! XMSS key signs the layer below's root (the bottom layer signs the FORS
//! public key).

use super::adrs::Adrs;
use super::params::{Params, MAX_N};
use super::xmss;
use crate::utils::subtle::constant_time_eq;

/// FIPS 205 Algorithm 12 `ht_sign`.
///
/// Appends `d` XMSS signatures to `out` at `out_off`; returns the offset just
/// past them. The caller must size `out` for the full hypertree signature.
pub(crate) fn ht_sign(
    p: &Params,
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    tree_id: u64,
    leaf_id: u32,
    out: &mut [u8],
    out_off: usize,
) -> usize {
    let n = p.n;
    let d = p.d;
    let hm = p.hm;
    let mask: u64 = (1u64 << hm) - 1;
    let mut adrs = Adrs::new(!p.is_shake);
    let mut root = [0u8; MAX_N];
    let mut next_root = [0u8; MAX_N];
    root[..n].copy_from_slice(&msg[..n]);

    let mut off = out_off;
    let mut tree = tree_id;
    let mut leaf = leaf_id;
    for layer in 0..d {
        adrs.set_layer_address(layer);
        adrs.set_tree_address(tree);
        let start = off;
        off = xmss::xmss_sign(p, &root[..n], sk_seed, leaf, pk_seed, &mut adrs, out, off);
        if layer + 1 < d {
            // Recover the XMSS root just signed; it becomes the next message.
            xmss::xmss_pk_from_sig(
                p,
                leaf,
                &out[start..off],
                0,
                &root[..n],
                pk_seed,
                &mut adrs,
                &mut next_root[..n],
            );
            root[..n].copy_from_slice(&next_root[..n]);
            leaf = (tree & mask) as u32;
            tree >>= hm;
        }
    }
    off
}

/// FIPS 205 Algorithm 13 `ht_verify`.
///
/// Reads `d` XMSS signatures from `sig` starting at `sig_off`. Returns
/// `Some(offset)` just past them when the recomputed root equals `pk_root`,
/// or `None` on mismatch. `sig` must have the exact parameter-set length.
pub(crate) fn ht_verify(
    p: &Params,
    msg: &[u8],
    sig: &[u8],
    sig_off: usize,
    pk_seed: &[u8],
    tree_id: u64,
    leaf_id: u32,
    pk_root: &[u8],
) -> Option<usize> {
    let n = p.n;
    let d = p.d;
    let hm = p.hm;
    let mask: u64 = (1u64 << hm) - 1;
    let mut adrs = Adrs::new(!p.is_shake);
    let mut node = [0u8; MAX_N];
    let mut parent = [0u8; MAX_N];
    node[..n].copy_from_slice(&msg[..n]);

    let mut off = sig_off;
    let mut tree = tree_id;
    let mut leaf = leaf_id;
    for layer in 0..d {
        adrs.set_layer_address(layer);
        adrs.set_tree_address(tree);
        off = xmss::xmss_pk_from_sig(
            p,
            leaf,
            sig,
            off,
            &node[..n],
            pk_seed,
            &mut adrs,
            &mut parent[..n],
        );
        node[..n].copy_from_slice(&parent[..n]);
        leaf = (tree & mask) as u32;
        tree >>= hm;
    }

    if constant_time_eq(&node[..n], pk_root) {
        Some(off)
    } else {
        None
    }
}
