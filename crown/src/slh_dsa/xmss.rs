//! XMSS few-time signature scheme (FIPS 205 Section 6).
//!
//! An XMSS signature is one WOTS+ signature followed by an authentication
//! path of `h'` nodes of `n` bytes each.

use super::adrs::{Adrs, TYPE_TREE, TYPE_WOTS_HASH};
use super::hash;
use super::params::Params;
use super::wots;

/// FIPS 205 Algorithm 9 `xmss_node`.
///
/// Computes the node at `(node_id, height)` of the XMSS tree whose layer and
/// tree addresses are already set on `adrs`.
pub(crate) fn xmss_node(
    p: &Params,
    sk_seed: &[u8],
    node_id: u32,
    height: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    out: &mut [u8],
) {
    if height == 0 {
        adrs.set_type_and_clear(TYPE_WOTS_HASH);
        adrs.set_keypair_address(node_id);
        wots::wots_pk_gen(p, sk_seed, pk_seed, adrs, out);
    } else {
        let mut lnode = [0u8; super::params::MAX_N];
        let mut rnode = [0u8; super::params::MAX_N];
        xmss_node(p, sk_seed, 2 * node_id, height - 1, pk_seed, adrs, &mut lnode);
        xmss_node(p, sk_seed, 2 * node_id + 1, height - 1, pk_seed, adrs, &mut rnode);
        adrs.set_type_and_clear(TYPE_TREE);
        adrs.set_tree_height(height);
        adrs.set_tree_index(node_id);
        hash::h(p, pk_seed, adrs, &lnode, &rnode, out);
    }
}

/// FIPS 205 Algorithm 10 `xmss_sign`.
///
/// Appends the WOTS+ signature and the `h'`-node authentication path to `out`
/// at `out_off`; returns the offset just past them.
pub(crate) fn xmss_sign(
    p: &Params,
    msg: &[u8],
    sk_seed: &[u8],
    node_id: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    out: &mut [u8],
    out_off: usize,
) -> usize {
    let n = p.n;
    let hm = p.hm;

    adrs.set_type_and_clear(TYPE_WOTS_HASH);
    adrs.set_keypair_address(node_id);
    let mut off = wots::wots_sign(p, msg, sk_seed, pk_seed, adrs, out, out_off);

    let mut id = node_id;
    for h in 0..hm {
        let mut node = [0u8; super::params::MAX_N];
        xmss_node(p, sk_seed, id ^ 1, h, pk_seed, adrs, &mut node);
        out[off..off + n].copy_from_slice(&node[..n]);
        off += n;
        id >>= 1;
    }
    off
}

/// FIPS 205 Algorithm 11 `xmss_pkFromSig`.
///
/// Reads one XMSS signature from `sig` at `sig_off`; returns the offset just
/// past it and writes the candidate node to `pk_out`.
pub(crate) fn xmss_pk_from_sig(
    p: &Params,
    node_id: u32,
    sig: &[u8],
    sig_off: usize,
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    pk_out: &mut [u8],
) -> usize {
    let n = p.n;
    let hm = p.hm;

    adrs.set_type_and_clear(TYPE_WOTS_HASH);
    adrs.set_keypair_address(node_id);
    let mut off = wots::wots_pk_from_sig(p, sig, sig_off, msg, pk_seed, adrs, pk_out);

    adrs.set_type_and_clear(TYPE_TREE);
    let mut id = node_id;
    let mut node = [0u8; super::params::MAX_N];
    let mut parent = [0u8; super::params::MAX_N];
    node[..n].copy_from_slice(&pk_out[..n]);
    for k in 0..hm {
        let auth = &sig[off..off + n];
        adrs.set_tree_height(k + 1);
        if id & 1 == 0 {
            id >>= 1;
            adrs.set_tree_index(id);
            hash::h(p, pk_seed, adrs, &node[..n], auth, &mut parent[..n]);
        } else {
            id = (id - 1) >> 1;
            adrs.set_tree_index(id);
            hash::h(p, pk_seed, adrs, auth, &node[..n], &mut parent[..n]);
        }
        node[..n].copy_from_slice(&parent[..n]);
        off += n;
    }
    pk_out[..n].copy_from_slice(&node[..n]);
    off
}
