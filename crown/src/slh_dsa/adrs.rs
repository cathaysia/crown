//! SLH-DSA address (ADRS) handling.
//!
//! FIPS 205 Section 4.2 describes the 32-byte uncompressed address used by the
//! SHAKE parameter sets; Section 11.2 Table 3 describes the 22-byte compressed
//! address used by the SHA2 parameter sets.  Both layouts are represented by
//! [`Adrs`] with a runtime `compressed` flag.

/// Uncompressed address size (SHAKE variants).
pub(crate) const ADRS_SIZE: usize = 32;
/// Compressed address size (SHA2 variants).
pub(crate) const ADRSC_SIZE: usize = 22;

// FIPS 205 Section 4.2 Table 1: uncompressed offsets.
const OFF_LAYER: usize = 0;
const OFF_TREE: usize = 4;
const OFF_TYPE: usize = 16;
const OFF_KEYPAIR: usize = 20;
const OFF_CHAIN: usize = 24;
const OFF_HASH: usize = 28;

// FIPS 205 Section 11.2 Table 3: compressed offsets.
const OFFC_LAYER: usize = 0;
const OFFC_TREE: usize = 1;
const OFFC_TYPE: usize = 9;
const OFFC_KEYPAIR: usize = 10;
const OFFC_CHAIN: usize = 14;
const OFFC_HASH: usize = 18;

/// Address types (FIPS 205 Table 1 / Section 4.3).
pub(crate) const TYPE_WOTS_HASH: u32 = 0;
pub(crate) const TYPE_WOTS_PK: u32 = 1;
pub(crate) const TYPE_TREE: u32 = 2;
pub(crate) const TYPE_FORS_TREE: u32 = 3;
pub(crate) const TYPE_FORS_ROOTS: u32 = 4;
pub(crate) const TYPE_WOTS_PRF: u32 = 5;
pub(crate) const TYPE_FORS_PRF: u32 = 6;

/// An SLH-DSA address object.
///
/// The tree address field is 12 bytes in the uncompressed layout, but all
/// FIPS 205 parameter sets use at most 64-bit tree indices, so only the low
/// 8 bytes are written and the high 4 bytes stay zero.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Adrs {
    buf: [u8; ADRS_SIZE],
    compressed: bool,
}

impl Adrs {
    /// New address object; `compressed` selects the 22-byte SHA2 layout.
    pub(crate) fn new(compressed: bool) -> Self {
        Self {
            buf: [0u8; ADRS_SIZE],
            compressed,
        }
    }

    fn layer_off(&self) -> usize {
        if self.compressed { OFFC_LAYER } else { OFF_LAYER }
    }
    fn type_off(&self) -> usize {
        if self.compressed { OFFC_TYPE } else { OFF_TYPE }
    }
    fn keypair_off(&self) -> usize {
        if self.compressed { OFFC_KEYPAIR } else { OFF_KEYPAIR }
    }
    fn chain_off(&self) -> usize {
        if self.compressed { OFFC_CHAIN } else { OFF_CHAIN }
    }
    fn hash_off(&self) -> usize {
        if self.compressed { OFFC_HASH } else { OFF_HASH }
    }
    fn type_size(&self) -> usize {
        if self.compressed { 1 } else { 4 }
    }

    /// Serialized length: 22 compressed, 32 uncompressed.
    pub(crate) fn len(&self) -> usize {
        if self.compressed { ADRSC_SIZE } else { ADRS_SIZE }
    }

    /// The serialized address bytes to feed into a hash function.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len()]
    }

    /// Zero the whole address.
    pub(crate) fn zero(&mut self) {
        self.buf.fill(0);
    }

    /// Copy keypair address (4 bytes) from `src`, keeping the rest of `self`.
    pub(crate) fn copy_keypair_address(&mut self, src: &Adrs) {
        let off = self.keypair_off();
        self.buf[off..off + 4].copy_from_slice(&src.buf[off..off + 4]);
    }

    /// layer_address field.
    pub(crate) fn set_layer_address(&mut self, layer: u32) {
        let off = self.layer_off();
        if self.compressed {
            self.buf[off] = layer as u8;
        } else {
            self.buf[off..off + 4].copy_from_slice(&layer.to_be_bytes());
        }
    }

    /// tree_address field. The uncompressed layout reserves 12 bytes at offset
    /// 4; only the low 8 are used (offset 8), with the high 4 left zero.
    pub(crate) fn set_tree_address(&mut self, tree: u64) {
        let off = if self.compressed { OFFC_TREE } else { OFF_TREE + 4 };
        self.buf[off..off + 8].copy_from_slice(&tree.to_be_bytes());
    }

    /// Set the type field and clear everything after it.
    pub(crate) fn set_type_and_clear(&mut self, ty: u32) {
        let off = self.type_off();
        if self.compressed {
            self.buf[off] = ty as u8;
        } else {
            self.buf[off..off + 4].copy_from_slice(&ty.to_be_bytes());
        }
        let clear_from = off + self.type_size();
        self.buf[clear_from..].fill(0);
    }

    /// keypair_address field.
    pub(crate) fn set_keypair_address(&mut self, keypair: u32) {
        let off = self.keypair_off();
        self.buf[off..off + 4].copy_from_slice(&keypair.to_be_bytes());
    }

    /// chain_address field (also used as tree height).
    pub(crate) fn set_chain_address(&mut self, chain: u32) {
        let off = self.chain_off();
        self.buf[off..off + 4].copy_from_slice(&chain.to_be_bytes());
    }

    /// hash_address field (also used as tree index).
    pub(crate) fn set_hash_address(&mut self, hash: u32) {
        let off = self.hash_off();
        self.buf[off..off + 4].copy_from_slice(&hash.to_be_bytes());
    }

    /// tree height alias for [`Self::set_chain_address`].
    pub(crate) fn set_tree_height(&mut self, height: u32) {
        self.set_chain_address(height);
    }

    /// tree index alias for [`Self::set_hash_address`].
    pub(crate) fn set_tree_index(&mut self, index: u32) {
        self.set_hash_address(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_layout() {
        let mut a = Adrs::new(false);
        a.set_layer_address(0x11223344);
        a.set_tree_address(0x0102_0304_0506_0708);
        a.set_type_and_clear(TYPE_FORS_TREE);
        a.set_keypair_address(0xAABBCCDD);
        a.set_chain_address(7);
        a.set_hash_address(9);
        let b = a.as_bytes();
        assert_eq!(b.len(), 32);
        assert_eq!(&b[0..4], &[0x11, 0x22, 0x33, 0x44]);
        // tree address occupies bytes 4..16, low 8 bytes used
        assert_eq!(&b[4..8], &[0, 0, 0, 0]);
        assert_eq!(&b[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&b[16..20], &[0, 0, 0, 3]); // TYPE_FORS_TREE
        assert_eq!(&b[20..24], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&b[24..28], &[0, 0, 0, 7]);
        assert_eq!(&b[28..32], &[0, 0, 0, 9]);
    }

    #[test]
    fn set_type_clears_tail() {
        let mut a = Adrs::new(false);
        a.set_keypair_address(0xFFFFFFFF);
        a.set_chain_address(0xFFFFFFFF);
        a.set_hash_address(0xFFFFFFFF);
        a.set_type_and_clear(TYPE_TREE);
        let b = a.as_bytes();
        assert_eq!(&b[16..20], &[0, 0, 0, 2]);
        assert!(b[20..].iter().all(|&x| x == 0));
    }

    #[test]
    fn compressed_layout() {
        let mut a = Adrs::new(true);
        a.set_layer_address(5);
        a.set_tree_address(0x0102_0304_0506_0708);
        a.set_type_and_clear(TYPE_WOTS_HASH);
        a.set_keypair_address(0x0A0B0C0D);
        a.set_tree_height(3);
        a.set_tree_index(0x11121314);
        let b = a.as_bytes();
        assert_eq!(b.len(), 22);
        assert_eq!(b[0], 5);
        assert_eq!(&b[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(b[9], 0); // TYPE_WOTS_HASH
        assert_eq!(&b[10..14], &[0x0A, 0x0B, 0x0C, 0x0D]);
        assert_eq!(&b[14..18], &[0, 0, 0, 3]);
        assert_eq!(&b[18..22], &[0x11, 0x12, 0x13, 0x14]);
    }

    #[test]
    fn copy_keypair_address() {
        let mut src = Adrs::new(false);
        src.set_keypair_address(0x12345678);
        let mut dst = Adrs::new(false);
        dst.set_layer_address(1);
        dst.copy_keypair_address(&src);
        assert_eq!(&dst.as_bytes()[20..24], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&dst.as_bytes()[0..4], &[0, 0, 0, 1]);
    }
}
