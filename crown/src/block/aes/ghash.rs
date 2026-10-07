#![allow(dead_code)]
//! GHASH field arithmetic over GF(2¹²⁸) shared by GCM and GMAC. In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//
//	the coefficient of x⁰ can be obtained by v.low >> 63.
//	the coefficient of x⁶³ can be obtained by v.low & 1.
//	the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//	the coefficient of x¹²⁷ can be obtained by v.high & 1.
//
// The generic helpers below are unused when the asm feature is enabled.

#[derive(Clone, Copy, Debug)]
struct GcmFieldElement {
    low: u64,
    high: u64,
}

const GCM_BLOCK_SIZE: usize = 16;

// ghash is a variable-time generic implementation of GHASH, which shouldn't
// be used on any architecture with hardware support for AES-GCM.
//
// Each input is zero-padded to 128-bit before being absorbed.
pub(crate) fn ghash(out: &mut [u8; GCM_BLOCK_SIZE], h: &[u8; GCM_BLOCK_SIZE], inputs: &[&[u8]]) {
    let mut state = [0u8; GCM_BLOCK_SIZE];
    ghash_absorb(&mut state, h, inputs);
    *out = state;
}

/// GHASH `inputs` continuing from `state` (rather than from zero). On return
/// `state` holds the accumulated value. Used to chain AAD -> stitch -> tail.
pub(crate) fn ghash_absorb(
    state: &mut [u8; GCM_BLOCK_SIZE],
    h: &[u8; GCM_BLOCK_SIZE],
    inputs: &[&[u8]],
) {
    #[cfg(all(feature = "asm", feature = "alloc", target_arch = "x86_64"))]
    {
        crate::block::aes::gcm::asm::ghash_absorb(state, h, inputs);
    }

    #[cfg(crown_aarch64_asm)]
    {
        if crate::block::aes::gcm::asm::ghash_pmull_supported() {
            crate::block::aes::gcm::asm::ghash_absorb(state, h, inputs);
            return;
        }
    }

    #[cfg(crown_riscv64_asm)]
    {
        // Zvkg, then Zvkb+Zvbc, then Zbc; without any of them the portable
        // implementation below stays in charge (like `GHASH_ASM_RV64I`
        // falling through to the 4-bit tables in gcm128.c).
        if crate::block::aes::gcm::asm::riscv_ghash_tier().is_some() {
            crate::block::aes::gcm::asm::ghash_absorb(state, h, inputs);
            return;
        }
    }

    #[cfg(any(
        not(feature = "asm"),
        not(feature = "alloc"),
        not(target_arch = "x86_64")
    ))]
    {
        // product table then absorb, seeded from `state`.
        let mut product_table = [GcmFieldElement { low: 0, high: 0 }; 16];
        let x = GcmFieldElement {
            low: u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]),
            high: u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]),
        };
        product_table[reverse_bits(1)] = x;
        for i in (2..16).step_by(2) {
            product_table[reverse_bits(i)] = ghash_double(&product_table[reverse_bits(i / 2)]);
            product_table[reverse_bits(i + 1)] = ghash_add(&product_table[reverse_bits(i)], &x);
        }
        let mut y = GcmFieldElement {
            low: u64::from_be_bytes([
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
            ]),
            high: u64::from_be_bytes([
                state[8], state[9], state[10], state[11], state[12], state[13], state[14],
                state[15],
            ]),
        };
        for input in inputs {
            ghash_update(&product_table, &mut y, input);
        }
        state[0..8].copy_from_slice(&y.low.to_be_bytes());
        state[8..16].copy_from_slice(&y.high.to_be_bytes());
    }
}

pub(crate) fn generic_ghash(
    out: &mut [u8; GCM_BLOCK_SIZE],
    h: &[u8; GCM_BLOCK_SIZE],
    inputs: &[&[u8]],
) {
    let mut table = GhashTable::new(h);
    for input in inputs {
        // ghash_update zero-pads the final partial block, matching the
        // one-shot GHASH semantics.
        table.absorb_padded(input);
    }
    table.sum_into(out);
}

/// Reusable GHASH multiplier: builds the 16-entry product table once and
/// absorbs inputs incrementally. Shared by callers that need repeated
/// multiplies under one key (e.g. GMAC).
pub(crate) struct GhashTable {
    product_table: [GcmFieldElement; 16],
    y: GcmFieldElement,
}

impl GhashTable {
    pub(crate) fn new(h: &[u8; GCM_BLOCK_SIZE]) -> Self {
        // We precompute 16 multiples of H. However, when we do lookups
        // into this table we'll be using bits from a field element and
        // therefore the bits will be in the reverse order. So normally one
        // would expect, say, 4*H to be in index 4 of the table but due to
        // this bit ordering it will actually be in index 0010 (base 2) = 2.
        let x = GcmFieldElement {
            low: u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]),
            high: u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]),
        };
        let mut product_table = [GcmFieldElement { low: 0, high: 0 }; 16];
        product_table[reverse_bits(1)] = x;
        for i in (2..16).step_by(2) {
            product_table[reverse_bits(i)] = ghash_double(&product_table[reverse_bits(i / 2)]);
            product_table[reverse_bits(i + 1)] = ghash_add(&product_table[reverse_bits(i)], &x);
        }
        Self {
            product_table,
            y: GcmFieldElement { low: 0, high: 0 },
        }
    }

    /// XOR `block` into the accumulator and multiply by H. `block` must be
    /// exactly one GHASH block.
    pub(crate) fn absorb_block(&mut self, block: &[u8; GCM_BLOCK_SIZE]) {
        let block_low = u64::from_be_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let block_high = u64::from_be_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);
        self.y.low ^= block_low;
        self.y.high ^= block_high;
        ghash_mul(&self.product_table, &mut self.y);
    }

    /// Zero-pad `data` to a whole block and absorb it.
    pub(crate) fn absorb_padded(&mut self, data: &[u8]) {
        let full = (data.len() >> 4) << 4;
        for chunk in data[..full].as_chunks::<GCM_BLOCK_SIZE>().0 {
            self.absorb_block(chunk);
        }
        if data.len() != full {
            let mut partial = [0u8; GCM_BLOCK_SIZE];
            partial[..data.len() - full].copy_from_slice(&data[full..]);
            self.absorb_block(&partial);
        }
    }

    /// Copy the current accumulator out as big-endian bytes.
    pub(crate) fn sum_into(&self, out: &mut [u8; GCM_BLOCK_SIZE]) {
        out[0..8].copy_from_slice(&self.y.low.to_be_bytes());
        out[8..16].copy_from_slice(&self.y.high.to_be_bytes());
    }
}

// reverseBits reverses the order of the bits of 4-bit number in i.
fn reverse_bits(i: usize) -> usize {
    let mut i = i;
    i = ((i << 2) & 0xc) | ((i >> 2) & 0x3);
    i = ((i << 1) & 0xa) | ((i >> 1) & 0x5);
    i
}

// ghashAdd adds two elements of GF(2¹²⁸) and returns the sum.
fn ghash_add(x: &GcmFieldElement, y: &GcmFieldElement) -> GcmFieldElement {
    // Addition in a characteristic 2 field is just XOR.
    GcmFieldElement {
        low: x.low ^ y.low,
        high: x.high ^ y.high,
    }
}

// ghashDouble returns the result of doubling an element of GF(2¹²⁸).
fn ghash_double(x: &GcmFieldElement) -> GcmFieldElement {
    let msb_set = x.high & 1 == 1;

    // Because of the bit-ordering, doubling is actually a right shift.
    let mut double = GcmFieldElement {
        high: x.high >> 1,
        low: x.low >> 1,
    };
    double.high |= x.low << 63;

    // If the most-significant bit was set before shifting then it,
    // conceptually, becomes a term of x^128. This is greater than the
    // irreducible polynomial so the result has to be reduced. The
    // irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
    // eliminate the term at x^128 which also means subtracting the other
    // four terms. In characteristic 2 fields, subtraction == addition ==
    // XOR.
    if msb_set {
        double.low ^= 0xe100000000000000;
    }

    double
}

static GHASH_REDUCTION_TABLE: [u16; 16] = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0,
];

// ghashMul sets y to y*H, where H is the GCM key, fixed during New.
fn ghash_mul(product_table: &[GcmFieldElement; 16], y: &mut GcmFieldElement) {
    let mut z = GcmFieldElement { low: 0, high: 0 };

    for i in 0..2 {
        let mut word = if i == 0 { y.high } else { y.low };

        // Multiplication works by multiplying z by 16 and adding in
        // one of the precomputed multiples of H.
        for _j in (0..64).step_by(4) {
            let msw = z.high & 0xf;
            z.high >>= 4;
            z.high |= z.low << 60;
            z.low >>= 4;
            z.low ^= (GHASH_REDUCTION_TABLE[msw as usize] as u64) << 48;

            // the values in |table| are ordered for little-endian bit
            // positions. See the comment in New.
            let t = product_table[(word & 0xf) as usize];

            z.low ^= t.low;
            z.high ^= t.high;
            word >>= 4;
        }
    }

    *y = z;
}

// updateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
fn update_blocks(
    product_table: &[GcmFieldElement; 16],
    y: &mut GcmFieldElement,
    mut blocks: &[u8],
) {
    while blocks.len() >= GCM_BLOCK_SIZE {
        let block_low = u64::from_be_bytes([
            blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], blocks[5], blocks[6], blocks[7],
        ]);
        let block_high = u64::from_be_bytes([
            blocks[8], blocks[9], blocks[10], blocks[11], blocks[12], blocks[13], blocks[14],
            blocks[15],
        ]);

        y.low ^= block_low;
        y.high ^= block_high;
        ghash_mul(product_table, y);
        blocks = &blocks[GCM_BLOCK_SIZE..];
    }
}

// ghashUpdate extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
fn ghash_update(product_table: &[GcmFieldElement; 16], y: &mut GcmFieldElement, data: &[u8]) {
    let full_blocks = (data.len() >> 4) << 4;
    update_blocks(product_table, y, &data[..full_blocks]);

    if data.len() != full_blocks {
        let mut partial_block = [0u8; GCM_BLOCK_SIZE];
        partial_block[..data.len() - full_blocks].copy_from_slice(&data[full_blocks..]);
        update_blocks(product_table, y, &partial_block);
    }
}
