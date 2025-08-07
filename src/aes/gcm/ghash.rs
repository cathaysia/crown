// gcmFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//
//	the coefficient of x⁰ can be obtained by v.low >> 63.
//	the coefficient of x⁶³ can be obtained by v.low & 1.
//	the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//	the coefficient of x¹²⁷ can be obtained by v.high & 1.
#[derive(Clone, Copy, Debug)]
struct GcmFieldElement {
    low: u64,
    high: u64,
}

const GCM_BLOCK_SIZE: usize = 16;

// GHASH is exposed to allow crypto/cipher to implement non-AES GCM modes.
// It is not allowed as a stand-alone operation in FIPS mode because it
// is not ACVP tested.
pub fn ghash_public(key: &[u8; 16], inputs: &[&[u8]]) -> [u8; GCM_BLOCK_SIZE] {
    // fips140.RecordNonApproved() - Not applicable in Rust implementation
    let mut out = [0u8; GCM_BLOCK_SIZE];
    ghash(&mut out, key, inputs);
    out
}

// ghash is a variable-time generic implementation of GHASH, which shouldn't
// be used on any architecture with hardware support for AES-GCM.
//
// Each input is zero-padded to 128-bit before being absorbed.
pub(crate) fn ghash(out: &mut [u8; GCM_BLOCK_SIZE], h: &[u8; GCM_BLOCK_SIZE], inputs: &[&[u8]]) {
    // productTable contains the first sixteen powers of the key, H.
    // However, they are in bit reversed order.
    let mut product_table = [GcmFieldElement { low: 0, high: 0 }; 16];

    // We precompute 16 multiples of H. However, when we do lookups
    // into this table we'll be using bits from a field element and
    // therefore the bits will be in the reverse order. So normally one
    // would expect, say, 4*H to be in index 4 of the table but due to
    // this bit ordering it will actually be in index 0010 (base 2) = 2.
    let x = GcmFieldElement {
        low: u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]),
        high: u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]),
    };
    product_table[reverse_bits(1)] = x;

    for i in (2..16).step_by(2) {
        product_table[reverse_bits(i)] = ghash_double(&product_table[reverse_bits(i / 2)]);
        product_table[reverse_bits(i + 1)] = ghash_add(&product_table[reverse_bits(i)], &x);
    }

    let mut y = GcmFieldElement { low: 0, high: 0 };
    for input in inputs {
        ghash_update(&product_table, &mut y, input);
    }

    let low_bytes = y.low.to_be_bytes();
    let high_bytes = y.high.to_be_bytes();
    out[0..8].copy_from_slice(&low_bytes);
    out[8..16].copy_from_slice(&high_bytes);
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
