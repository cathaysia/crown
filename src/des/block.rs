use std::sync::Once;

pub static FEISTEL_BOX_INIT: Once = Once::new();
static mut FEISTEL_BOX: [[u32; 64]; 8] = [[0; 64]; 8];

pub fn crypt_block(subkeys: &[u64], dst: &mut [u8], src: &[u8], decrypt: bool) {
    let b = u64::from_be_bytes(src[..8].try_into().unwrap());
    let b = permute_initial_block(b);
    let mut left = (b >> 32) as u32;
    let mut right = b as u32;

    left = left.rotate_left(1);
    right = right.rotate_left(1);

    if decrypt {
        for i in 0..8 {
            let (new_left, new_right) =
                feistel(left, right, subkeys[15 - 2 * i], subkeys[15 - (2 * i + 1)]);
            left = new_left;
            right = new_right;
        }
    } else {
        for i in 0..8 {
            let (new_left, new_right) = feistel(left, right, subkeys[2 * i], subkeys[2 * i + 1]);
            left = new_left;
            right = new_right;
        }
    }

    left = left.rotate_right(1);
    right = right.rotate_right(1);

    let pre_output = ((right as u64) << 32) | (left as u64);
    let result = permute_final_block(pre_output);
    dst[..8].copy_from_slice(&result.to_be_bytes());
}

pub(crate) fn feistel(l: u32, r: u32, k0: u64, k1: u64) -> (u32, u32) {
    FEISTEL_BOX_INIT.call_once(|| {
        init_feistel_box();
    });

    let feistel_box = unsafe { FEISTEL_BOX };

    let mut l = l;
    let mut r = r;

    let mut t = r ^ (k0 >> 32) as u32;
    l ^= feistel_box[7][(t & 0x3f) as usize]
        ^ feistel_box[5][((t >> 8) & 0x3f) as usize]
        ^ feistel_box[3][((t >> 16) & 0x3f) as usize]
        ^ feistel_box[1][((t >> 24) & 0x3f) as usize];

    t = r.rotate_right(4) ^ k0 as u32;
    l ^= feistel_box[6][(t & 0x3f) as usize]
        ^ feistel_box[4][((t >> 8) & 0x3f) as usize]
        ^ feistel_box[2][((t >> 16) & 0x3f) as usize]
        ^ feistel_box[0][((t >> 24) & 0x3f) as usize];

    t = l ^ (k1 >> 32) as u32;
    r ^= feistel_box[7][(t & 0x3f) as usize]
        ^ feistel_box[5][((t >> 8) & 0x3f) as usize]
        ^ feistel_box[3][((t >> 16) & 0x3f) as usize]
        ^ feistel_box[1][((t >> 24) & 0x3f) as usize];

    t = l.rotate_right(4) ^ k1 as u32;
    r ^= feistel_box[6][(t & 0x3f) as usize]
        ^ feistel_box[4][((t >> 8) & 0x3f) as usize]
        ^ feistel_box[2][((t >> 16) & 0x3f) as usize]
        ^ feistel_box[0][((t >> 24) & 0x3f) as usize];

    (l, r)
}

pub fn permute_block(src: u64, permutation: &[u8]) -> u64 {
    let mut block = 0u64;
    for (position, &n) in permutation.iter().enumerate() {
        let bit = (src >> n) & 1;
        block |= bit << ((permutation.len() - 1) - position);
    }
    block
}

pub fn init_feistel_box() {
    use super::consts::{PERMUTATION_FUNCTION, S_BOXES};

    unsafe {
        for s in 0..8 {
            for i in 0..4 {
                for j in 0..16 {
                    let mut f = (S_BOXES[s][i][j] as u64) << (4 * (7 - s));
                    f = permute_block(f, &PERMUTATION_FUNCTION);

                    let row = ((i & 2) << 4) | (i & 1);
                    let col = j << 1;
                    let t = row | col;

                    f = (f << 1) | (f >> 31);

                    FEISTEL_BOX[s][t] = f as u32;
                }
            }
        }
    }
}

pub(crate) fn permute_initial_block(mut block: u64) -> u64 {
    let b1 = block >> 48;
    let b2 = block << 48;
    block ^= b1 ^ b2 ^ (b1 << 48) ^ (b2 >> 48);

    let b1 = (block >> 32) & 0xff00ff;
    let b2 = block & 0xff00ff00;
    block ^= (b1 << 32) ^ b2 ^ (b1 << 8) ^ (b2 << 24);

    let b1 = block & 0x0f0f00000f0f0000;
    let b2 = block & 0x0000f0f00000f0f0;
    block ^= b1 ^ b2 ^ (b1 >> 12) ^ (b2 << 12);

    let b1 = block & 0x3300330033003300;
    let b2 = block & 0x00cc00cc00cc00cc;
    block ^= b1 ^ b2 ^ (b1 >> 6) ^ (b2 << 6);

    let b1 = block & 0xaaaaaaaa55555555;
    block ^= b1 ^ (b1 >> 33) ^ (b1 << 33);

    block
}

pub(crate) fn permute_final_block(mut block: u64) -> u64 {
    let b1 = block & 0xaaaaaaaa55555555;
    block ^= b1 ^ (b1 >> 33) ^ (b1 << 33);

    let b1 = block & 0x3300330033003300;
    let b2 = block & 0x00cc00cc00cc00cc;
    block ^= b1 ^ b2 ^ (b1 >> 6) ^ (b2 << 6);

    let b1 = block & 0x0f0f00000f0f0000;
    let b2 = block & 0x0000f0f00000f0f0;
    block ^= b1 ^ b2 ^ (b1 >> 12) ^ (b2 << 12);

    let b1 = (block >> 32) & 0xff00ff;
    let b2 = block & 0xff00ff00;
    block ^= (b1 << 32) ^ b2 ^ (b1 << 8) ^ (b2 << 24);

    let b1 = block >> 48;
    let b2 = block << 48;
    block ^= b1 ^ b2 ^ (b1 << 48) ^ (b2 >> 48);

    block
}

pub fn ks_rotate(input: u32, rotations: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(16);
    let mut last = input;

    for &rotation in rotations {
        let left = (last << (4 + rotation)) >> 4;
        let right = (last << 4) >> (32 - rotation);
        let result = left | right;
        out.push(result);
        last = result;
    }

    out
}

pub fn unpack(x: u64) -> u64 {
    ((x >> 6) & 0xff)
        | ((x >> (6 * 3)) & 0xff) << 8
        | ((x >> (6 * 5)) & 0xff) << (8 * 2)
        | ((x >> (6 * 7)) & 0xff) << (8 * 3)
        | (x & 0xff) << (8 * 4)
        | ((x >> (6 * 2)) & 0xff) << (8 * 5)
        | ((x >> (6 * 4)) & 0xff) << (8 * 6)
        | ((x >> (6 * 6)) & 0xff) << (8 * 7)
}
