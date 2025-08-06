// rc stores the round constants for use in the ι step.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// keccak_f1600_generic applies the Keccak permutation.
pub fn keccak_f1600_generic(da: &mut [u8; 200]) {
    let mut a_storage: [u64; 25];
    let a: &mut [u64; 25];

    if cfg!(target_endian = "big") {
        a_storage = [0u64; 25];
        for i in 0..25 {
            a_storage[i] = u64::from_le_bytes([
                da[i * 8],
                da[i * 8 + 1],
                da[i * 8 + 2],
                da[i * 8 + 3],
                da[i * 8 + 4],
                da[i * 8 + 5],
                da[i * 8 + 6],
                da[i * 8 + 7],
            ]);
        }
        a = &mut a_storage;
    } else {
        // Safety: We're casting a [u8; 200] to [u64; 25], which is safe because:
        // - Both have the same size (200 bytes = 25 * 8 bytes)
        // - u64 has alignment requirements that are satisfied by u8 arrays
        // - We're on little-endian, so byte order matches
        a = unsafe { &mut *(da.as_mut_ptr() as *mut [u64; 25]) };
    }

    // Implementation translated from Keccak-inplace.c
    // in the keccak reference code.
    let mut t: u64;
    let mut bc0: u64;
    let mut bc1: u64;
    let mut bc2: u64;
    let mut bc3: u64;
    let mut bc4: u64;
    let mut d0: u64;
    let mut d1: u64;
    let mut d2: u64;
    let mut d3: u64;
    let mut d4: u64;

    let mut i = 0;
    while i < 24 {
        // Combines the 5 steps in each round into 2 steps.
        // Unrolls 4 rounds per loop and spreads some steps across rounds.

        // Round 1
        bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        d0 = bc4 ^ (bc1.rotate_left(1));
        d1 = bc0 ^ (bc2.rotate_left(1));
        d2 = bc1 ^ (bc3.rotate_left(1));
        d3 = bc2 ^ (bc4.rotate_left(1));
        d4 = bc3 ^ (bc0.rotate_left(1));

        bc0 = a[0] ^ d0;
        t = a[6] ^ d1;
        bc1 = t.rotate_left(44);
        t = a[12] ^ d2;
        bc2 = t.rotate_left(43);
        t = a[18] ^ d3;
        bc3 = t.rotate_left(21);
        t = a[24] ^ d4;
        bc4 = t.rotate_left(14);
        a[0] = bc0 ^ (bc2 & !bc1) ^ RC[i];
        a[6] = bc1 ^ (bc3 & !bc2);
        a[12] = bc2 ^ (bc4 & !bc3);
        a[18] = bc3 ^ (bc0 & !bc4);
        a[24] = bc4 ^ (bc1 & !bc0);

        t = a[10] ^ d0;
        bc2 = t.rotate_left(3);
        t = a[16] ^ d1;
        bc3 = t.rotate_left(45);
        t = a[22] ^ d2;
        bc4 = t.rotate_left(61);
        t = a[3] ^ d3;
        bc0 = t.rotate_left(28);
        t = a[9] ^ d4;
        bc1 = t.rotate_left(20);
        a[10] = bc0 ^ (bc2 & !bc1);
        a[16] = bc1 ^ (bc3 & !bc2);
        a[22] = bc2 ^ (bc4 & !bc3);
        a[3] = bc3 ^ (bc0 & !bc4);
        a[9] = bc4 ^ (bc1 & !bc0);

        t = a[20] ^ d0;
        bc4 = t.rotate_left(18);
        t = a[1] ^ d1;
        bc0 = t.rotate_left(1);
        t = a[7] ^ d2;
        bc1 = t.rotate_left(6);
        t = a[13] ^ d3;
        bc2 = t.rotate_left(25);
        t = a[19] ^ d4;
        bc3 = t.rotate_left(8);
        a[20] = bc0 ^ (bc2 & !bc1);
        a[1] = bc1 ^ (bc3 & !bc2);
        a[7] = bc2 ^ (bc4 & !bc3);
        a[13] = bc3 ^ (bc0 & !bc4);
        a[19] = bc4 ^ (bc1 & !bc0);

        t = a[5] ^ d0;
        bc1 = t.rotate_left(36);
        t = a[11] ^ d1;
        bc2 = t.rotate_left(10);
        t = a[17] ^ d2;
        bc3 = t.rotate_left(15);
        t = a[23] ^ d3;
        bc4 = t.rotate_left(56);
        t = a[4] ^ d4;
        bc0 = t.rotate_left(27);
        a[5] = bc0 ^ (bc2 & !bc1);
        a[11] = bc1 ^ (bc3 & !bc2);
        a[17] = bc2 ^ (bc4 & !bc3);
        a[23] = bc3 ^ (bc0 & !bc4);
        a[4] = bc4 ^ (bc1 & !bc0);

        t = a[15] ^ d0;
        bc3 = t.rotate_left(41);
        t = a[21] ^ d1;
        bc4 = t.rotate_left(2);
        t = a[2] ^ d2;
        bc0 = t.rotate_left(62);
        t = a[8] ^ d3;
        bc1 = t.rotate_left(55);
        t = a[14] ^ d4;
        bc2 = t.rotate_left(39);
        a[15] = bc0 ^ (bc2 & !bc1);
        a[21] = bc1 ^ (bc3 & !bc2);
        a[2] = bc2 ^ (bc4 & !bc3);
        a[8] = bc3 ^ (bc0 & !bc4);
        a[14] = bc4 ^ (bc1 & !bc0);

        // Round 2
        bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        d0 = bc4 ^ (bc1.rotate_left(1));
        d1 = bc0 ^ (bc2.rotate_left(1));
        d2 = bc1 ^ (bc3.rotate_left(1));
        d3 = bc2 ^ (bc4.rotate_left(1));
        d4 = bc3 ^ (bc0.rotate_left(1));

        bc0 = a[0] ^ d0;
        t = a[16] ^ d1;
        bc1 = t.rotate_left(44);
        t = a[7] ^ d2;
        bc2 = t.rotate_left(43);
        t = a[23] ^ d3;
        bc3 = t.rotate_left(21);
        t = a[14] ^ d4;
        bc4 = t.rotate_left(14);
        a[0] = bc0 ^ (bc2 & !bc1) ^ RC[i + 1];
        a[16] = bc1 ^ (bc3 & !bc2);
        a[7] = bc2 ^ (bc4 & !bc3);
        a[23] = bc3 ^ (bc0 & !bc4);
        a[14] = bc4 ^ (bc1 & !bc0);

        t = a[20] ^ d0;
        bc2 = t.rotate_left(3);
        t = a[11] ^ d1;
        bc3 = t.rotate_left(45);
        t = a[2] ^ d2;
        bc4 = t.rotate_left(61);
        t = a[18] ^ d3;
        bc0 = t.rotate_left(28);
        t = a[9] ^ d4;
        bc1 = t.rotate_left(20);
        a[20] = bc0 ^ (bc2 & !bc1);
        a[11] = bc1 ^ (bc3 & !bc2);
        a[2] = bc2 ^ (bc4 & !bc3);
        a[18] = bc3 ^ (bc0 & !bc4);
        a[9] = bc4 ^ (bc1 & !bc0);

        t = a[15] ^ d0;
        bc4 = t.rotate_left(18);
        t = a[6] ^ d1;
        bc0 = t.rotate_left(1);
        t = a[22] ^ d2;
        bc1 = t.rotate_left(6);
        t = a[13] ^ d3;
        bc2 = t.rotate_left(25);
        t = a[4] ^ d4;
        bc3 = t.rotate_left(8);
        a[15] = bc0 ^ (bc2 & !bc1);
        a[6] = bc1 ^ (bc3 & !bc2);
        a[22] = bc2 ^ (bc4 & !bc3);
        a[13] = bc3 ^ (bc0 & !bc4);
        a[4] = bc4 ^ (bc1 & !bc0);

        t = a[10] ^ d0;
        bc1 = t.rotate_left(36);
        t = a[1] ^ d1;
        bc2 = t.rotate_left(10);
        t = a[17] ^ d2;
        bc3 = t.rotate_left(15);
        t = a[8] ^ d3;
        bc4 = t.rotate_left(56);
        t = a[24] ^ d4;
        bc0 = t.rotate_left(27);
        a[10] = bc0 ^ (bc2 & !bc1);
        a[1] = bc1 ^ (bc3 & !bc2);
        a[17] = bc2 ^ (bc4 & !bc3);
        a[8] = bc3 ^ (bc0 & !bc4);
        a[24] = bc4 ^ (bc1 & !bc0);

        t = a[5] ^ d0;
        bc3 = t.rotate_left(41);
        t = a[21] ^ d1;
        bc4 = t.rotate_left(2);
        t = a[12] ^ d2;
        bc0 = t.rotate_left(62);
        t = a[3] ^ d3;
        bc1 = t.rotate_left(55);
        t = a[19] ^ d4;
        bc2 = t.rotate_left(39);
        a[5] = bc0 ^ (bc2 & !bc1);
        a[21] = bc1 ^ (bc3 & !bc2);
        a[12] = bc2 ^ (bc4 & !bc3);
        a[3] = bc3 ^ (bc0 & !bc4);
        a[19] = bc4 ^ (bc1 & !bc0);

        // Round 3
        bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        d0 = bc4 ^ (bc1.rotate_left(1));
        d1 = bc0 ^ (bc2.rotate_left(1));
        d2 = bc1 ^ (bc3.rotate_left(1));
        d3 = bc2 ^ (bc4.rotate_left(1));
        d4 = bc3 ^ (bc0.rotate_left(1));

        bc0 = a[0] ^ d0;
        t = a[11] ^ d1;
        bc1 = t.rotate_left(44);
        t = a[22] ^ d2;
        bc2 = t.rotate_left(43);
        t = a[8] ^ d3;
        bc3 = t.rotate_left(21);
        t = a[19] ^ d4;
        bc4 = t.rotate_left(14);
        a[0] = bc0 ^ (bc2 & !bc1) ^ RC[i + 2];
        a[11] = bc1 ^ (bc3 & !bc2);
        a[22] = bc2 ^ (bc4 & !bc3);
        a[8] = bc3 ^ (bc0 & !bc4);
        a[19] = bc4 ^ (bc1 & !bc0);

        t = a[15] ^ d0;
        bc2 = t.rotate_left(3);
        t = a[1] ^ d1;
        bc3 = t.rotate_left(45);
        t = a[12] ^ d2;
        bc4 = t.rotate_left(61);
        t = a[23] ^ d3;
        bc0 = t.rotate_left(28);
        t = a[9] ^ d4;
        bc1 = t.rotate_left(20);
        a[15] = bc0 ^ (bc2 & !bc1);
        a[1] = bc1 ^ (bc3 & !bc2);
        a[12] = bc2 ^ (bc4 & !bc3);
        a[23] = bc3 ^ (bc0 & !bc4);
        a[9] = bc4 ^ (bc1 & !bc0);

        t = a[5] ^ d0;
        bc4 = t.rotate_left(18);
        t = a[16] ^ d1;
        bc0 = t.rotate_left(1);
        t = a[2] ^ d2;
        bc1 = t.rotate_left(6);
        t = a[13] ^ d3;
        bc2 = t.rotate_left(25);
        t = a[24] ^ d4;
        bc3 = t.rotate_left(8);
        a[5] = bc0 ^ (bc2 & !bc1);
        a[16] = bc1 ^ (bc3 & !bc2);
        a[2] = bc2 ^ (bc4 & !bc3);
        a[13] = bc3 ^ (bc0 & !bc4);
        a[24] = bc4 ^ (bc1 & !bc0);

        t = a[20] ^ d0;
        bc1 = t.rotate_left(36);
        t = a[6] ^ d1;
        bc2 = t.rotate_left(10);
        t = a[17] ^ d2;
        bc3 = t.rotate_left(15);
        t = a[3] ^ d3;
        bc4 = t.rotate_left(56);
        t = a[14] ^ d4;
        bc0 = t.rotate_left(27);
        a[20] = bc0 ^ (bc2 & !bc1);
        a[6] = bc1 ^ (bc3 & !bc2);
        a[17] = bc2 ^ (bc4 & !bc3);
        a[3] = bc3 ^ (bc0 & !bc4);
        a[14] = bc4 ^ (bc1 & !bc0);

        t = a[10] ^ d0;
        bc3 = t.rotate_left(41);
        t = a[21] ^ d1;
        bc4 = t.rotate_left(2);
        t = a[7] ^ d2;
        bc0 = t.rotate_left(62);
        t = a[18] ^ d3;
        bc1 = t.rotate_left(55);
        t = a[4] ^ d4;
        bc2 = t.rotate_left(39);
        a[10] = bc0 ^ (bc2 & !bc1);
        a[21] = bc1 ^ (bc3 & !bc2);
        a[7] = bc2 ^ (bc4 & !bc3);
        a[18] = bc3 ^ (bc0 & !bc4);
        a[4] = bc4 ^ (bc1 & !bc0);

        // Round 4
        bc0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        bc1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        bc2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        bc3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        bc4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        d0 = bc4 ^ (bc1.rotate_left(1));
        d1 = bc0 ^ (bc2.rotate_left(1));
        d2 = bc1 ^ (bc3.rotate_left(1));
        d3 = bc2 ^ (bc4.rotate_left(1));
        d4 = bc3 ^ (bc0.rotate_left(1));

        bc0 = a[0] ^ d0;
        t = a[1] ^ d1;
        bc1 = t.rotate_left(44);
        t = a[2] ^ d2;
        bc2 = t.rotate_left(43);
        t = a[3] ^ d3;
        bc3 = t.rotate_left(21);
        t = a[4] ^ d4;
        bc4 = t.rotate_left(14);
        a[0] = bc0 ^ (bc2 & !bc1) ^ RC[i + 3];
        a[1] = bc1 ^ (bc3 & !bc2);
        a[2] = bc2 ^ (bc4 & !bc3);
        a[3] = bc3 ^ (bc0 & !bc4);
        a[4] = bc4 ^ (bc1 & !bc0);

        t = a[5] ^ d0;
        bc2 = t.rotate_left(3);
        t = a[6] ^ d1;
        bc3 = t.rotate_left(45);
        t = a[7] ^ d2;
        bc4 = t.rotate_left(61);
        t = a[8] ^ d3;
        bc0 = t.rotate_left(28);
        t = a[9] ^ d4;
        bc1 = t.rotate_left(20);
        a[5] = bc0 ^ (bc2 & !bc1);
        a[6] = bc1 ^ (bc3 & !bc2);
        a[7] = bc2 ^ (bc4 & !bc3);
        a[8] = bc3 ^ (bc0 & !bc4);
        a[9] = bc4 ^ (bc1 & !bc0);

        t = a[10] ^ d0;
        bc4 = t.rotate_left(18);
        t = a[11] ^ d1;
        bc0 = t.rotate_left(1);
        t = a[12] ^ d2;
        bc1 = t.rotate_left(6);
        t = a[13] ^ d3;
        bc2 = t.rotate_left(25);
        t = a[14] ^ d4;
        bc3 = t.rotate_left(8);
        a[10] = bc0 ^ (bc2 & !bc1);
        a[11] = bc1 ^ (bc3 & !bc2);
        a[12] = bc2 ^ (bc4 & !bc3);
        a[13] = bc3 ^ (bc0 & !bc4);
        a[14] = bc4 ^ (bc1 & !bc0);

        t = a[15] ^ d0;
        bc1 = t.rotate_left(36);
        t = a[16] ^ d1;
        bc2 = t.rotate_left(10);
        t = a[17] ^ d2;
        bc3 = t.rotate_left(15);
        t = a[18] ^ d3;
        bc4 = t.rotate_left(56);
        t = a[19] ^ d4;
        bc0 = t.rotate_left(27);
        a[15] = bc0 ^ (bc2 & !bc1);
        a[16] = bc1 ^ (bc3 & !bc2);
        a[17] = bc2 ^ (bc4 & !bc3);
        a[18] = bc3 ^ (bc0 & !bc4);
        a[19] = bc4 ^ (bc1 & !bc0);

        t = a[20] ^ d0;
        bc3 = t.rotate_left(41);
        t = a[21] ^ d1;
        bc4 = t.rotate_left(2);
        t = a[22] ^ d2;
        bc0 = t.rotate_left(62);
        t = a[23] ^ d3;
        bc1 = t.rotate_left(55);
        t = a[24] ^ d4;
        bc2 = t.rotate_left(39);
        a[20] = bc0 ^ (bc2 & !bc1);
        a[21] = bc1 ^ (bc3 & !bc2);
        a[22] = bc2 ^ (bc4 & !bc3);
        a[23] = bc3 ^ (bc0 & !bc4);
        a[24] = bc4 ^ (bc1 & !bc0);

        i += 4;
    }

    // Convert back to bytes if we're on big-endian
    if cfg!(target_endian = "big") {
        for i in 0..25 {
            let bytes = a[i].to_le_bytes();
            da[i * 8..i * 8 + 8].copy_from_slice(&bytes);
        }
    }
}
