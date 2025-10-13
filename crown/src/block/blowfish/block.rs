use super::Blowfish;

// getNextWord returns the next big-endian uint32 value from the byte slice
// at the given position in a circular manner, updating the position.
fn get_next_word(b: &[u8], pos: &mut usize) -> u32 {
    let mut w = 0u32;
    let mut j = *pos;
    for _ in 0..4 {
        w = (w << 8) | b[j] as u32;
        j += 1;
        if j >= b.len() {
            j = 0;
        }
    }
    *pos = j;
    w
}

// ExpandKey performs a key expansion on the given *Cipher. Specifically, it
// performs the Blowfish algorithm's key schedule which sets up the *Cipher's
// pi and substitution tables for calls to Encrypt. This is used, primarily,
// by the bcrypt package to reuse the Blowfish key schedule during its
// set up. It's unlikely that you need to use this directly.
pub fn expand_key(key: &[u8], c: &mut Blowfish) {
    let mut j = 0;
    for i in 0..18 {
        // Using inlined getNextWord for performance.
        let mut d = 0u32;
        for _ in 0..4 {
            d = (d << 8) | key[j] as u32;
            j += 1;
            if j >= key.len() {
                j = 0;
            }
        }
        c.p[i] ^= d;
    }

    let mut l = 0u32;
    let mut r = 0u32;
    for i in (0..18).step_by(2) {
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.p[i] = l;
        c.p[i + 1] = r;
    }

    for i in (0..256).step_by(2) {
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s0[i] = l;
        c.s0[i + 1] = r;
    }
    for i in (0..256).step_by(2) {
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s1[i] = l;
        c.s1[i + 1] = r;
    }
    for i in (0..256).step_by(2) {
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s2[i] = l;
        c.s2[i + 1] = r;
    }
    for i in (0..256).step_by(2) {
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s3[i] = l;
        c.s3[i + 1] = r;
    }
}

// This is similar to ExpandKey, but folds the salt during the key
// schedule. While ExpandKey is essentially expandKeyWithSalt with an all-zero
// salt passed in, reusing ExpandKey turns out to be a place of inefficiency
// and specializing it here is useful.
pub fn expand_key_with_salt(key: &[u8], salt: &[u8], c: &mut Blowfish) {
    let mut j = 0;
    for i in 0..18 {
        c.p[i] ^= get_next_word(key, &mut j);
    }

    j = 0;
    let mut l = 0u32;
    let mut r = 0u32;
    for i in (0..18).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.p[i] = l;
        c.p[i + 1] = r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s0[i] = l;
        c.s0[i + 1] = r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s1[i] = l;
        c.s1[i + 1] = r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s2[i] = l;
        c.s2[i + 1] = r;
    }

    for i in (0..256).step_by(2) {
        l ^= get_next_word(salt, &mut j);
        r ^= get_next_word(salt, &mut j);
        let (new_l, new_r) = encrypt_block(l, r, c);
        l = new_l;
        r = new_r;
        c.s3[i] = l;
        c.s3[i + 1] = r;
    }
}

pub fn encrypt_block(l: u32, r: u32, c: &Blowfish) -> (u32, u32) {
    let mut xl = l;
    let mut xr = r;
    xl ^= c.p[0];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[1];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[2];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[3];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[4];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[5];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[6];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[7];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[8];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[9];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[10];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[11];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[12];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[13];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[14];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[15];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[16];
    xr ^= c.p[17];
    (xr, xl)
}

pub fn decrypt_block(l: u32, r: u32, c: &Blowfish) -> (u32, u32) {
    let mut xl = l;
    let mut xr = r;
    xl ^= c.p[17];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[16];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[15];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[14];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[13];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[12];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[11];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[10];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[9];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[8];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[7];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[6];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[5];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[4];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[3];
    xr ^= ((c.s0[((xl >> 24) & 0xff) as usize].wrapping_add(c.s1[((xl >> 16) & 0xff) as usize]))
        ^ c.s2[((xl >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xl & 0xff) as usize])
        ^ c.p[2];
    xl ^= ((c.s0[((xr >> 24) & 0xff) as usize].wrapping_add(c.s1[((xr >> 16) & 0xff) as usize]))
        ^ c.s2[((xr >> 8) & 0xff) as usize])
        .wrapping_add(c.s3[(xr & 0xff) as usize])
        ^ c.p[1];
    xr ^= c.p[0];
    (xr, xl)
}
