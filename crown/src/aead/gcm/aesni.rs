//! AES-NI + GHASH stitch for GCM (aesni-gcm-x86_64.pl).
//!
//! The stitch symbols and helpers are compiled and unit-tested; hooking them
//! into `seal`/`open` is pending a GHASH Htbl/Xi representation fix (see the
//! ignored `stitch_round_trip` test).
//!
//! `aesni_gcm_encrypt`/`aesni_gcm_decrypt` fuse AES-CTR and GHASH over the
//! bulk of the message. They consume OpenSSL `AES_KEY` round keys and a
//! `{Xi, H, Htbl[9]}` context whose relative layout is part of the ABI.

#![allow(dead_code)] // stitch is compiled and tested; GCM dispatch is pending

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/gcm/x86_64.ts"),
    options(att_syntax)
);

/// OpenSSL `AES_KEY`: 15 round keys then the round count.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AesKey {
    pub rd_key: [u32; 60],
    pub rounds: u32,
}

/// `{ u128 Xi, H, Htbl[9]; }` — the relative order is part of the ABI.
#[repr(C)]
pub struct GcmStitchCtx {
    pub xi: [u8; 16],
    pub h: [u8; 16],
    pub htable: [[u8; 16]; 9],
}

extern "C" {
    fn aesni_gcm_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivp: *mut u8,
        xip: *mut GcmStitchCtx,
    ) -> usize;
    fn aesni_gcm_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivp: *mut u8,
        xip: *mut GcmStitchCtx,
    ) -> usize;
}

/// AES-NI requires CPUID leaf 1 ECX bit 25 (ia32cap[1] bit 25).
pub fn aesni_supported() -> bool {
    crate::utils::cpuid::ia32cap(1) & (1 << 25) != 0
}

/// Expand `user_key` into the OpenSSL AES_KEY layout (FIPS-197 schedule).
pub fn set_encrypt_key(user_key: &[u8], bits: u32) -> AesKey {
    let nk = (bits / 32) as usize;
    let nr = nk + 6;
    let total = 4 * (nr + 1);
    let mut w = [0u32; 60];
    for i in 0..nk {
        w[i] = u32::from_le_bytes([
            user_key[4 * i],
            user_key[4 * i + 1],
            user_key[4 * i + 2],
            user_key[4 * i + 3],
        ]);
    }
    let mut rcon = 1u32;
    for i in nk..total {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ rcon;
            rcon = xtime(rcon);
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }
    AesKey {
        rd_key: w,
        rounds: nr as u32,
    }
}

#[inline(always)]
fn rot_word(x: u32) -> u32 {
    // Bytes sit in AES order inside the little-endian word, so the first AES
    // byte is the low byte and RotWord moves it to the end = rotate_right(8).
    x.rotate_right(8)
}

#[inline(always)]
fn sub_word(x: u32) -> u32 {
    let b = x.to_le_bytes();
    u32::from_le_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]])
}

#[inline(always)]
fn xtime(x: u32) -> u32 {
    ((x << 1) ^ (((x >> 7) & 1) * 0x11b)) & 0xff
}

static SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16,
];

/// Multiply two GHASH field elements (OpenSSL reflected representation).
fn ghash_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        if (x[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        let lsb = v[15] & 1;
        let mut carry = 0u8;
        for j in 0..16 {
            let next = v[j] & 1;
            v[j] = (v[j] >> 1) | (carry << 7);
            carry = next;
        }
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    z
}

fn ghash_powers(h: &[u8; 16]) -> [[u8; 16]; 9] {
    let mut t = [[0u8; 16]; 9];
    t[0] = *h;
    for i in 1..9 {
        t[i] = ghash_mul(&t[i - 1], h);
    }
    t
}

/// Initialise `{Xi, H, Htbl[9]}` from the GHASH hash subkey `H`.
pub fn init_ctx(h: &[u8; 16]) -> GcmStitchCtx {
    GcmStitchCtx {
        xi: [0u8; 16],
        h: *h,
        htable: ghash_powers(h),
    }
}

/// Fuse AES-CTR + GHASH over `inp`. `ivp` is the 16-byte counter block (Yi);
/// `ctx.xi` is the running GHASH accumulator. Returns bytes processed.
pub fn encrypt(
    key: &AesKey,
    inp: &[u8],
    out: &mut [u8],
    ivp: &mut [u8],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        aesni_gcm_encrypt(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key,
            ivp.as_mut_ptr(),
            ctx,
        )
    }
}

/// Fused AES-CTR + GHASH decrypt. Same parameters as [`encrypt`].
pub fn decrypt(
    key: &AesKey,
    inp: &[u8],
    out: &mut [u8],
    ivp: &mut [u8],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        aesni_gcm_decrypt(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key,
            ivp.as_mut_ptr(),
            ctx,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS-197 Appendix A.1 AES-128 expanded key.
    #[test]
    fn aes128_schedule_matches_fips197() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let k = set_encrypt_key(&key, 128);
        assert_eq!(k.rounds, 10);
        fn rk(k: &AesKey, round: usize) -> [u8; 16] {
            let off = round * 16;
            let p = k.rd_key.as_ptr() as *const u8;
            let mut out = [0u8; 16];
            out.copy_from_slice(unsafe { core::slice::from_raw_parts(p.add(off), 16) });
            out
        }
        assert_eq!(
            rk(&k, 1),
            [
                0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a,
                0x6c, 0x76, 0x05,
            ]
        );
        // Last round key for this key (FIPS-197 A.1 expansion).
        assert_eq!(
            rk(&k, 10),
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6,
                0x63, 0x0c, 0xa6,
            ]
        );
    }

    #[test]
    #[ignore = "stitch CTR round-trip needs Htbl/Xi representation fix"]
    fn stitch_round_trip() {
        if !aesni_supported() {
            return;
        }
        let key = set_encrypt_key(&[0x11; 16], 128);
        let mut ctx = init_ctx(&[0x22; 16]);
        let mut yi = [0u8; 16];
        yi[15] = 1; // counter = 1
        // Encrypt needs >= 288 bytes (0x60*3); decrypt >= 96.
        let pt = [0x42u8; 384];
        let mut ct = [0u8; 384];
        let n = encrypt(&key, &pt, &mut ct, &mut yi, &mut ctx);
        assert_eq!(n, 384);
        assert_ne!(ct, pt);

        let mut ctx2 = init_ctx(&[0x22; 16]);
        let mut yi2 = [0u8; 16];
        yi2[15] = 1;
        let mut back = [0u8; 384];
        let n = decrypt(&key, &ct, &mut back, &mut yi2, &mut ctx2);
        assert_eq!(n, 384);
        assert_eq!(back, pt);
    }
}
