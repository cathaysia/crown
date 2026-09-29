//! ChaCha20-Poly1305 stitched AEAD assembly
//! (BoringSSL `chacha20_poly1305_x86_64.pl`) for x86_64.
//!
//! BoringSSL's `chacha20_poly1305_{seal,open}` fuse the ChaCha20 keystream
//! with Poly1305 tag computation in SSE4.1/AVX2 paths. The dispatcher
//! mirrors BoringSSL's `e_chacha20poly1305.cc`: the AVX2 body requires
//! AVX2+BMI2 (plus the usual OSXSAVE/XCR0 YMM state check), everything
//! else takes the SSE4.1 body, and the module as a whole requires SSE4.1.
//!
//! Data layout (part of the ABI, from boringssl `crypto/cipher/internal.h`):
//!
//! * `open_data` (48 bytes): `in { key[32], counter u32, nonce[12] }`;
//!   after the call bytes `0..16` hold the computed tag (`out.tag`).
//! * `seal_data` (64 bytes): `in { key[32], counter u32, nonce[12],
//!   extra_ciphertext ptr, extra_ciphertext_len }` (the extras are not
//!   used here and stay null); after the call bytes `0..16` hold the tag.
//!
//! Both operations are one-shot: `seal` encrypts `in` into `out` and tags
//! `ad || ciphertext`; `open` decrypts `in` into `out` and returns the
//! tag for the caller to compare (BoringSSL's detached interface).


#![allow(dead_code, unused_imports)]
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/chacha20poly1305/x86_64.ts"),
    options(att_syntax)
);

/// `union chacha20_poly1305_open_data` (48 bytes).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenData {
    pub key: [u8; 32],
    pub counter: u32,
    pub nonce: [u8; 12],
    /// After the call, the computed tag (overlaps `key`).
    pub out_tag: [u8; 16],
}

/// `union chacha20_poly1305_seal_data` (64 bytes).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SealData {
    pub key: [u8; 32],
    pub counter: u32,
    pub nonce: [u8; 12],
    pub extra_ciphertext: *const u8,
    pub extra_ciphertext_len: usize,
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn chacha20_poly1305_seal_sse41(
        out: *mut u8,
        inp: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut SealData,
    );
    fn chacha20_poly1305_seal_avx2(
        out: *mut u8,
        inp: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut SealData,
    );
    fn chacha20_poly1305_open_sse41(
        out: *mut u8,
        inp: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut OpenData,
    );
    fn chacha20_poly1305_open_avx2(
        out: *mut u8,
        inp: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut OpenData,
    );
}

/// SSE4.1 is the module's minimum (boringssl `chacha20_poly1305_asm_capable`).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn sse41_capable() -> bool {
    crate::utils::cpuid::ia32cap(1) & (1 << 19) != 0
}

/// AVX2 + BMI2 + OS YMM state (boringssl `CRYPTO_is_AVX2_capable` plus the
/// BMI2 requirement of the open/seal dispatch).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn avx2_capable() -> bool {
    // OSXSAVE (leaf 1 ECX bit 27) and AVX (bit 28).
    if crate::utils::cpuid::ia32cap(1) & ((1 << 27) | (1 << 28)) != ((1 << 27) | (1 << 28)) {
        return false;
    }
    // AVX2 (leaf 7 EBX bit 5) and BMI2 (leaf 7 EBX bit 8).
    if crate::utils::cpuid::ia32cap(2) & ((1 << 5) | (1 << 8)) != ((1 << 5) | (1 << 8)) {
        return false;
    }
    // XCR0[2:1] == 3: XMM and YMM state enabled.
    (unsafe { core::arch::x86_64::_xgetbv(0) } & 0x6) == 0x6
}

/// Encrypt `in` into `out` and return the 16-byte tag.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn seal(
    out: &mut [u8],
    inp: &[u8],
    ad: &[u8],
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> crate::error::CryptoResult<[u8; 16]> {
    if out.len() < inp.len() {
        return Err(crate::error::CryptoError::BufferTooSmall);
    }
    let mut data = SealData {
        key: *key,
        counter,
        nonce: *nonce,
        extra_ciphertext: core::ptr::null(),
        extra_ciphertext_len: 0,
    };
    let call = if avx2_capable() {
        chacha20_poly1305_seal_avx2
    } else {
        chacha20_poly1305_seal_sse41
    };
    unsafe {
        call(
            out.as_mut_ptr(),
            inp.as_ptr(),
            inp.len(),
            ad.as_ptr(),
            ad.len(),
            &mut data,
        );
    }
    // The tag lands in data.out.tag, overlapping the key's first 16 bytes.
    let mut tag_out = [0u8; 16];
    let bytes: &[u8] =
        unsafe { core::slice::from_raw_parts(&data as *const SealData as *const u8, 16) };
    tag_out.copy_from_slice(bytes);
    Ok(tag_out)
}

/// Decrypt `in` into `out` and return the computed tag for the caller to
/// compare with the received one.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn open(
    out: &mut [u8],
    inp: &[u8],
    ad: &[u8],
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> crate::error::CryptoResult<[u8; 16]> {
    if out.len() < inp.len() {
        return Err(crate::error::CryptoError::BufferTooSmall);
    }
    // `out.tag` overlaps the first 16 bytes of the union (key[0..16]).
    let mut data = OpenData {
        key: *key,
        counter,
        nonce: *nonce,
        out_tag: [0u8; 16],
    };
    let call = if avx2_capable() {
        chacha20_poly1305_open_avx2
    } else {
        chacha20_poly1305_open_sse41
    };
    unsafe {
        call(
            out.as_mut_ptr(),
            inp.as_ptr(),
            inp.len(),
            ad.as_ptr(),
            ad.len(),
            &mut data,
        );
    }
    // The computed tag lands at the START of the union (out.tag overlaps
    // key[0..16]).
    let mut tag = [0u8; 16];
    let bytes: &[u8] =
        unsafe { core::slice::from_raw_parts(&data as *const OpenData as *const u8, 16) };
    tag.copy_from_slice(bytes);
    Ok(tag)
}

/// Seal in place: `inout` is both ciphertext destination and plaintext source.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn seal_inplace(
    inout: &mut [u8],
    ad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> crate::error::CryptoResult<[u8; 16]> {
    let mut data = SealData {
        key: *key,
        counter: 0,
        nonce: *nonce,
        extra_ciphertext: core::ptr::null(),
        extra_ciphertext_len: 0,
    };
    let call = if avx2_capable() {
        chacha20_poly1305_seal_avx2
    } else {
        chacha20_poly1305_seal_sse41
    };
    unsafe {
        call(
            inout.as_mut_ptr(),
            inout.as_ptr(),
            inout.len(),
            ad.as_ptr(),
            ad.len(),
            &mut data,
        );
    }
    let mut tag = [0u8; 16];
    let bytes: &[u8] =
        unsafe { core::slice::from_raw_parts(&data as *const SealData as *const u8, 16) };
    tag.copy_from_slice(bytes);
    Ok(tag)
}

/// Open in place: decrypts `inout` and returns the computed tag.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn open_inplace(
    inout: &mut [u8],
    ad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> crate::error::CryptoResult<[u8; 16]> {
    let mut data = OpenData {
        key: *key,
        counter: 0,
        nonce: *nonce,
        out_tag: [0u8; 16],
    };
    let call = if avx2_capable() {
        chacha20_poly1305_open_avx2
    } else {
        chacha20_poly1305_open_sse41
    };
    unsafe {
        call(
            inout.as_mut_ptr(),
            inout.as_ptr(),
            inout.len(),
            ad.as_ptr(),
            ad.len(),
            &mut data,
        );
    }
    let mut tag = [0u8; 16];
    let bytes: &[u8] =
        unsafe { core::slice::from_raw_parts(&data as *const OpenData as *const u8, 16) };
    tag.copy_from_slice(bytes);
    Ok(tag)
}
