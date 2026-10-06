//! C ABI for big numbers, finite-field Diffie-Hellman and the OS random
//! source. These are the "math" primitives a protocol stack (for example an
//! SSH library) needs on top of the EVP-style surface exported by the other
//! modules.

use super::*;
use crown::bn::Bn;
use crown::dh;
use std::io::Read;

/// Opaque big number handle.
pub struct BnHandle(Bn);

/// OS random source. `failed` latches a read error so callers can refuse to
/// use material derived from a broken source instead of panicking across the
/// C boundary.
pub(crate) struct OsRng {
    pub failed: bool,
}

impl OsRng {
    pub(crate) fn new() -> Self {
        OsRng { failed: false }
    }
}

impl crown::rng::Rng for OsRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        if fill_random(out).is_err() {
            self.failed = true;
            out.fill(0);
        }
    }
}

fn fill_random(out: &mut [u8]) -> std::io::Result<()> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(out)
}

/// Fill `len` bytes with cryptographically secure random data.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_random(buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() && len != 0 {
        return -1;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match fill_random(out) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Allocate a big number with the value zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_new() -> *mut BnHandle {
    Box::into_raw(Box::new(BnHandle(Bn::from_u32(0))))
}

/// Release a big number. NULL is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_free(bn: *mut BnHandle) {
    if !bn.is_null() {
        drop(unsafe { Box::from_raw(bn) });
    }
}

/// Allocate a big number from a big-endian byte string (leading zeros are
/// accepted). Returns NULL on a NULL input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_from_bin(bin: *const u8, len: usize) -> *mut BnHandle {
    let Some(bytes) = (unsafe { slice_from_raw_parts(bin, len) }) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(BnHandle(Bn::from_be_bytes(bytes))))
}

/// Replace the value of `bn` with the big-endian integer in `bin`.
///
/// Returns 0 on success, -1 on a NULL argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_set_from_bin(
    bn: *mut BnHandle,
    bin: *const u8,
    len: usize,
) -> i32 {
    if bn.is_null() {
        return -1;
    }
    let Some(bytes) = (unsafe { slice_from_raw_parts(bin, len) }) else {
        return -1;
    };
    unsafe { (*bn).0 = Bn::from_be_bytes(bytes) };
    0
}

/// Write the minimal big-endian encoding (no leading zeros, nothing at all
/// for zero) into `out`, which must hold at least `crown_bn_bytes` bytes.
///
/// Returns the number of bytes written, or 0 if the value does not fit (or
/// `out` is NULL) — matching `BN_bn2bin`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_to_bin(
    bn: *const BnHandle,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if bn.is_null() || out.is_null() {
        return 0;
    }
    let bytes = unsafe { (*bn).0.to_be_bytes() };
    if bytes.len() > out_len {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len()
}

/// Number of significant bits (0 for zero).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_bits(bn: *const BnHandle) -> usize {
    if bn.is_null() {
        return 0;
    }
    unsafe { (*bn).0.bit_len() }
}

/// Number of bytes needed for the minimal big-endian encoding (0 for zero).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_bytes(bn: *const BnHandle) -> usize {
    if bn.is_null() {
        return 0;
    }
    unsafe { (*bn).0.byte_len() }
}

/// Set the value to a 32-bit word. Returns 0 on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_set_word(bn: *mut BnHandle, word: u32) -> i32 {
    if bn.is_null() {
        return -1;
    }
    unsafe { (*bn).0 = Bn::from_u32(word) };
    0
}

/// `a - b`. Returns NULL when the result would be negative or an argument is
/// NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_sub(a: *const BnHandle, b: *const BnHandle) -> *mut BnHandle {
    if a.is_null() || b.is_null() {
        return std::ptr::null_mut();
    }
    match unsafe { (*a).0.sub(&(*b).0) } {
        Ok(v) => Box::into_raw(Box::new(BnHandle(v))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Copy the value of `src` into `dst`. Returns 0 on success, -1 on a NULL
/// argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_copy(dst: *mut BnHandle, src: *const BnHandle) -> i32 {
    if dst.is_null() || src.is_null() {
        return -1;
    }
    let bytes = unsafe { (*src).0.to_be_bytes() };
    unsafe { (*dst).0 = Bn::from_be_bytes(&bytes) };
    0
}

/// Compare two big numbers: -1 if `a < b`, 0 if equal, 1 if `a > b`.
/// Returns -2 on a NULL argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_bn_cmp(a: *const BnHandle, b: *const BnHandle) -> i32 {
    if a.is_null() || b.is_null() {
        return -2;
    }
    let (a, b) = unsafe { (&(*a).0, &(*b).0) };
    if a.lt(b) {
        -1
    } else if b.lt(a) {
        1
    } else {
        0
    }
}

/// Generate a Diffie-Hellman key pair for the group `(p, g)`: writes the
/// private exponent to `*out_private` and `g^x mod p` to `*out_public`.
///
/// Both outputs are freshly allocated and owned by the caller. Returns 0 on
/// success, -1 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_dh_key_pair(
    p: *const BnHandle,
    g: *const BnHandle,
    out_private: *mut *mut BnHandle,
    out_public: *mut *mut BnHandle,
) -> i32 {
    if p.is_null() || g.is_null() || out_private.is_null() || out_public.is_null() {
        return -1;
    }
    let mut rng = OsRng::new();
    let (x, y) = match dh::generate(unsafe { &(*p).0 }, unsafe { &(*g).0 }, &mut rng) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    if rng.failed {
        return -1;
    }
    unsafe {
        *out_private = Box::into_raw(Box::new(BnHandle(x)));
        *out_public = Box::into_raw(Box::new(BnHandle(y)));
    }
    0
}

/// Compute the shared secret `peer^private mod p` and store it in
/// `*out_secret`. Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_dh_secret(
    private: *const BnHandle,
    peer: *const BnHandle,
    p: *const BnHandle,
    out_secret: *mut *mut BnHandle,
) -> i32 {
    if private.is_null() || peer.is_null() || p.is_null() || out_secret.is_null() {
        return -1;
    }
    let shared = match dh::agree(unsafe { &(*p).0 }, unsafe { &(*private).0 }, unsafe {
        &(*peer).0
    }) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    unsafe { *out_secret = Box::into_raw(Box::new(BnHandle(shared))) };
    0
}

/// Validate a peer's DH public value: 1 when `1 < f < p - 1`, else 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_dh_validate(f: *const BnHandle, p: *const BnHandle) -> i32 {
    if f.is_null() || p.is_null() {
        return 0;
    }
    let (f, p) = unsafe { (&(*f).0, &(*p).0) };
    if f.is_zero() || f.is_one() {
        return 0;
    }
    let one = Bn::one();
    let Ok(pm1) = p.sub(&one) else {
        return 0;
    };
    if !f.lt(&pm1) {
        return 0;
    }
    1
}
