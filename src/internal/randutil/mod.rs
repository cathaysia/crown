use std::io::Read;

/// MaybeReadByte reads a single byte from r with 50% probability. This is used
/// to ensure that callers do not depend on non-guaranteed behaviour, e.g.
/// assuming that rsa.GenerateKey is deterministic w.r.t. a given random stream.
///
/// This does not affect tests that pass a stream of fixed bytes as the random
/// source (e.g. a zeroReader).
#[allow(dead_code)]
pub fn maybe_read_byte(mut r: impl Read) {
    let mut buf = [0u8; 1];
    let _ = r.read_exact(&mut buf);
}
