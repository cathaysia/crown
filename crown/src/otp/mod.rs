//! HOTP (RFC 4226) and TOTP (RFC 6238).

use crate::core::CoreWrite;
use crate::hash::sha1::new as new_sha1;
use crate::hash::Hash;
use crate::mac::hmac::HMAC;

/// HMAC-SHA1 helper used by HOTP (RFC 4226 mandates HMAC-SHA-1).
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = HMAC::new(new_sha1, key);
    mac.write_all(data).expect("HMAC write should not fail");
    mac.sum()
}

/// HOTP: HMAC-based One-Time Password with dynamic truncation (RFC 4226 §5).
/// `digits` is the number of decimal digits to return (6..=10).
pub fn hotp(key: &[u8], counter: u64, digits: usize) -> u32 {
    assert!((6..=10).contains(&digits), "digits must be in 6..=10");
    let msg = counter.to_be_bytes();
    let mac = hmac_sha1(key, &msg);
    // RFC 4226 §5.4 dynamic truncation
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    bin % 10u32.pow(digits as u32)
}

/// TOTP: Time-based One-Time Password (RFC 6238 §4).
/// `time` is the current Unix time, `step` the time step X (default 30),
/// `digits` the OTP length, `t0` the Unix time to start counting steps (default 0).
pub fn totp(key: &[u8], time: u64, step: u64, digits: usize, t0: u64) -> u32 {
    assert!(step > 0, "step must be > 0");
    let t = time.saturating_sub(t0) / step;
    hotp(key, t, digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D / RFC 6238 Appendix B SHA-1 secret: ASCII "12345678901234567890"
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    /// RFC 4226 Appendix D expected 6-digit HOTP values for counters 0..9.
    const RFC4226_D: [u32; 10] = [
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    ];

    #[test]
    fn hotp_rfc4226_appendix_d() {
        for (i, &expected) in RFC4226_D.iter().enumerate() {
            let got = hotp(RFC_SECRET, i as u64, 6);
            assert_eq!(got, expected, "counter {}", i);
        }
    }

    /// RFC 6238 Appendix B: 8-digit TOTP, step=30, t0=0, HMAC-SHA-1.
    const RFC6238_B: [(u64, u32); 6] = [
        (59, 94287082),
        (1111111109, 7081804),
        (1111111111, 14050471),
        (1234567890, 89005924),
        (2000000000, 69279037),
        (20000000000, 65353130),
    ];

    #[test]
    fn totp_rfc6238_appendix_b_sha1() {
        for &(t, expected) in RFC6238_B.iter() {
            let got = totp(RFC_SECRET, t, 30, 8, 0);
            assert_eq!(got, expected, "time {}", t);
        }
    }

    #[test]
    fn totp_step_changes() {
        let k = b"secret";
        assert_ne!(totp(k, 59, 30, 8, 0), totp(k, 90, 30, 8, 0));
    }

    #[test]
    fn totp_t0_shifts() {
        let k = b"secret";
        assert_ne!(totp(k, 100, 30, 8, 0), totp(k, 100, 30, 8, 45));
    }
}
