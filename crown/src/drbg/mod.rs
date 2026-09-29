//! NIST SP 800-90A DRBGs: HMAC-DRBG and Hash-DRBG (SHA-256).

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sha256::{new256, sum256};
use crate::hash::Hash;
use crate::mac::hmac::HMAC;

use alloc::vec::Vec;
const SHA256_LEN: usize = 32;
/// SP 800-90A seedlen for SHA-256 Hash_DRBG = 440 bits.
const HASH_SEED_LEN: usize = 55;
const RESEED_INTERVAL: u64 = 1 << 48;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_LEN] {
    let mut mac = HMAC::new(new256, key);
    mac.write_all(data).expect("HMAC write should not fail");
    mac.sum()
}

/// HMAC_DRBG_Update (SP 800-90A §10.1.2.2)
fn hmac_drbg_update(provided: &[u8], k: &mut [u8], v: &mut [u8]) {
    // K = HMAC(K, V || 0x00 || provided_data)
    let mut buf = Vec::with_capacity(v.len() + 1 + provided.len());
    buf.extend_from_slice(v);
    buf.push(0x00);
    buf.extend_from_slice(provided);
    let nk = hmac_sha256(k, &buf);
    k.copy_from_slice(&nk);
    // V = HMAC(K, V)
    let nv = hmac_sha256(k, v);
    v.copy_from_slice(&nv);

    if !provided.is_empty() {
        let mut buf = Vec::with_capacity(v.len() + 1 + provided.len());
        buf.extend_from_slice(v);
        buf.push(0x01);
        buf.extend_from_slice(provided);
        let nk = hmac_sha256(k, &buf);
        k.copy_from_slice(&nk);
        let nv = hmac_sha256(k, v);
        v.copy_from_slice(&nv);
    }
}

/// HMAC_DRBG (SP 800-90A §10.1.2), SHA-256.
pub struct HmacDrbg {
    k: [u8; SHA256_LEN],
    v: [u8; SHA256_LEN],
    reseed_counter: u64,
}

impl HmacDrbg {
    /// Instantiate with entropy || nonce || personalization as seed material.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Self {
        let mut seed = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(personalization);

        let mut k = [0u8; SHA256_LEN];
        let mut v = [0x01u8; SHA256_LEN];
        hmac_drbg_update(&seed, &mut k, &mut v);
        HmacDrbg { k, v, reseed_counter: 1 }
    }

    /// Reseed with entropy || additional as seed material.
    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) {
        let mut seed = Vec::with_capacity(entropy.len() + additional.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(additional);
        hmac_drbg_update(&seed, &mut self.k, &mut self.v);
        self.reseed_counter = 1;
    }

    /// Generate `out.len()` bytes. `additional` may be empty.
    pub fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> CryptoResult<()> {
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(CryptoError::InvalidParameterStr("reseed required"));
        }
        if !additional.is_empty() {
            hmac_drbg_update(additional, &mut self.k, &mut self.v);
        }

        let mut offset = 0;
        while offset < out.len() {
            let nv = hmac_sha256(&self.k, &self.v);
            self.v.copy_from_slice(&nv);
            let n = core::cmp::min(SHA256_LEN, out.len() - offset);
            out[offset..offset + n].copy_from_slice(&self.v[..n]);
            offset += n;
        }

        // Update with additional (or empty) after generation
        hmac_drbg_update(additional, &mut self.k, &mut self.v);
        self.reseed_counter += 1;
        Ok(())
    }
}

/// Hash_df (SP 800-90A §10.3.1)
fn hash_df(input: &[u8], out: &mut [u8]) {
    let mut temp = Vec::new();
    let mut counter: u8 = 1;
    let bits = (out.len() as u32) * 8;
    while temp.len() < out.len() {
        let mut buf = Vec::with_capacity(1 + 4 + input.len());
        buf.push(counter);
        buf.extend_from_slice(&bits.to_be_bytes());
        buf.extend_from_slice(input);
        let h = sum256(&buf);
        temp.extend_from_slice(&h);
        counter = counter.wrapping_add(1);
    }
    out.copy_from_slice(&temp[..out.len()]);
}

/// Hashgen (SP 800-90A §10.3.3), SHA-256.
fn hashgen(requested: usize, v: &[u8; HASH_SEED_LEN]) -> Vec<u8> {
    let mut data = *v;
    let mut temp = Vec::new();
    while temp.len() < requested {
        let h = sum256(&data);
        temp.extend_from_slice(&h);
        // data = (data + 1) mod 2^seedlen
        for i in (0..HASH_SEED_LEN).rev() {
            data[i] = data[i].wrapping_add(1);
            if data[i] != 0 {
                break;
            }
        }
    }
    temp.truncate(requested);
    temp
}

/// Add two big-endian byte slices modulo 2^(8*n) into `acc`.
fn add_assign(acc: &mut [u8], other: &[u8]) {
    let n = acc.len();
    debug_assert_eq!(other.len(), n);
    let mut carry = 0u16;
    for i in (0..n).rev() {
        let s = acc[i] as u16 + other[i] as u16 + carry;
        acc[i] = s as u8;
        carry = s >> 8;
    }
}

/// Hash_DRBG (SP 800-90A §10.1.1), SHA-256, seedlen = 440 bits.
pub struct HashDrbg {
    v: [u8; HASH_SEED_LEN],
    c: [u8; HASH_SEED_LEN],
    reseed_counter: u64,
}

impl HashDrbg {
    /// Instantiate with entropy || nonce || personalization as seed material.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Self {
        let mut seed = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(personalization);

        let mut v = [0u8; HASH_SEED_LEN];
        hash_df(&seed, &mut v);

        // C = Hash_df(0x00 || V)
        let mut c_in = Vec::with_capacity(1 + HASH_SEED_LEN);
        c_in.push(0x00);
        c_in.extend_from_slice(&v);
        let mut c = [0u8; HASH_SEED_LEN];
        hash_df(&c_in, &mut c);
        HashDrbg { v, c, reseed_counter: 1 }
    }

    /// Reseed with entropy || additional as seed material.
    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) {
        let mut seed = Vec::with_capacity(entropy.len() + additional.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(additional);

        let mut v_in = Vec::with_capacity(1 + HASH_SEED_LEN + seed.len());
        v_in.push(0x01);
        v_in.extend_from_slice(&self.v);
        v_in.extend_from_slice(&seed);
        hash_df(&v_in, &mut self.v);

        let mut c_in = Vec::with_capacity(1 + HASH_SEED_LEN);
        c_in.push(0x00);
        c_in.extend_from_slice(&self.v);
        hash_df(&c_in, &mut self.c);
        self.reseed_counter = 1;
    }

    /// Generate `out.len()` bytes. `additional` may be empty.
    pub fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> CryptoResult<()> {
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(CryptoError::InvalidParameterStr("reseed required"));
        }
        if !additional.is_empty() {
            let mut v_in = Vec::with_capacity(1 + HASH_SEED_LEN + additional.len());
            v_in.push(0x02);
            v_in.extend_from_slice(&self.v);
            v_in.extend_from_slice(additional);
            hash_df(&v_in, &mut self.v);
        }

        let temp = hashgen(out.len(), &self.v);
        out.copy_from_slice(&temp);

        // H = Hash(0x03 || V)
        let mut h_in = Vec::with_capacity(1 + HASH_SEED_LEN);
        h_in.push(0x03);
        h_in.extend_from_slice(&self.v);
        let h = sum256(&h_in);

        // V = (V + H + C + reseed_counter) mod 2^seedlen
        let mut h_seeded = [0u8; HASH_SEED_LEN];
        h_seeded[HASH_SEED_LEN - 32..].copy_from_slice(&h);
        add_assign(&mut self.v, &h_seeded);
        add_assign(&mut self.v, &self.c);
        let mut ctr = [0u8; HASH_SEED_LEN];
        let bc = self.reseed_counter.to_be_bytes();
        ctr[HASH_SEED_LEN - 8..].copy_from_slice(&bc);
        add_assign(&mut self.v, &ctr);

        self.reseed_counter += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_drbg_determinism() {
        let e = [0x01u8; 32];
        let n = [0x02u8; 16];
        let mut a = HmacDrbg::new(&e, &n, b"test");
        let mut b = HmacDrbg::new(&e, &n, b"test");
        let mut oa = [0u8; 64];
        let mut ob = [0u8; 64];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_eq!(oa, ob);

        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_eq!(oa, ob);
    }

    #[test]
    fn hmac_drbg_reseed_changes_output() {
        let e = [0x01u8; 32];
        let n = [0x02u8; 16];
        let mut a = HmacDrbg::new(&e, &n, b"");
        let mut b = HmacDrbg::new(&e, &n, b"");
        b.reseed(&[0xAAu8; 32], b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn hmac_drbg_additional_changes_output() {
        let e = [0x01u8; 32];
        let n = [0x02u8; 16];
        let mut a = HmacDrbg::new(&e, &n, b"");
        let mut b = HmacDrbg::new(&e, &n, b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"extra").unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn hmac_drbg_distinct_entropy() {
        let mut a = HmacDrbg::new(&[1u8; 32], &[2u8; 16], b"");
        let mut b = HmacDrbg::new(&[9u8; 32], &[8u8; 16], b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn hash_drbg_determinism() {
        let e = [0x03u8; 32];
        let n = [0x04u8; 16];
        let mut a = HashDrbg::new(&e, &n, b"p");
        let mut b = HashDrbg::new(&e, &n, b"p");
        let mut oa = [0u8; 40];
        let mut ob = [0u8; 40];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_eq!(oa, ob);
    }

    #[test]
    fn hash_drbg_reseed_changes_output() {
        let e = [0x03u8; 32];
        let n = [0x04u8; 16];
        let mut a = HashDrbg::new(&e, &n, b"");
        let mut b = HashDrbg::new(&e, &n, b"");
        b.reseed(&[0x55u8; 32], b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn hash_drbg_distinct_streams() {
        let mut a = HashDrbg::new(&[1u8; 32], &[2u8; 16], b"");
        let mut b = HashDrbg::new(&[9u8; 32], &[8u8; 16], b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"").unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn hash_drbg_additional_changes_output() {
        let e = [0x03u8; 32];
        let n = [0x04u8; 16];
        let mut a = HashDrbg::new(&e, &n, b"");
        let mut b = HashDrbg::new(&e, &n, b"");
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, b"").unwrap();
        b.generate(&mut ob, b"add").unwrap();
        assert_ne!(oa, ob);
    }
}
