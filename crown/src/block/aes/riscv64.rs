//! riscv64 AES implementation (`aes-riscv64*.pl`).
//!
//! Upstream builds riscv64 with `AES_ASM` unconditionally (the T-table
//! assembly replaces the C implementation) and the provider's cipher
//! implementations prefer the crypto extensions on top of it
//! (`cipher_aes_hw_rv64i.inc`). crown mirrors that layering with three
//! tiers, picked by [`tier`]:
//!
//! | tier | key schedule | block | bulk |
//! |---|---|---|---|
//! | `Zvkned` (`RISCV_HAS_ZVKNED() && vlen >= 128`) | `rv64i_zvkned_set_encrypt_key` (AES-128/256), `AES_set_encrypt_key` (AES-192) | `rv64i_zvkned_{encrypt,decrypt}` | `rv64i_zvkned_{cbc,ecb}_*`, `rv64i_zvkb_zvkned_ctr32_*` |
//! | `Zkn` (`RISCV_HAS_ZKND_AND_ZKNE()`) | `rv64i_zkne_set_encrypt_key` / `rv64i_zknd_set_decrypt_key` | `rv64i_zk{ne,nd}_{encrypt,decrypt}` | none (portable loops) |
//! | `Ttable` | `AES_set_{encrypt,decrypt}_key` | `AES_{encrypt,decrypt}` | none (portable loops) |
//!
//! Two upstream quirks are reproduced exactly:
//!
//! * Zvkned generates key schedules for 128/256-bit keys only, so AES-192
//!   falls back to the T-table schedule (`cipher_aes_hw_rv64i.inc`) -- the
//!   two writers agree on the FIPS-197 word order, which the Zvkned bodies
//!   consume unchanged.
//! * all Zvkned bodies decrypt with the *forward* schedule, so
//!   [`set_decrypt_key`] builds the same schedule as [`set_encrypt_key`] in
//!   that tier, unlike the `Zkn` and `Ttable` ones.
//!
//! The bulk routines never see partial blocks: CBC/ECB take whole blocks and
//! CTR takes a block count, exactly like the OpenSSL wrappers.

pub use super::key::AesKey;

/// The AES block size, the unit the CBC/ECB bulk bodies count in.
const BLOCK_SIZE: usize = 16;

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/riscv64/aes_ttable.ts"),
    options(raw)
);

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/riscv64/zkn.ts"),
    options(raw)
);

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/riscv64/zvkned.ts"),
    options(raw)
);

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/riscv64/zvkb_zvkned_ctr32.ts"),
    options(raw)
);

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/riscv64/zvbb_zvkg_zvkned_xts.ts"),
    options(raw)
);

extern "C" {
    // aes-riscv64.pl (T-table, the AES_ASM implementation).
    fn AES_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn AES_set_decrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn AES_encrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn AES_decrypt(inp: *const u8, out: *mut u8, key: *const AesKey);

    // aes-riscv64-zkn.pl (Zknd/Zkne scalar crypto).
    fn rv64i_zkne_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn rv64i_zknd_set_decrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn rv64i_zkne_encrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn rv64i_zknd_decrypt(inp: *const u8, out: *mut u8, key: *const AesKey);

    // aes-riscv64-zvkned.pl (Zvkned vector crypto).
    fn rv64i_zvkned_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn rv64i_zvkned_set_decrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn rv64i_zvkned_encrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn rv64i_zvkned_decrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn rv64i_zvkned_cbc_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut u8,
        enc: i32,
    );
    fn rv64i_zvkned_cbc_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut u8,
        enc: i32,
    );
    fn rv64i_zvkned_ecb_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        enc: i32,
    );
    fn rv64i_zvkned_ecb_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        enc: i32,
    );

    // aes-riscv64-zvkb-zvkned.pl (Zvkb + Zvkned CTR32).
    fn rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        ivec: *const u8,
    );

    // aes-riscv64-zvbb-zvkg-zvkned.pl (Zvbb + Zvkg + Zvkned XTS).
    fn rv64i_zvbb_zvkg_zvkned_aes_xts_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
    fn rv64i_zvbb_zvkg_zvkned_aes_xts_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
}

/// The implementation tier, in `PROV_CIPHER_HW_select` order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Tier {
    /// `RISCV_HAS_ZVKNED() && riscv_vlen() >= 128`.
    Zvkned,
    /// `RISCV_HAS_ZKND_AND_ZKNE()`.
    Zkn,
    /// Everything else: the T-table assembly, which riscv64 builds always
    /// install as `AES_ASM`.
    Ttable,
}

/// The tier this CPU gets.
pub(crate) fn tier() -> Tier {
    use crate::utils::cpuid::{riscv_vlen, riscvcap, RISCV_ZKND, RISCV_ZKNE, RISCV_ZVKNED};
    let cap = riscvcap();
    if cap & RISCV_ZVKNED != 0 && riscv_vlen() >= 128 {
        Tier::Zvkned
    } else if cap & RISCV_ZKND != 0 && cap & RISCV_ZKNE != 0 {
        Tier::Zkn
    } else {
        Tier::Ttable
    }
}

/// `RISCV_HAS_ZVBB() && RISCV_HAS_ZVKG() && RISCV_HAS_ZVKNED() && vlen >= 128`:
/// the XTS routine of aes-riscv64-zvbb-zvkg-zvkned.pl.
pub(crate) fn xts_supported() -> bool {
    use crate::utils::cpuid::{riscv_vlen, riscvcap, RISCV_ZVBB, RISCV_ZVKG, RISCV_ZVKNED};
    let cap = riscvcap();
    cap & RISCV_ZVBB != 0 && cap & RISCV_ZVKG != 0 && cap & RISCV_ZVKNED != 0 && riscv_vlen() >= 128
}

/// `keylen * 8 == 128 || keylen * 8 == 256`: the key sizes Zvkned's key
/// schedule generation supports.
fn zvkned_key_bits(bits: usize) -> bool {
    bits == 128 || bits == 256
}

/// Build the forward schedule for a 16/24/32-byte key.
pub(crate) fn set_encrypt_key(user_key: &[u8]) -> AesKey {
    let bits = (user_key.len() * 8) as i32;
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc = unsafe {
        match tier() {
            Tier::Zvkned if zvkned_key_bits(bits as usize) => {
                rv64i_zvkned_set_encrypt_key(user_key.as_ptr(), bits, &mut key)
            }
            // AES-192: Zvkned cannot generate that schedule, so the T-table
            // one is built instead -- the Zvkned bodies read it unchanged.
            Tier::Zvkned => AES_set_encrypt_key(user_key.as_ptr(), bits, &mut key),
            Tier::Zkn => rv64i_zkne_set_encrypt_key(user_key.as_ptr(), bits, &mut key),
            Tier::Ttable => AES_set_encrypt_key(user_key.as_ptr(), bits, &mut key),
        }
    };
    // The writers disagree on their success value: the T-table and Zkn ones
    // return 0 (`AES_set_encrypt_key`'s convention), the Zvkned ones return 1
    // and only signal failure with a negative value -- which is why
    // `cipher_aes_hw_rv64i.inc` tests `ret < 0`.
    debug_assert!(rc >= 0, "set_encrypt_key failed: {rc}");
    key
}

/// Build the inverse schedule for a 16/24/32-byte key. In the `Zvkned` tier
/// the module's `set_decrypt_key` builds the *forward* schedule again (those
/// bodies decrypt with it); AES-192 has no Zvkned schedule at all, so its
/// T-table schedule is built for both directions.
pub(crate) fn set_decrypt_key(user_key: &[u8]) -> AesKey {
    let bits = (user_key.len() * 8) as i32;
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc = unsafe {
        match tier() {
            Tier::Zvkned if zvkned_key_bits(bits as usize) => {
                rv64i_zvkned_set_decrypt_key(user_key.as_ptr(), bits, &mut key)
            }
            Tier::Zvkned => AES_set_encrypt_key(user_key.as_ptr(), bits, &mut key),
            Tier::Zkn => rv64i_zknd_set_decrypt_key(user_key.as_ptr(), bits, &mut key),
            Tier::Ttable => AES_set_decrypt_key(user_key.as_ptr(), bits, &mut key),
        }
    };
    debug_assert!(rc >= 0, "set_decrypt_key failed: {rc}");
    key
}

/// Encrypt one block in place with the forward schedule.
pub(crate) fn encrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe {
        match tier() {
            Tier::Zvkned => rv64i_zvkned_encrypt(p, p, key),
            Tier::Zkn => rv64i_zkne_encrypt(p, p, key),
            Tier::Ttable => AES_encrypt(p, p, key),
        }
    }
}

/// Decrypt one block in place with the inverse schedule ([`set_decrypt_key`]).
pub(crate) fn decrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe {
        match tier() {
            Tier::Zvkned => rv64i_zvkned_decrypt(p, p, key),
            Tier::Zkn => rv64i_zknd_decrypt(p, p, key),
            Tier::Ttable => AES_decrypt(p, p, key),
        }
    }
}

/// In-place CBC over full blocks, updating `ivec` to the last ciphertext
/// block. Returns false when the tier has no CBC routine or when `inout` is
/// not a whole number of blocks -- `rv64i_zvkned_cbc_*` bails out on such a
/// length without touching anything, so the caller's per-block chain has to
/// stay in charge.
pub(crate) fn cbc_encrypt(inout: &mut [u8], key: &AesKey, ivec: &mut [u8; 16], enc: bool) -> bool {
    if tier() != Tier::Zvkned || !inout.len().is_multiple_of(BLOCK_SIZE) {
        return false;
    }
    unsafe {
        if enc {
            rv64i_zvkned_cbc_encrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                inout.len(),
                key,
                ivec.as_mut_ptr(),
                1,
            );
        } else {
            rv64i_zvkned_cbc_decrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                inout.len(),
                key,
                ivec.as_mut_ptr(),
                0,
            );
        }
    }
    true
}

/// In-place ECB over full blocks. Returns false when the tier has no ECB
/// routine or when `inout` is not a whole number of blocks, like
/// [`cbc_encrypt`].
pub(crate) fn ecb_encrypt(inout: &mut [u8], key: &AesKey, enc: bool) -> bool {
    if tier() != Tier::Zvkned || !inout.len().is_multiple_of(BLOCK_SIZE) {
        return false;
    }
    unsafe {
        if enc {
            rv64i_zvkned_ecb_encrypt(inout.as_ptr(), inout.as_mut_ptr(), inout.len(), key, 1);
        } else {
            rv64i_zvkned_ecb_decrypt(inout.as_ptr(), inout.as_mut_ptr(), inout.len(), key, 0);
        }
    }
    true
}

/// In-place CTR32 over `blocks` 16-byte blocks. `ivec` is the counter block,
/// read but not written back; the 32-bit counter lives in its last four
/// bytes. Returns false when the tier lacks the Zvkb CTR32 routine, which is
/// what `cipher_aes_hw_rv64i.inc` installs.
pub(crate) fn ctr32_encrypt_blocks(
    inp: &[u8],
    out: &mut [u8],
    blocks: usize,
    key: &AesKey,
    ivec: &[u8; 16],
) -> bool {
    if tier() != Tier::Zvkned || !crate::utils::cpuid::has_zvkb() {
        return false;
    }
    debug_assert!(blocks > 0);
    unsafe {
        rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
            inp.as_ptr(),
            out.as_mut_ptr(),
            blocks,
            key,
            ivec.as_ptr(),
        );
    }
    true
}

/// In-place XTS over one data unit, ciphertext stealing included. `key1` is
/// the data key, `key2` the tweak key; both are *forward* schedules, which is
/// what `cipher_hw_aes_xts_rv64i_zvbb_zvkg_zvkned_initkey` builds. Returns
/// false when the CPU lacks the Zvbb+Zvkg+Zvkned combination, in which case
/// the caller keeps the portable XTS (with the tier's per-block bodies).
pub(crate) fn xts_crypt(
    inout: &mut [u8],
    key1: &AesKey,
    key2: &AesKey,
    iv: &[u8; 16],
    enc: bool,
) -> bool {
    if !xts_supported() {
        return false;
    }
    debug_assert!(inout.len() >= 16);
    unsafe {
        if enc {
            rv64i_zvbb_zvkg_zvkned_aes_xts_encrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                inout.len(),
                key1,
                key2,
                iv.as_ptr(),
            );
        } else {
            rv64i_zvbb_zvkg_zvkned_aes_xts_decrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                inout.len(),
                key1,
                key2,
                iv.as_ptr(),
            );
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::aes::{generic, BlockExpanded};

    /// Every tier must agree with the software implementation on both
    /// directions, for every key size -- including AES-192 in the Zvkned
    /// tier, whose schedule comes from the T-table while the bodies come from
    /// `rv64i_zvkned_*`.
    #[test]
    fn block_matches_generic() {
        for key_len in [16usize, 24, 32] {
            let mut key = alloc::vec![0u8; key_len];
            rand::fill(&mut key[..]);
            let enc_key = set_encrypt_key(&key);
            let dec_key = set_decrypt_key(&key);
            let mut block = BlockExpanded::default();
            block.expand(&key);

            for _ in 0..32 {
                let mut buf = [0u8; 16];
                rand::fill(&mut buf);

                let mut soft = buf;
                generic::encrypt_block_generic(&block, &mut soft);
                let mut hw = buf;
                encrypt_block(&mut hw, &enc_key);
                assert_eq!(soft, hw, "encrypt key_len={key_len} tier={:?}", tier());

                let mut soft_dec = hw;
                generic::decrypt_block_generic(&block, &mut soft_dec);
                let mut hw_dec = hw;
                decrypt_block(&mut hw_dec, &dec_key);
                assert_eq!(
                    soft_dec,
                    hw_dec,
                    "decrypt key_len={key_len} tier={:?}",
                    tier()
                );
            }
        }
    }

    /// The Zvkned tier's schedule must be interchangeable with the T-table
    /// one: that is what lets AES-192 mix the two (upstream
    /// `cipher_aes_hw_rv64i.inc`).
    #[test]
    fn zvkned_and_ttable_schedules_agree() {
        if tier() != Tier::Zvkned {
            return;
        }
        for key_len in [16usize, 24, 32] {
            let mut key = alloc::vec![0u8; key_len];
            rand::fill(&mut key[..]);
            let mut zvkned = AesKey {
                rd_key: [0; 60],
                rounds: 0,
            };
            let mut ttable = AesKey {
                rd_key: [0; 60],
                rounds: 0,
            };
            unsafe {
                rv64i_zvkned_set_encrypt_key(key.as_ptr(), (key_len * 8) as i32, &mut zvkned);
                AES_set_encrypt_key(key.as_ptr(), (key_len * 8) as i32, &mut ttable);
            }
            if key_len == 24 {
                // AES-192 is the case the Zvkned writer refuses (and the one
                // upstream falls back to `AES_set_encrypt_key` for): it must
                // leave the schedule untouched.
                assert_eq!(zvkned.rounds, 0, "Zvkned must reject AES-192");
            } else {
                // For the sizes it does build, the two writers must produce
                // byte-identical FIPS-197 schedules -- that is what lets the
                // Zvkned bodies consume the T-table one.
                assert_eq!(zvkned.rounds, ttable.rounds, "rounds key_len={key_len}");
                assert_eq!(
                    zvkned.rd_key[..(zvkned.rounds as usize + 1) * 4],
                    ttable.rd_key[..(ttable.rounds as usize + 1) * 4],
                    "schedule key_len={key_len}"
                );
            }
        }
    }

    /// CBC, ECB and CTR bulk bodies against the per-block software path.
    #[test]
    fn bulk_matches_generic() {
        use crate::modes::ctr::Ctr;
        use crate::stream::StreamCipher;

        for key_len in [16usize, 32] {
            let mut key = alloc::vec![0u8; key_len];
            rand::fill(&mut key[..]);
            let enc_key = set_encrypt_key(&key);
            let dec_key = set_decrypt_key(&key);
            let mut block = BlockExpanded::default();
            block.expand(&key);

            for blocks in [1usize, 2, 3, 4, 5, 8, 17] {
                let mut data = alloc::vec![0u8; blocks * 16];
                rand::fill(&mut data[..]);
                let mut iv = [0u8; 16];
                rand::fill(&mut iv);

                // ECB encrypt/decrypt.
                let mut soft = data.clone();
                for chunk in soft.as_chunks_mut::<16>().0 {
                    generic::encrypt_block_generic(&block, chunk);
                }
                let mut hw = data.clone();
                if ecb_encrypt(&mut hw, &enc_key, true) {
                    assert_eq!(soft, hw, "ecb enc blocks={blocks}");

                    let mut soft_dec = hw.clone();
                    for chunk in soft_dec.as_chunks_mut::<16>().0 {
                        generic::decrypt_block_generic(&block, chunk);
                    }
                    let mut hw_dec = hw.clone();
                    assert!(ecb_encrypt(&mut hw_dec, &dec_key, false));
                    assert_eq!(soft_dec, hw_dec, "ecb dec blocks={blocks}");
                } else {
                    assert_eq!(hw, data, "ecb must leave data untouched when unsupported");
                }

                // CBC encrypt: the software chain.
                let mut soft_cbc = data.clone();
                let mut prev = iv;
                for chunk in soft_cbc.as_chunks_mut::<16>().0 {
                    for j in 0..16 {
                        chunk[j] ^= prev[j];
                    }
                    generic::encrypt_block_generic(&block, chunk);
                    prev = *chunk;
                }
                let mut hw_cbc = data.clone();
                let mut hw_iv = iv;
                if cbc_encrypt(&mut hw_cbc, &enc_key, &mut hw_iv, true) {
                    assert_eq!(soft_cbc, hw_cbc, "cbc enc blocks={blocks}");
                    assert_eq!(hw_iv, prev, "cbc enc iv blocks={blocks}");
                }

                // CBC decrypt, the backwards chain of `cbc/decrypt.rs`.
                let mut soft_dec = soft_cbc.clone();
                let mut hl = soft_dec.len();
                while hl > 0 {
                    let start = hl - 16;
                    let mut prev_ct = [0u8; 16];
                    if start > 0 {
                        prev_ct.copy_from_slice(&soft_dec[start - 16..start]);
                    } else {
                        prev_ct = iv;
                    }
                    generic::decrypt_block_generic(&block, &mut soft_dec[start..hl]);
                    for j in 0..16 {
                        soft_dec[start + j] ^= prev_ct[j];
                    }
                    hl = start;
                }
                let mut hw_dec = soft_cbc.clone();
                let mut hw_iv = iv;
                if cbc_encrypt(&mut hw_dec, &dec_key, &mut hw_iv, false) {
                    assert_eq!(soft_dec, hw_dec, "cbc dec blocks={blocks}");
                }

                // CTR: same keystream as the portable CTR mode over the same
                // counter block (last four bytes big-endian, like OpenSSL).
                let mut ks = alloc::vec![0u8; data.len()];
                crate::block::aes::Aes::new(&key)
                    .unwrap()
                    .to_ctr(&iv[..])
                    .unwrap()
                    .xor_key_stream(&mut ks)
                    .unwrap();

                let mut hw_ctr = data.clone();
                if ctr32_encrypt_blocks(&data, &mut hw_ctr, blocks, &enc_key, &iv) {
                    for i in 0..data.len() {
                        assert_eq!(hw_ctr[i], data[i] ^ ks[i], "ctr byte {i} blocks={blocks}");
                    }
                }
            }
        }
    }

    /// The whole-data-unit XTS body against the portable XTS, ciphertext
    /// stealing included (lengths that are not a multiple of 16 exercise it).
    #[test]
    fn xts_matches_portable() {
        use crate::modes::xts::Xts;

        if !xts_supported() {
            return;
        }
        for key_len in [32usize, 64] {
            let mut key = alloc::vec![0u8; key_len];
            rand::fill(&mut key[..]);
            let mut iv = [0u8; 16];
            rand::fill(&mut iv);

            let k1 = set_encrypt_key(&key[..key_len / 2]);
            let k2 = set_encrypt_key(&key[key_len / 2..]);

            let portable = Xts::<crate::block::aes::Aes>::new(&key).unwrap();
            for len in [16usize, 17, 31, 32, 48, 64, 80, 129] {
                let mut data = alloc::vec![0u8; len];
                rand::fill(&mut data[..]);

                let mut soft = data.clone();
                portable.encrypt(&iv, &mut soft).unwrap();

                let mut hw = data.clone();
                assert!(xts_crypt(&mut hw, &k1, &k2, &iv, true));
                assert_eq!(soft, hw, "xts enc len={len} key_len={key_len}");

                assert!(xts_crypt(&mut hw, &k1, &k2, &iv, false));
                assert_eq!(hw, data, "xts dec len={len} key_len={key_len}");
            }
        }
    }
}
