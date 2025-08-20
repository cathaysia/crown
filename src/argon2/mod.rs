//! Module argon2 implements the key derivation function Argon2.
//! Argon2 was selected as the winner of the Password Hashing Competition and can
//! be used to derive cryptographic keys from passwords.
//!
//! For a detailed specification of Argon2 see [^1].
//!
//! If you aren't sure which function you need, use Argon2id (IDKey) and
//! the parameter recommendations for your scenario.
//!
//! # Argon2i
//!
//! Argon2i (implemented by Key) is the side-channel resistant version of Argon2.
//! It uses data-independent memory access, which is preferred for password
//! hashing and password-based key derivation. Argon2i requires more passes over
//! memory than Argon2id to protect from trade-off attacks. The recommended
//! parameters (taken from [^2]) for non-interactive operations are time=3 and to
//! use the maximum available memory.
//!
//! # Argon2id
//!
//! Argon2id (implemented by IDKey) is a hybrid version of Argon2 combining
//! Argon2i and Argon2d. It uses data-independent memory access for the first
//! half of the first iteration over the memory and data-dependent memory access
//! for the rest. Argon2id is side-channel resistant and provides better brute-
//! force cost savings due to time-memory tradeoffs than Argon2i. The recommended
//! parameters for non-interactive operations (taken from [^2]) are time=1 and to
//! use the maximum available memory.
//!
//! [^1]: <https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf>
//! [^2]: <https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-9.3>

mod blake2_hash;
mod blamka_generic;

#[cfg(test)]
mod tests;

mod noasm;
use noasm::*;

use crate::blake2b::SIZE as BLAKE2B_SIZE;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::HashVariable;
use blake2_hash::blake2b_hash;

// The Argon2 version implemented by this package.
const VERSION: u32 = 0x13;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum ArgonMode {
    ARGON2D = 0,
    ARGON2I = 1,
    ARGON2ID = 2,
}

const BLOCK_LENGTH: usize = 128;
const SYNC_POINTS: u32 = 4;

type Block = [u64; BLOCK_LENGTH];

// Key derives a key from the password, salt, and cost parameters using Argon2i
// returning a byte slice of length keyLen that can be used as cryptographic
// key. The CPU cost and parallelism degree must be greater than zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.Key([]byte("some password"), salt, 3, 32*1024, 4, 32)
//
// The draft RFC recommends[2] time=3, and memory=32*1024 is a sensible number.
// If using that amount of memory (32 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=32*1024 sets the memory cost to ~32 MB. The number of threads can be
// adjusted to the number of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
pub fn key(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u8,
    key_len: u32,
) -> CryptoResult<Vec<u8>> {
    derive_key(
        ArgonMode::ARGON2I,
        password,
        salt,
        &[],
        &[],
        time,
        memory,
        threads,
        key_len,
    )
}

// IDKey derives a key from the password, salt, and cost parameters using
// Argon2id returning a byte slice of length keyLen that can be used as
// cryptographic key. The CPU cost and parallelism degree must be greater than
// zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.IDKey([]byte("some password"), salt, 1, 64*1024, 4, 32)
//
// The draft RFC recommends[2] time=1, and memory=64*1024 is a sensible number.
// If using that amount of memory (64 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
// adjusted to the numbers of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
pub fn id_key(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u8,
    key_len: u32,
) -> CryptoResult<Vec<u8>> {
    derive_key(
        ArgonMode::ARGON2ID,
        password,
        salt,
        &[],
        &[],
        time,
        memory,
        threads,
        key_len,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_key(
    mode: ArgonMode,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    data: &[u8],
    time: u32,
    memory: u32,
    threads: u8,
    key_len: u32,
) -> CryptoResult<Vec<u8>> {
    if time < 1 {
        return Err(CryptoError::InvalidParameter(
            "argon2: number of rounds too small".to_string(),
        ));
    }
    if threads < 1 {
        return Err(CryptoError::InvalidParameter(
            "argon2: parallelism degree too low".to_string(),
        ));
    }

    let mut h0 = init_hash(
        password,
        salt,
        secret,
        data,
        time,
        memory,
        threads as u32,
        key_len,
        mode,
    )?;

    let memory = memory / (SYNC_POINTS * threads as u32) * (SYNC_POINTS * threads as u32);
    let memory = if memory < 2 * SYNC_POINTS * threads as u32 {
        2 * SYNC_POINTS * threads as u32
    } else {
        memory
    };

    let mut blocks = init_blocks(&mut h0, memory, threads as u32)?;
    process_blocks(&mut blocks, time, memory, threads as u32, mode)?;
    extract_key(&blocks, memory, threads as u32, key_len)
}

#[allow(clippy::too_many_arguments)]
fn init_hash(
    password: &[u8],
    salt: &[u8],
    key: &[u8],
    data: &[u8],
    time: u32,
    memory: u32,
    threads: u32,
    key_len: u32,
    mode: ArgonMode,
) -> CryptoResult<[u8; BLAKE2B_SIZE + 8]> {
    let mut h0 = [0u8; BLAKE2B_SIZE + 8];
    let mut params = [0u8; 24];
    let mut tmp = [0u8; 4];

    // Create blake2b hasher
    let mut b2 = crate::blake2b::Blake2bVariable::new(BLAKE2B_SIZE, None)?;

    // Write parameters
    params[0..4].copy_from_slice(&threads.to_le_bytes());
    params[4..8].copy_from_slice(&key_len.to_le_bytes());
    params[8..12].copy_from_slice(&memory.to_le_bytes());
    params[12..16].copy_from_slice(&time.to_le_bytes());
    params[16..20].copy_from_slice(&VERSION.to_le_bytes());
    params[20..24].copy_from_slice(&(mode as u32).to_le_bytes());

    use std::io::Write;
    b2.write_all(&params)?;

    tmp.copy_from_slice(&(password.len() as u32).to_le_bytes());
    b2.write_all(&tmp)?;
    b2.write_all(password)?;

    tmp.copy_from_slice(&(salt.len() as u32).to_le_bytes());
    b2.write_all(&tmp)?;
    b2.write_all(salt)?;

    tmp.copy_from_slice(&(key.len() as u32).to_le_bytes());
    b2.write_all(&tmp)?;
    b2.write_all(key)?;

    tmp.copy_from_slice(&(data.len() as u32).to_le_bytes());
    b2.write_all(&tmp)?;
    b2.write_all(data)?;

    let hash = b2.sum_vec();
    h0[..BLAKE2B_SIZE].copy_from_slice(&hash);

    Ok(h0)
}

fn init_blocks(
    h0: &mut [u8; BLAKE2B_SIZE + 8],
    memory: u32,
    threads: u32,
) -> CryptoResult<Vec<Block>> {
    let mut block0 = [0u8; 1024];
    let mut blocks = vec![[0u64; BLOCK_LENGTH]; memory as usize];

    for lane in 0..threads {
        let j = (lane * (memory / threads)) as usize;

        // Set lane
        h0[BLAKE2B_SIZE + 4..BLAKE2B_SIZE + 8].copy_from_slice(&lane.to_le_bytes());

        // Generate first block
        h0[BLAKE2B_SIZE..BLAKE2B_SIZE + 4].copy_from_slice(&0u32.to_le_bytes());
        blake2b_hash(&mut block0, &*h0)?;
        for i in 0..BLOCK_LENGTH {
            blocks[j][i] = u64::from_le_bytes([
                block0[i * 8],
                block0[i * 8 + 1],
                block0[i * 8 + 2],
                block0[i * 8 + 3],
                block0[i * 8 + 4],
                block0[i * 8 + 5],
                block0[i * 8 + 6],
                block0[i * 8 + 7],
            ]);
        }

        // Generate second block
        h0[BLAKE2B_SIZE..BLAKE2B_SIZE + 4].copy_from_slice(&1u32.to_le_bytes());
        blake2b_hash(&mut block0, &*h0)?;
        for i in 0..BLOCK_LENGTH {
            blocks[j + 1][i] = u64::from_le_bytes([
                block0[i * 8],
                block0[i * 8 + 1],
                block0[i * 8 + 2],
                block0[i * 8 + 3],
                block0[i * 8 + 4],
                block0[i * 8 + 5],
                block0[i * 8 + 6],
                block0[i * 8 + 7],
            ]);
        }
    }

    Ok(blocks)
}

fn process_blocks(
    blocks: &mut [Block],
    time: u32,
    memory: u32,
    threads: u32,
    mode: ArgonMode,
) -> CryptoResult<()> {
    let lanes = memory / threads;
    let segments = lanes / SYNC_POINTS;

    for n in 0..time {
        for slice in 0..SYNC_POINTS {
            for lane in 0..threads {
                process_segment(
                    blocks, memory, n, slice, lane, time, mode, lanes, segments, threads,
                );
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_segment(
    blocks: &mut [Block],
    memory: u32,
    n: u32,
    slice: u32,
    lane: u32,
    time: u32,
    mode: ArgonMode,
    lanes: u32,
    segments: u32,
    threads: u32,
) {
    let mut addresses = [0u64; BLOCK_LENGTH];
    let mut input = [0u64; BLOCK_LENGTH];
    let zero = [0u64; BLOCK_LENGTH];

    if mode == ArgonMode::ARGON2I
        || (mode == ArgonMode::ARGON2ID && n == 0 && slice < SYNC_POINTS / 2)
    {
        input[0] = n as u64;
        input[1] = lane as u64;
        input[2] = slice as u64;
        input[3] = memory as u64;
        input[4] = time as u64;
        input[5] = mode as u64;
    }

    let mut index = 0u32;
    if n == 0 && slice == 0 {
        index = 2; // we have already generated the first two blocks
        if mode == ArgonMode::ARGON2I || mode == ArgonMode::ARGON2ID {
            input[6] += 1;
            process_block(&mut addresses, &input, &zero);
            let src = addresses;
            process_block(&mut addresses, &src, &zero);
        }
    }

    let mut offset = (lane * lanes + slice * segments + index) as usize;

    while index < segments {
        let prev = if index == 0 && slice == 0 {
            offset + lanes as usize - 1 // last block in lane
        } else {
            offset - 1
        };

        let random = if mode == ArgonMode::ARGON2I
            || (mode == ArgonMode::ARGON2ID && n == 0 && slice < SYNC_POINTS / 2)
        {
            if index % BLOCK_LENGTH as u32 == 0 {
                input[6] += 1;
                process_block(&mut addresses, &input, &zero);
                let src = addresses;
                process_block(&mut addresses, &src, &zero);
            }
            addresses[(index % BLOCK_LENGTH as u32) as usize]
        } else {
            blocks[prev][0]
        };

        let new_offset =
            index_alpha(random, lanes, segments, threads, n, slice, lane, index) as usize;
        let src = unsafe {
            let ptr = blocks.as_ptr();
            std::slice::from_raw_parts(ptr, blocks.len())
        };
        process_block_xor(&mut blocks[offset], &src[prev], &src[new_offset]);

        index += 1;
        offset += 1;
    }
}

fn extract_key(blocks: &[Block], memory: u32, threads: u32, key_len: u32) -> CryptoResult<Vec<u8>> {
    let lanes = memory / threads;
    let mut final_block = blocks[(memory - 1) as usize];

    for lane in 0..(threads - 1) {
        let last_block = &blocks[((lane * lanes) + lanes - 1) as usize];
        for i in 0..BLOCK_LENGTH {
            final_block[i] ^= last_block[i];
        }
    }

    let mut block_bytes = [0u8; 1024];
    for (i, &v) in final_block.iter().enumerate() {
        block_bytes[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }

    let mut key = vec![0u8; key_len as usize];
    blake2b_hash(&mut key, &block_bytes)?;

    Ok(key)
}

#[allow(clippy::too_many_arguments)]
fn index_alpha(
    rand: u64,
    lanes: u32,
    segments: u32,
    threads: u32,
    n: u32,
    slice: u32,
    lane: u32,
    index: u32,
) -> u32 {
    let ref_lane = if n == 0 && slice == 0 {
        lane
    } else {
        ((rand >> 32) % threads as u64) as u32
    };

    let (mut m, s) = if n == 0 {
        let s = 0;
        let mut m = slice * segments;
        if slice == 0 || lane == ref_lane {
            m += index;
        }
        (m, s)
    } else {
        let s = ((slice + 1) % SYNC_POINTS) * segments;
        let mut m = 3 * segments;
        if lane == ref_lane {
            m += index;
        }
        (m, s)
    };

    if index == 0 || lane == ref_lane {
        m -= 1;
    }

    phi(rand, m as u64, s as u64, ref_lane, lanes)
}

fn phi(rand: u64, m: u64, s: u64, lane: u32, lanes: u32) -> u32 {
    let p = rand & 0xFFFFFFFF;
    let p = (p * p) >> 32;
    let p = (p * m) >> 32;
    lane * lanes + ((s + m - (p + 1)) % lanes as u64) as u32
}
