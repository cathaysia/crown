//! Module bcrypt implements Provos and Mazières's bcrypt adaptive hashing
//! algorithm. See <http://www.usenix.org/event/usenix99/provos/provos.pdf>
//!

mod base64;
use base64::*;

#[cfg(test)]
mod tests;

use crate::{
    blowfish::{expand_key, Blowfish as BlowfishCipher},
    cipher::BlockCipher,
    error::CryptoError,
    utils::constant_time_eq,
};
use std::fmt;

// Constants
pub const MIN_COST: u32 = 4;
pub const MAX_COST: u32 = 31;
pub const DEFAULT_COST: u32 = 10;

const MAJOR_VERSION: u8 = b'2';
const MINOR_VERSION: u8 = b'a';
const MAX_SALT_SIZE: usize = 16;
const MAX_CRYPTED_HASH_SIZE: usize = 23;
const ENCODED_SALT_SIZE: usize = 22;
const ENCODED_HASH_SIZE: usize = 31;
const MIN_HASH_SIZE: usize = 59;

// Magic cipher data for bcrypt
const MAGIC_CIPHER_DATA: [u8; 24] = [
    0x4f, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6e, 0x42, 0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x53,
    0x63, 0x72, 0x79, 0x44, 0x6f, 0x75, 0x62, 0x74,
];

// Error types
#[derive(Debug, Clone, PartialEq)]
pub enum BcryptError {
    MismatchedHashAndPassword,
    HashTooShort,
    HashVersionTooNew(u8),
    InvalidHashPrefix(u8),
    InvalidCost(u32),
    PasswordTooLong,
}

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BcryptError::MismatchedHashAndPassword => {
                write!(
                    f,
                    "crypto/bcrypt: hashedPassword is not the hash of the given password"
                )
            }
            BcryptError::HashTooShort => {
                write!(
                    f,
                    "crypto/bcrypt: hashedSecret too short to be a bcrypted password"
                )
            }
            BcryptError::HashVersionTooNew(version) => {
                write!(f, "crypto/bcrypt: bcrypt algorithm version '{}' requested is newer than current version '{}'",
                       *version as char, MAJOR_VERSION as char)
            }
            BcryptError::InvalidHashPrefix(prefix) => {
                write!(f, "crypto/bcrypt: bcrypt hashes must start with '$', but hashedSecret started with '{}'",
                       *prefix as char)
            }
            BcryptError::InvalidCost(cost) => {
                write!(
                    f,
                    "crypto/bcrypt: cost {} is outside allowed inclusive range {}..{}",
                    cost, MIN_COST, MAX_COST
                )
            }
            BcryptError::PasswordTooLong => {
                write!(f, "bcrypt: password length exceeds 72 bytes")
            }
        }
    }
}

impl std::error::Error for BcryptError {}

impl From<BcryptError> for CryptoError {
    fn from(err: BcryptError) -> Self {
        CryptoError::StringError(err.to_string())
    }
}

// Hashed password structure
#[derive(Debug, Clone)]
struct Hashed {
    hash: Vec<u8>,
    salt: Vec<u8>,
    cost: u32,
    major: u8,
    minor: u8,
}

impl Hashed {
    fn new() -> Self {
        Self {
            hash: Vec::new(),
            salt: Vec::new(),
            cost: 0,
            major: 0,
            minor: 0,
        }
    }

    fn to_hash(&self) -> Vec<u8> {
        let mut arr = Vec::with_capacity(60);
        arr.push(b'$');
        arr.push(self.major);

        let mut n = 2;
        if self.minor != 0 {
            arr.push(self.minor);
            n = 3;
        }

        arr.push(b'$');
        n += 1;

        let cost_str = format!("{:02}", self.cost);
        arr.extend_from_slice(cost_str.as_bytes());
        n += 2;

        arr.push(b'$');
        n += 1;

        arr.extend_from_slice(&self.salt);
        n += ENCODED_SALT_SIZE;

        arr.extend_from_slice(&self.hash);
        n += ENCODED_HASH_SIZE;

        arr.truncate(n);
        arr
    }

    fn decode_version(&mut self, sbytes: &[u8]) -> Result<usize, BcryptError> {
        if sbytes[0] != b'$' {
            return Err(BcryptError::InvalidHashPrefix(sbytes[0]));
        }
        if sbytes[1] > MAJOR_VERSION {
            return Err(BcryptError::HashVersionTooNew(sbytes[1]));
        }
        self.major = sbytes[1];
        let mut n = 3;
        if sbytes[2] != b'$' {
            self.minor = sbytes[2];
            n += 1;
        }
        Ok(n)
    }

    fn decode_cost(&mut self, sbytes: &[u8]) -> Result<usize, BcryptError> {
        let cost_str =
            std::str::from_utf8(&sbytes[0..2]).map_err(|_| BcryptError::InvalidCost(0))?;
        let cost = cost_str
            .parse::<u32>()
            .map_err(|_| BcryptError::InvalidCost(0))?;
        check_cost(cost)?;
        self.cost = cost;
        Ok(3)
    }
}

// Public API functions

/// Generate a bcrypt hash from a password with the given cost
pub fn generate_from_password(password: &[u8], cost: u32) -> Result<Vec<u8>, BcryptError> {
    if password.len() > 72 {
        return Err(BcryptError::PasswordTooLong);
    }
    let p = new_from_password(password, cost)?;
    Ok(p.to_hash())
}

/// Compare a bcrypt hashed password with its possible plaintext equivalent
pub fn compare_hash_and_password(
    hashed_password: &[u8],
    password: &[u8],
) -> Result<(), BcryptError> {
    let p = new_from_hash(hashed_password)?;

    let other_hash = bcrypt(password, p.cost, &p.salt)?;

    let other_p = Hashed {
        hash: other_hash,
        salt: p.salt.clone(),
        cost: p.cost,
        major: p.major,
        minor: p.minor,
    };

    if constant_time_eq(&p.to_hash(), &other_p.to_hash()) {
        Ok(())
    } else {
        Err(BcryptError::MismatchedHashAndPassword)
    }
}

/// Return the hashing cost used to create the given hashed password
pub fn cost(hashed_password: &[u8]) -> Result<u32, BcryptError> {
    let p = new_from_hash(hashed_password)?;
    Ok(p.cost)
}

// Internal helper functions

fn new_from_password(password: &[u8], cost: u32) -> Result<Hashed, BcryptError> {
    let cost = if cost < MIN_COST { DEFAULT_COST } else { cost };

    let mut p = Hashed::new();
    p.major = MAJOR_VERSION;
    p.minor = MINOR_VERSION;

    check_cost(cost)?;
    p.cost = cost;

    let mut unencoded_salt = vec![0u8; MAX_SALT_SIZE];
    rand::fill(unencoded_salt.as_mut_slice());

    p.salt = base64_encode(&unencoded_salt);
    let hash = bcrypt(password, p.cost, &p.salt)?;
    p.hash = hash;

    Ok(p)
}

fn new_from_hash(hashed_secret: &[u8]) -> Result<Hashed, BcryptError> {
    if hashed_secret.len() < MIN_HASH_SIZE {
        return Err(BcryptError::HashTooShort);
    }

    let mut p = Hashed::new();
    let n = p.decode_version(hashed_secret)?;
    let hashed_secret = &hashed_secret[n..];

    let n = p.decode_cost(hashed_secret)?;
    let hashed_secret = &hashed_secret[n..];

    p.salt = vec![0u8; ENCODED_SALT_SIZE + 2];
    p.salt[..ENCODED_SALT_SIZE].copy_from_slice(&hashed_secret[..ENCODED_SALT_SIZE]);
    p.salt.truncate(ENCODED_SALT_SIZE);

    let hashed_secret = &hashed_secret[ENCODED_SALT_SIZE..];
    p.hash = hashed_secret.to_vec();

    Ok(p)
}

fn bcrypt(password: &[u8], cost: u32, salt: &[u8]) -> Result<Vec<u8>, BcryptError> {
    let mut cipher_data = MAGIC_CIPHER_DATA.to_vec();

    let c = expensive_blowfish_setup(password, cost, salt)?;

    for i in (0..24).step_by(8) {
        for _ in 0..64 {
            c.encrypt(&mut cipher_data[i..i + 8]);
        }
    }

    let hsh = base64_encode(&cipher_data[..MAX_CRYPTED_HASH_SIZE]);
    Ok(hsh)
}

fn expensive_blowfish_setup(
    key: &[u8],
    cost: u32,
    salt: &[u8],
) -> Result<BlowfishCipher, BcryptError> {
    let csalt = base64_decode(salt)?;

    let mut ckey = key.to_vec();
    ckey.push(0);

    let mut c =
        BlowfishCipher::new_salted(&ckey, &csalt).map_err(|_| BcryptError::InvalidCost(cost))?;

    let rounds = 1u64 << cost;
    for _ in 0..rounds {
        expand_key(&ckey, &mut c);
        expand_key(&csalt, &mut c);
    }

    Ok(c)
}

fn check_cost(cost: u32) -> Result<(), BcryptError> {
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        Err(BcryptError::InvalidCost(cost))
    } else {
        Ok(())
    }
}
