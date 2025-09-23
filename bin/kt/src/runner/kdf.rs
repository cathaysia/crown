use base64::Engine;

use crate::args::ArgsKdf;

pub fn run_kdf(args: ArgsKdf) -> anyhow::Result<()> {
    let ArgsKdf {
        algorithm,
        password,
        salt,
        iterations,
        length,
        out_file,
        hex,
        base64,
    } = args;

    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();

    let derived_key = match algorithm {
        crate::args::KdfAlgorithm::Pbkdf2 => kittycrypto::password_hash::pbkdf2::key(
            password_bytes,
            salt_bytes,
            iterations,
            length,
            kittycrypto::hash::sha256::new256,
        ),
        crate::args::KdfAlgorithm::Scrypt => {
            kittycrypto::password_hash::scrypt::key(password_bytes, salt_bytes, 14, 8, 1, length)?
        }
        crate::args::KdfAlgorithm::Argon2 => kittycrypto::password_hash::argon2::id_key(
            password_bytes,
            salt_bytes,
            iterations,
            65536,
            1,
            length as u32,
        )?,
        crate::args::KdfAlgorithm::Hkdf => {
            let prk = kittycrypto::kdf::hkdf::extract(
                kittycrypto::hash::sha256::new256,
                password_bytes,
                salt_bytes,
            );
            let mut hkdf =
                kittycrypto::kdf::hkdf::expand(kittycrypto::hash::sha256::new256, &prk, &[]);
            let mut output = vec![0u8; length];
            std::io::Read::read_exact(&mut hkdf, &mut output)?;
            output
        }
        crate::args::KdfAlgorithm::Bcrypt => {
            let cost = (iterations as f64).log2().round() as u32;
            kittycrypto::password_hash::bcrypt::generate_from_password(password_bytes, cost)?
        }
    };

    let output = if hex {
        hex::encode(&derived_key)
    } else if base64 {
        base64::prelude::BASE64_STANDARD.encode(&derived_key)
    } else {
        String::from_utf8_lossy(&derived_key).to_string()
    };

    if let Some(out_file) = out_file {
        std::fs::write(out_file, output)?;
    } else {
        println!("{}", output);
    }

    Ok(())
}
