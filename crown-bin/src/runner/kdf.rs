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
        secret,
        label,
        kdf_type,
        id,
        srtp_label,
    } = args;

    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();
    let secret_bytes: Vec<u8> = match &secret {
        Some(s) => hex::decode(s)?,
        None => password_bytes.to_vec(),
    };

    let derived_key = match algorithm {
        crate::args::KdfAlgorithm::Pbkdf2 => crown::password_hash::pbkdf2::key(
            password_bytes,
            salt_bytes,
            iterations,
            length,
            crown::hash::sha256::new256,
        ),
        crate::args::KdfAlgorithm::Scrypt => {
            crown::password_hash::scrypt::key(password_bytes, salt_bytes, 14, 8, 1, length)?
        }
        crate::args::KdfAlgorithm::Argon2 => crown::password_hash::argon2::id_key(
            password_bytes,
            salt_bytes,
            iterations,
            65536,
            1,
            length as u32,
        )?,
        crate::args::KdfAlgorithm::Hkdf => {
            let prk =
                crown::kdf::hkdf::extract(crown::hash::sha256::new256, password_bytes, salt_bytes);
            let mut hkdf = crown::kdf::hkdf::expand(crown::hash::sha256::new256, &prk, &[]);
            let mut output = vec![0u8; length];
            crown::core::CoreRead::read_exact(&mut hkdf, &mut output)?;
            output
        }
        crate::args::KdfAlgorithm::Bcrypt => {
            let cost = (iterations as f64).log2().round() as u32;
            crown::password_hash::bcrypt::generate_from_password(password_bytes, cost)?
        }
        crate::args::KdfAlgorithm::Pbkdf1 => crown::kdf::pbkdf1::derive(
            crown::envelope::EvpHash::new_sha256,
            password_bytes,
            salt_bytes,
            iterations as u64,
            length,
        )?,
        crate::args::KdfAlgorithm::Tls1Prf => crown::kdf::tls1_prf::derive(
            crown::envelope::EvpHash::new_sha256_hmac,
            &secret_bytes,
            label.as_bytes(),
            length,
        )?,
        crate::args::KdfAlgorithm::Sskdf => crown::kdf::sskdf::derive_hash(
            crown::envelope::EvpHash::new_sha256,
            &secret_bytes,
            label.as_bytes(),
            length,
        )?,
        crate::args::KdfAlgorithm::SshKdf => {
            let typ = match kdf_type.chars().next().unwrap_or('A') {
                'B' | 'b' => crown::kdf::sshkdf::SshKdfType::B,
                'C' | 'c' => crown::kdf::sshkdf::SshKdfType::C,
                'D' | 'd' => crown::kdf::sshkdf::SshKdfType::D,
                'E' | 'e' => crown::kdf::sshkdf::SshKdfType::E,
                'F' | 'f' => crown::kdf::sshkdf::SshKdfType::F,
                _ => crown::kdf::sshkdf::SshKdfType::A,
            };
            // password = shared secret K, salt = exchange hash H, label = session id
            crown::kdf::sshkdf::derive(
                crown::envelope::EvpHash::new_sha256,
                &secret_bytes,
                salt_bytes,
                label.as_bytes(),
                typ,
                length,
            )?
        }
        crate::args::KdfAlgorithm::Pkcs12Kdf => crown::kdf::pkcs12kdf::derive(
            crown::envelope::EvpHash::new_sha256,
            password_bytes,
            salt_bytes,
            id,
            iterations as u64,
            length,
        )?,
        crate::args::KdfAlgorithm::SrtpKdf => {
            // password = master key, salt = master salt, label = RFC 3711 label
            crown::kdf::srtpkdf::derive_aes_cm(
                &secret_bytes,
                salt_bytes,
                &[],
                iterations,
                srtp_label,
            )?
        }
        crate::args::KdfAlgorithm::X963Kdf => crown::kdf::sskdf::x963_derive_hash(
            crown::envelope::EvpHash::new_sha256,
            &secret_bytes,
            label.as_bytes(),
            length,
        )?,
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
