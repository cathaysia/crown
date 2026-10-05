use crate::args::{ArgsPkey, PkeyOp};
use crate::utils::pki::{self, FileRng};
use crown::asn1::pem;
use crown::x509::{pbe, SubjectPublicKeyInfo};

pub fn run_pkey(args: ArgsPkey) -> anyhow::Result<()> {
    match args.op {
        PkeyOp::Info { input, password } => {
            let info = pki::load_private_key_info(&input, Some(&password))?;
            println!("Private Key Algorithm: {}", info.algorithm.oid);
            match info.decode() {
                Ok(private_key) => {
                    println!("Private Key Type: {private_key:?}");
                    let public_key = private_key.public_key()?;
                    println!(
                        "Public Key Algorithm: {}",
                        pki::public_key_text(&public_key)
                    );
                    let spki = SubjectPublicKeyInfo::from_public_key(&public_key)?;
                    println!("Public Key: {}", pki::colon_hex(&spki.key));
                }
                Err(error) => println!("Private Key Type: (unsupported: {error})"),
            }
        }
        PkeyOp::Decrypt {
            input,
            password,
            der,
            out,
        } => {
            let info = pki::load_private_key_info(&input, Some(&password))?;
            let encoded = info.encode();
            let output = if der {
                encoded
            } else {
                pem::encode("PRIVATE KEY", &encoded).into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        PkeyOp::Encrypt {
            input,
            password,
            cipher,
            iterations,
            der,
            out,
        } => {
            let info = pki::load_private_key_info(&input, None)?;
            let encrypted = pbe::encrypt_private_key(
                &info.encode(),
                password.as_bytes(),
                pki::pbes2_cipher(cipher),
                iterations,
                &mut FileRng,
            )?;
            let encoded = encrypted.encode();
            let output = if der {
                encoded
            } else {
                pem::encode("ENCRYPTED PRIVATE KEY", &encoded).into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        PkeyOp::Pubout {
            input,
            password,
            der,
            out,
        } => {
            let info = pki::load_private_key_info(&input, Some(&password))?;
            let public_key = info.decode()?.public_key()?;
            let spki = SubjectPublicKeyInfo::from_public_key(&public_key)?;
            let encoded = spki.encode();
            let output = if der {
                encoded
            } else {
                pem::encode("PUBLIC KEY", &encoded).into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
    }
    Ok(())
}
