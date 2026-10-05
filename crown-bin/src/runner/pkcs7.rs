use std::fmt::Write as _;

use crate::args::{ArgsPkcs7, Pkcs7Op};
use crate::utils::pki::{self, FileRng};
use crown::asn1::pem;
use crown::pkcs7::{Pkcs7, SignedData, SignedDataBuilder, SignerIdentifier};
use crown::x509::Hash;

pub fn run_pkcs7(args: ArgsPkcs7) -> anyhow::Result<()> {
    match args.op {
        Pkcs7Op::Encrypt {
            input,
            recipients,
            password,
            cipher,
            iterations,
            der,
            out,
        } => run_encrypt(
            input,
            recipients,
            password,
            Some(cipher),
            iterations,
            der,
            out,
        )?,
        Pkcs7Op::Decrypt {
            input,
            key,
            key_password,
            cert,
            password,
            out,
        } => run_decrypt(input, key, key_password, cert, password, out)?,
        Pkcs7Op::Info { input } => {
            let der = pki::load_der_payload(&input)?;
            match Pkcs7::parse(&der)? {
                Pkcs7::SignedData(data) => print!("{}", report(&data)),
                Pkcs7::Data(content) => println!("PKCS#7 Data ({} bytes)", content.len()),
                Pkcs7::Other(info) => {
                    println!("PKCS#7 ContentInfo: content type {}", info.content_type);
                }
            }
        }
        Pkcs7Op::Sign {
            input,
            key,
            password,
            cert,
            chain,
            detached,
            hash,
            der,
            out,
            sm2_id,
        } => {
            let content = std::fs::read(&input)?;
            let key_info = pki::load_private_key_info(&key, password.as_deref())?;
            let private_key = key_info.decode()?;
            let certificate = pki::load_certificate(&cert)?;
            let hash = pki::hash_from_cli(hash)?;
            let algorithm = pki::default_signature_algorithm(&private_key, hash)?;
            let mut builder = if detached {
                SignedDataBuilder::detached(content)
            } else {
                SignedDataBuilder::new(content)
            };
            builder = builder.add_certificate(certificate.clone());
            for chain_path in &chain {
                for chained in pki::load_certificates(chain_path)? {
                    builder = builder.add_certificate(chained);
                }
            }
            let mut rng = FileRng;
            let signed = match &sm2_id {
                Some(id) => builder.sign_with_sm2_id(
                    &private_key,
                    &certificate,
                    hash,
                    algorithm,
                    id.as_bytes(),
                    &mut rng,
                )?,
                None => builder.sign(&private_key, &certificate, hash, algorithm, &mut rng)?,
            };
            let encoded = signed.to_content_info().encode();
            let output = if der {
                encoded
            } else {
                pem::encode("CMS", &encoded).into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        Pkcs7Op::Verify {
            input,
            content,
            sm2_id,
        } => {
            let der = pki::load_der_payload(&input)?;
            let detached = match &content {
                Some(path) => Some(std::fs::read(path)?),
                None => None,
            };
            let Pkcs7::SignedData(data) = Pkcs7::parse(&der)? else {
                anyhow::bail!("not a CMS SignedData object");
            };
            match &sm2_id {
                Some(id) => data.verify_with_sm2_id(detached.as_deref(), id.as_bytes())?,
                None => data.verify(detached.as_deref())?,
            }
            println!("OK");
            println!("Signers: {}", data.signer_infos.len());
            println!("Certificates: {}", data.certificates.len());
        }
        Pkcs7Op::Extract { input, out } => {
            let der = pki::load_der_payload(&input)?;
            let content = match Pkcs7::parse(&der)? {
                Pkcs7::SignedData(data) => data.content(None)?.to_vec(),
                Pkcs7::Data(content) => content,
                Pkcs7::Other(_) => anyhow::bail!("no encapsulated content"),
            };
            std::fs::write(&out, &content)?;
            println!("wrote {out} ({} bytes)", content.len());
        }
    }
    Ok(())
}

fn digest_name(algorithm: &crown::x509::AlgorithmIdentifier) -> String {
    match Hash::from_oid(&algorithm.oid) {
        Some(hash) => pki::hash_name(hash).to_string(),
        None => algorithm.oid.to_string(),
    }
}

fn report(data: &SignedData) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "CMS SignedData:");
    let _ = writeln!(out, "    Version: {}", data.version);
    let digests: Vec<String> = data.digest_algorithms.iter().map(digest_name).collect();
    let _ = writeln!(out, "    Digest Algorithms: {}", digests.join(", "));
    let encap = &data.encap_content_info;
    match &encap.content {
        Some(content) => {
            let _ = writeln!(
                out,
                "    Encapsulated Content: {} (attached, {} bytes)",
                encap.content_type,
                content.len()
            );
        }
        None => {
            let _ = writeln!(
                out,
                "    Encapsulated Content: {} (detached)",
                encap.content_type
            );
        }
    }
    let _ = writeln!(out, "    Certificates: {}", data.certificates.len());
    for certificate in &data.certificates {
        let _ = writeln!(out, "        Subject: {}", certificate.subject());
    }
    let _ = writeln!(out, "    Signers: {}", data.signer_infos.len());
    for (index, signer) in data.signer_infos.iter().enumerate() {
        let _ = writeln!(out, "        Signer {}:", index + 1);
        let _ = writeln!(
            out,
            "            Digest Algorithm: {}",
            digest_name(&signer.digest_algorithm)
        );
        let _ = writeln!(
            out,
            "            Signature Algorithm: {}",
            pki::signature_algorithm_name_with_digest(
                &signer.signature_algorithm,
                Some(&signer.digest_algorithm)
            )
        );
        match &signer.sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer,
                serial_number,
            } => {
                let _ = writeln!(out, "            Issuer: {issuer}");
                let _ = writeln!(
                    out,
                    "            Serial Number: {}",
                    pki::serial_hex(serial_number)
                );
            }
            SignerIdentifier::SubjectKeyIdentifier(key_id) => {
                let _ = writeln!(
                    out,
                    "            Subject Key Identifier: {}",
                    pki::colon_hex(key_id)
                );
            }
        }
        match &signer.signed_attrs {
            Some(attributes) => {
                let _ = writeln!(
                    out,
                    "            Signed Attributes: {} present",
                    attributes.len()
                );
            }
            None => {
                let _ = writeln!(out, "            Signed Attributes: (none)");
            }
        }
    }
    out
}

fn run_encrypt(
    input: String,
    recipients: Vec<String>,
    password: Option<String>,
    cipher: Option<crate::args::CmsCipher>,
    iterations: u32,
    der: bool,
    out: Option<String>,
) -> anyhow::Result<()> {
    use crown::cms::EnvelopedDataBuilder;
    let content = std::fs::read(&input)?;
    let mut builder = EnvelopedDataBuilder::new(content);
    let cipher = cipher.map(pki::cms_cipher_from_cli);
    for path in &recipients {
        let certificate = pki::load_certificate(path)?;
        let cipher = cipher.unwrap_or(crown::cms::Cipher::Aes256Cbc);
        builder = builder.add_rsa_recipient(&certificate, cipher, &mut FileRng);
    }
    if let Some(password) = &password {
        let cipher = cipher.unwrap_or(crown::cms::Cipher::Aes256Cbc);
        builder = builder.add_password_recipient(password.as_bytes(), cipher, iterations);
    }
    if recipients.is_empty() && password.is_none() {
        anyhow::bail!("--recip or --password is required");
    }
    let enveloped = builder.build(&mut FileRng)?;
    let encoded = enveloped.to_content_info().encode();
    let output = if der {
        encoded
    } else {
        pem::encode("CMS", &encoded).into_bytes()
    };
    pki::write_output(out.as_deref(), &output)
}

fn run_decrypt(
    input: String,
    key: Option<String>,
    key_password: Option<String>,
    cert: Option<String>,
    password: Option<String>,
    out: Option<String>,
) -> anyhow::Result<()> {
    use crown::cms::EnvelopedData;
    let der = pki::load_der_payload(&input)?;
    let content_info = crown::pkcs7::ContentInfo::parse(&der)?;
    let enveloped = EnvelopedData::from_content_info(&content_info)?;
    let plaintext = if let Some(password) = &password {
        enveloped.decrypt_with_password(password.as_bytes())?
    } else {
        let (Some(key), Some(cert)) = (key.as_deref(), cert.as_deref()) else {
            anyhow::bail!("--key and --cert, or --password, are required");
        };
        let info = pki::load_private_key_info(key, key_password.as_deref())?;
        let private_key = info.decode()?;
        let certificate = pki::load_certificate(cert)?;
        enveloped.decrypt_with_key(&private_key, &certificate)?
    };
    pki::write_output(out.as_deref(), &plaintext)
}
