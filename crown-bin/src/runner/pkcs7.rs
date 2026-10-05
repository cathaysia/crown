use std::fmt::Write as _;

use crate::args::{ArgsPkcs7, Pkcs7Op};
use crate::utils::pki::{self, FileRng};
use crown::asn1::pem;
use crown::pkcs7::{Pkcs7, SignedData, SignedDataBuilder, SignerIdentifier};
use crown::x509::Hash;

pub fn run_pkcs7(args: ArgsPkcs7) -> anyhow::Result<()> {
    match args.op {
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
