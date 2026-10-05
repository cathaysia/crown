use std::fmt::Write as _;

use crate::args::{ArgsPkcs12, Pkcs12Op};
use crate::utils::pki::{self, FileRng};
use crown::asn1::pem;
use crown::pkcs12::{Bag, Pfx, SafeBag};
use crown::x509::pbe;
use crown::x509::{Certificate, PrivateKeyInfo};

pub fn run_pkcs12(args: ArgsPkcs12) -> anyhow::Result<()> {
    match args.op {
        Pkcs12Op::Info { input, password } => {
            let pfx = load_pfx(&input)?;
            print!("{}", report(&pfx, password.as_bytes())?);
        }
        Pkcs12Op::Verify { input, password } => {
            let pfx = load_pfx(&input)?;
            match &pfx.mac {
                Some(_) => match pfx.verify_mac(password.as_bytes()) {
                    Ok(()) => println!("MAC: OK"),
                    Err(error) => {
                        println!("MAC: FAILURE ({error})");
                        std::process::exit(1);
                    }
                },
                None => println!("MAC: (none present)"),
            }
        }
        Pkcs12Op::Export {
            key,
            key_password,
            cert,
            chain,
            name,
            iterations,
            password,
            pem: pem_output,
            out,
        } => {
            let key_password = key_password.as_deref().unwrap_or(&password);
            let key_info =
                pki::load_private_key_info(&key, Some(key_password)).map_err(|error| {
                    anyhow::anyhow!("{error} (use --key-password for an encrypted key)")
                })?;
            let certificate = pki::load_certificate(&cert)?;
            let key_id = certificate.subject_public_key_info().key_identifier()?;
            let mut rng = FileRng;
            let mut bags = vec![Pfx::shrouded_key_bag(
                &key_info,
                password.as_bytes(),
                name.as_deref(),
                &key_id,
                iterations,
                &mut rng,
            )?];
            bags.push(Pfx::certificate_bag(&certificate, name.as_deref(), &key_id));
            for chain_path in &chain {
                for chained in pki::load_certificates(chain_path)? {
                    bags.push(Pfx::certificate_bag(&chained, None, &[]));
                }
            }
            let pfx = Pfx::build(bags, password.as_bytes(), iterations, &mut rng)?;
            let output = if pem_output {
                pfx.to_pem().into_bytes()
            } else {
                pfx.encode()
            };
            std::fs::write(&out, &output)?;
            println!("wrote {out} ({} bytes)", output.len());
        }
        Pkcs12Op::Extract {
            input,
            password,
            key,
            cert,
            chain,
        } => {
            let pfx = load_pfx(&input)?;
            if pfx.mac.is_some() {
                pfx.verify_mac(password.as_bytes())?;
            }
            let mut keys = Vec::new();
            let mut certificates = Vec::new();
            collect_bags(
                &pfx.decoded_bags(password.as_bytes())?,
                password.as_bytes(),
                &mut keys,
                &mut certificates,
            )?;
            let mut wrote = false;
            if let Some(path) = key {
                let info = keys
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("no private key found in PFX"))?;
                std::fs::write(&path, pem::encode("PRIVATE KEY", &info.encode()))?;
                println!("wrote key to {path}");
                wrote = true;
            }
            if let Some(path) = cert {
                let certificate = certificates
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("no certificate found in PFX"))?;
                std::fs::write(&path, certificate.to_pem())?;
                println!("wrote certificate to {path}");
                wrote = true;
            }
            if let Some(path) = chain {
                let mut text = String::new();
                for certificate in certificates.iter().skip(1) {
                    text.push_str(&certificate.to_pem());
                }
                std::fs::write(&path, text)?;
                println!(
                    "wrote {} chain certificate(s) to {path}",
                    certificates.len().saturating_sub(1)
                );
                wrote = true;
            }
            if !wrote {
                print!("{}", report(&pfx, password.as_bytes())?);
            }
        }
    }
    Ok(())
}

fn load_pfx(path: &str) -> anyhow::Result<Pfx> {
    let bytes = std::fs::read(path)?;
    if bytes.windows(11).any(|window| window == b"-----BEGIN ") {
        Ok(Pfx::from_pem(&String::from_utf8_lossy(&bytes))?)
    } else {
        Ok(Pfx::parse(&bytes)?)
    }
}

fn collect_bags(
    bags: &[SafeBag],
    password: &[u8],
    keys: &mut Vec<PrivateKeyInfo>,
    certificates: &mut Vec<Certificate>,
) -> anyhow::Result<()> {
    for bag in bags {
        match &bag.bag {
            Bag::Key(info) => keys.push(info.clone()),
            Bag::ShroudedKey(encrypted) => {
                keys.push(pbe::decrypt_private_key(encrypted, password)?)
            }
            Bag::Cert(certificate) => certificates.push(certificate.clone()),
            Bag::SafeContents(inner) => collect_bags(inner, password, keys, certificates)?,
            _ => {}
        }
    }
    Ok(())
}

fn bag_description(bag: &SafeBag) -> String {
    let attributes = {
        let mut parts = Vec::new();
        if let Some(name) = bag.friendly_name() {
            parts.push(format!("friendlyName={name:?}"));
        }
        if let Some(key_id) = bag.local_key_id() {
            parts.push(format!("localKeyId={}", pki::colon_hex(&key_id)));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!(" [{}]", parts.join(", "))
        }
    };
    let body = match &bag.bag {
        Bag::Key(info) => format!("key ({}){attributes}", info.algorithm.oid),
        Bag::ShroudedKey(encrypted) => {
            format!("shrouded key ({}){attributes}", encrypted.algorithm.oid)
        }
        Bag::Cert(certificate) => format!(
            "cert{attributes}\n        Subject: {}",
            certificate.subject()
        ),
        Bag::Crl(crl) => format!("crl{attributes}\n        Issuer: {}", crl.tbs().issuer),
        Bag::Secret { oid, .. } => format!("secret ({oid}){attributes}"),
        Bag::SafeContents(inner) => format!("safeContents ({}){attributes}", inner.len()),
        Bag::Other { oid, .. } => format!("other ({oid}){attributes}"),
    };
    body
}

fn report(pfx: &Pfx, password: &[u8]) -> anyhow::Result<String> {
    let mut out = String::new();
    let _ = writeln!(out, "PKCS#12 PFX:");
    let _ = writeln!(out, "    Version: {}", pfx.version);
    match &pfx.mac {
        Some(mac) => match pfx.verify_mac(password) {
            Ok(()) => {
                let _ = writeln!(out, "    MAC: OK (iterations {})", mac.iterations);
            }
            Err(error) => {
                let _ = writeln!(out, "    MAC: FAILURE ({error})");
            }
        },
        None => {
            let _ = writeln!(out, "    MAC: (none present)");
        }
    }
    let bags = pfx.decoded_bags(password)?;
    let _ = writeln!(out, "    Bags: {}", bags.len());
    for (index, bag) in bags.iter().enumerate() {
        let _ = writeln!(out, "        Bag {}: {}", index + 1, bag_description(bag));
    }
    Ok(out)
}
