use std::time::{SystemTime, UNIX_EPOCH};

use crate::args::{ArgsX509, X509Op};
use crate::utils::pki;

pub fn run_x509(args: ArgsX509) -> anyhow::Result<()> {
    match args.op {
        X509Op::Info { input } => {
            let certificate = pki::load_certificate(&input)?;
            print!("{}", pki::certificate_report(&certificate));
        }
        X509Op::Fingerprint { input, hash } => {
            let certificate = pki::load_certificate(&input)?;
            let hash = pki::hash_from_cli(hash)?;
            let digest = certificate.fingerprint(hash)?;
            println!(
                "{} Fingerprint={}",
                pki::hash_name(hash).to_uppercase(),
                pki::colon_hex(&digest)
            );
        }
        X509Op::Verify {
            input,
            issuer,
            no_check_time,
            sm2_id,
        } => {
            let certificate = pki::load_certificate(&input)?;
            let issuer = pki::load_certificate(&issuer)?;
            let now = if no_check_time {
                None
            } else {
                Some(unix_time())
            };
            match &sm2_id {
                Some(id) => certificate.verify_with_sm2_id(&issuer, now, id.as_bytes())?,
                None => certificate.verify(&issuer, now)?,
            }
            println!("OK");
        }
        X509Op::CsrInfo { input } => {
            let csr = pki::load_csr(&input)?;
            print!("{}", pki::csr_report(&csr));
        }
        X509Op::CsrVerify { input, sm2_id } => {
            let csr = pki::load_csr(&input)?;
            let valid = match &sm2_id {
                Some(id) => csr.verify_signature_with_sm2_id(id.as_bytes())?,
                None => csr.verify_signature()?,
            };
            report(valid)?;
        }
        X509Op::CrlInfo { input } => {
            let crl = pki::load_crl(&input)?;
            print!("{}", pki::crl_report(&crl));
        }
        X509Op::CrlVerify {
            input,
            issuer,
            sm2_id,
        } => {
            let crl = pki::load_crl(&input)?;
            let issuer = pki::load_certificate(&issuer)?;
            let valid = match &sm2_id {
                Some(id) => crl.verify_signature_with_sm2_id(issuer.public_key(), id.as_bytes())?,
                None => crl.verify_signature(issuer.public_key())?,
            };
            report(valid)?;
        }
        X509Op::CrlCheck {
            input,
            issuer,
            serial,
            sm2_id,
        } => {
            let crl = pki::load_crl(&input)?;
            let issuer = pki::load_certificate(&issuer)?;
            let valid = match &sm2_id {
                Some(id) => crl.verify_signature_with_sm2_id(issuer.public_key(), id.as_bytes())?,
                None => crl.verify_signature(issuer.public_key())?,
            };
            if !valid {
                anyhow::bail!("CRL signature verification failed");
            }
            let serial = hex::decode(&serial)?;
            match crl.is_revoked(&serial) {
                Some(revoked) => {
                    println!("REVOKED ({})", pki::format_time(revoked.revocation_date));
                    std::process::exit(1);
                }
                None => println!("NOT REVOKED"),
            }
        }
    }
    Ok(())
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn report(valid: bool) -> anyhow::Result<()> {
    if valid {
        println!("OK");
        Ok(())
    } else {
        println!("FAILURE");
        std::process::exit(1);
    }
}
