use std::time::{SystemTime, UNIX_EPOCH};

use crate::args::{ArgsX509, X509Op};
use crate::utils::pki::{self, FileRng};
use crown::asn1::time::Asn1Time;
use crown::x509::extensions::{crl_number, CrlReason};
use crown::x509::{
    CertificateBuilder, CertificateList, RevokedCertificate, Store, VerifyFlags, VerifyOptions,
};

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
            trust,
            untrusted,
            crls,
            crl_check,
            crl_check_all,
            policy_check,
            explicit_policy,
            x509_strict,
            partial_chain,
            purpose,
            no_check_time,
            sm2_id,
        } => {
            let certificate = pki::load_certificate(&input)?;
            let now = if no_check_time {
                None
            } else {
                Some(unix_time())
            };
            if trust.is_empty() {
                let issuer = issuer
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--issuer or --trust is required"))?;
                let issuer = pki::load_certificate(issuer)?;
                match &sm2_id {
                    Some(id) => certificate.verify_with_sm2_id(&issuer, now, id.as_bytes())?,
                    None => certificate.verify(&issuer, now)?,
                }
                println!("OK");
                return Ok(());
            }
            let mut store = Store::new();
            for path in &trust {
                for anchor in pki::load_certificates(path)? {
                    store.add_trusted_certificate(anchor);
                }
            }
            for path in &crls {
                store.add_crl(pki::load_crl(path)?);
            }
            let mut options = VerifyOptions {
                time: now,
                purpose: pki::purpose_from_cli(purpose),
                flags: VerifyFlags {
                    crl_check,
                    crl_check_all,
                    policy_check,
                    explicit_policy,
                    inhibit_any_policy: false,
                    x509_strict,
                    partial_chain,
                },
                ..Default::default()
            };
            for path in &untrusted {
                options.untrusted.extend(pki::load_certificates(path)?);
            }
            match crown::x509::verify_certificate(&store, &certificate, &options) {
                Ok(result) => {
                    println!("OK (chain length {})", result.chain.len());
                    for (index, element) in result.chain.iter().enumerate() {
                        let role = if index == 0 {
                            "leaf"
                        } else if index + 1 == result.chain.len() {
                            "anchor"
                        } else {
                            "intermediate"
                        };
                        println!("  {role}: {}", element.subject());
                    }
                }
                Err(error) => {
                    println!("FAILURE: {} (code {})", error, error.code());
                    std::process::exit(1);
                }
            }
        }
        X509Op::SelfSign {
            key,
            key_password,
            subject,
            days,
            serial,
            sans,
            ca,
            hash,
            der,
            out,
        } => {
            let info = pki::load_private_key_info(&key, Some(&key_password))?;
            let private_key = info.decode()?;
            let name = pki::parse_name(&subject)?;
            let hash = pki::hash_from_cli(hash)?;
            let algorithm = pki::signature_algorithm_for_key(&private_key, hash)?;
            let (not_before, not_after) = validity_window(days)?;
            let mut builder = CertificateBuilder::new(
                name.clone(),
                crown::x509::SubjectPublicKeyInfo::from_public_key(&private_key.public_key()?)?,
                algorithm,
            );
            builder.issuer = name;
            builder.not_before = not_before;
            builder.not_after = not_after;
            builder.serial_number = pki::resolve_serial(serial.as_deref())?;
            builder.extensions =
                pki::issuance_extensions(&builder.subject, &private_key.public_key()?, &sans, ca)?;
            let certificate = builder.sign(&private_key, &mut FileRng)?;
            let output = if der {
                certificate.encode()
            } else {
                certificate.to_pem().into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        X509Op::Issue {
            csr,
            ca,
            ca_key,
            ca_password,
            days,
            serial,
            sans,
            is_ca,
            hash,
            der,
            out,
        } => {
            let request = pki::load_csr(&csr)?;
            let ca_certificate = pki::load_certificate(&ca)?;
            let ca_info = pki::load_private_key_info(&ca_key, Some(&ca_password))?;
            let ca_private = ca_info.decode()?;
            let hash = pki::hash_from_cli(hash)?;
            let algorithm = pki::signature_algorithm_for_key(&ca_private, hash)?;
            let (not_before, not_after) = validity_window(days)?;
            let mut builder = CertificateBuilder::from_request(&request, algorithm);
            builder.issuer = ca_certificate.subject().clone();
            builder.not_before = not_before;
            builder.not_after = not_after;
            builder.serial_number = pki::resolve_serial(serial.as_deref())?;
            let public_key = request.info().subject_public_key_info.public_key.clone();
            builder.extensions =
                pki::issuance_extensions(&builder.subject, &public_key, &sans, is_ca)?;
            let certificate = builder.sign(&ca_private, &mut FileRng)?;
            let output = if der {
                certificate.encode()
            } else {
                certificate.to_pem().into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        X509Op::Crl {
            ca,
            ca_key,
            ca_password,
            revoke,
            days,
            crl_number: number,
            hash,
            out,
        } => {
            let ca_certificate = pki::load_certificate(&ca)?;
            let ca_info = pki::load_private_key_info(&ca_key, Some(&ca_password))?;
            let ca_private = ca_info.decode()?;
            let hash = pki::hash_from_cli(hash)?;
            let algorithm = pki::signature_algorithm_for_key(&ca_private, hash)?;
            let (this_update, next_update) = validity_window(days)?;
            let mut entries = Vec::new();
            for item in &revoke {
                let (serial, reason) = match item.split_once(':') {
                    Some((serial, reason)) => (serial, Some(reason)),
                    None => (item.as_str(), None),
                };
                let serial = hex::decode(serial)?;
                let mut entry = RevokedCertificate::new(serial, this_update);
                if let Some(reason) = reason {
                    entry = entry.reason(parse_reason(reason)?);
                }
                entries.push(entry);
            }
            let mut extensions = Vec::new();
            if let Some(number) = number {
                extensions.push(crl_number(&number.to_be_bytes()));
            }
            let crl = CertificateList::build(
                ca_certificate.subject().clone(),
                this_update,
                Some(next_update),
                entries,
                extensions,
                algorithm,
                &ca_private,
                &mut FileRng,
            )?;
            pki::write_output(out.as_deref(), crl.to_pem().as_bytes())?;
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
        X509Op::AcInfo { input } => {
            let certificate = pki::load_attribute_certificate(&input)?;
            print!("{}", pki::attribute_certificate_report(&certificate));
        }
        X509Op::AcVerify {
            input,
            issuer,
            no_check_time,
        } => {
            let certificate = pki::load_attribute_certificate(&input)?;
            let issuer = pki::load_certificate(&issuer)?;
            let now = if no_check_time {
                None
            } else {
                Some(unix_time())
            };
            certificate.verify(&issuer, now)?;
            println!("OK");
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

fn validity_window(days: u64) -> anyhow::Result<(Asn1Time, Asn1Time)> {
    let now = unix_time();
    let days = i64::try_from(days).unwrap_or(i64::MAX);
    let not_before = Asn1Time::from_unix(now - 60, true);
    let not_after = Asn1Time::from_unix(now + days * 86_400, false);
    Ok((not_before, not_after))
}

fn parse_reason(text: &str) -> anyhow::Result<CrlReason> {
    Ok(match text.to_ascii_lowercase().as_str() {
        "unspecified" => CrlReason::Unspecified,
        "keycompromise" => CrlReason::KeyCompromise,
        "cacompromise" => CrlReason::CaCompromise,
        "affiliationchanged" => CrlReason::AffiliationChanged,
        "superseded" => CrlReason::Superseded,
        "cessationofoperation" => CrlReason::CessationOfOperation,
        "certificatehold" => CrlReason::CertificateHold,
        "removefromcrl" => CrlReason::RemoveFromCrl,
        "privilegewithdrawn" => CrlReason::PrivilegeWithdrawn,
        "aacompromise" => CrlReason::AaCompromise,
        other => anyhow::bail!("unknown CRL reason {other:?}"),
    })
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
