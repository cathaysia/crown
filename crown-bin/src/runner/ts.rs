use crate::args::{ArgsTs, TsOp};
use crate::utils::pki::{self, FileRng};
use crown::asn1::oid::ObjectIdentifier;
use crown::asn1::time::Asn1Time;
use crown::rng::Rng;
use crown::ts::{TimeStampReq, TimeStampResp, TimeStampSigner};

pub fn run_ts(args: ArgsTs) -> anyhow::Result<()> {
    match args.op {
        TsOp::Request {
            data,
            hash,
            cert_req,
            nonce,
            no_nonce,
            der,
            out,
        } => {
            let content = std::fs::read(&data)?;
            let hash = pki::hash_from_cli(hash)?;
            let mut request = TimeStampReq::for_data(&content, hash, cert_req)?;
            if !no_nonce {
                request.nonce = Some(match &nonce {
                    Some(nonce) => hex::decode(nonce)?,
                    None => {
                        let mut random = vec![0u8; 8];
                        FileRng.fill_bytes(&mut random);
                        random[0] &= 0x7f;
                        random
                    }
                });
            }
            let output = if der {
                request.encode()
            } else {
                request.to_pem().into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        TsOp::Reply {
            query,
            signer,
            key,
            key_password,
            chain,
            policy,
            serial,
            der,
            out,
        } => {
            let der_query = pki::load_der_payload(&query)?;
            let request = TimeStampReq::parse(&der_query)?;
            let certificate = pki::load_certificate(&signer)?;
            let info = pki::load_private_key_info(&key, Some(&key_password))?;
            let private_key = info.decode()?;
            let hash = pki::hash_from_cli(crate::args::HashAlgorithm::Sha256)?;
            let algorithm = pki::default_signature_algorithm(&private_key, hash)?;
            let mut chain_certificates = Vec::new();
            for path in &chain {
                chain_certificates.extend(pki::load_certificates(path)?);
            }
            let signer =
                TimeStampSigner::new(certificate, private_key, chain_certificates, algorithm);
            let policy = ObjectIdentifier::from_dotted_string(&policy)?;
            let serial = pki::resolve_serial(serial.as_deref())?;
            let response = signer.reply(
                &request,
                policy,
                &serial,
                Asn1Time::from_unix(unix_time(), false),
                None,
                &mut FileRng,
            )?;
            let output = if der {
                response.encode()
            } else {
                response.to_pem().into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        TsOp::Verify {
            input,
            tsa,
            query,
            data,
        } => {
            let der = pki::load_der_payload(&input)?;
            let response = TimeStampResp::parse(&der)?;
            let tsa = pki::load_certificate(&tsa)?;
            let info = match &query {
                Some(query) => {
                    let request = TimeStampReq::parse(&pki::load_der_payload(query)?)?;
                    response.verify_request(&tsa, &request)?
                }
                None => response.verify(&tsa)?,
            };
            println!("Signature: OK");
            println!("Policy: {}", info.policy);
            println!("Serial: {}", pki::serial_hex(&info.serial_number));
            println!("Generated At: {}", pki::format_time(info.gen_time));
            if let Some(data) = &data {
                let content = std::fs::read(data)?;
                if !info.message_imprint.matches(&content)? {
                    anyhow::bail!("message imprint does not match {data}");
                }
                println!("Message Imprint: OK");
            }
            if let Some(nonce) = &info.nonce {
                println!("Nonce: {}", pki::colon_hex(nonce));
            }
        }
        TsOp::Info { input } => {
            let der = pki::load_der_payload(&input)?;
            let response = TimeStampResp::parse(&der)?;
            println!("Timestamp Response:");
            println!("    Status: {}", response.status.status);
            for text in &response.status.status_string {
                println!("    Status String: {text}");
            }
            match response.basic() {
                Ok(info) => {
                    println!("    Policy: {}", info.policy);
                    println!("    Serial: {}", pki::serial_hex(&info.serial_number));
                    println!("    Generated At: {}", pki::format_time(info.gen_time));
                    println!("    Version: {}", info.version);
                    if let Some(tsa) = &info.tsa {
                        println!("    TSA: {}", pki::general_name_text(tsa));
                    }
                    if let Some(nonce) = &info.nonce {
                        println!("    Nonce: {}", pki::colon_hex(nonce));
                    }
                }
                Err(error) => println!("    (no basic token: {error})"),
            }
        }
    }
    Ok(())
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
