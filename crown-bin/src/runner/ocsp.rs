use crate::args::{ArgsOcsp, OcspOp};
use crate::utils::pki;
use crown::ocsp::{CertStatus, OcspRequest, OcspResponse, OcspResponseStatus};

pub fn run_ocsp(args: ArgsOcsp) -> anyhow::Result<()> {
    match args.op {
        OcspOp::Request {
            cert,
            issuer,
            hash,
            nonce,
            der,
            out,
        } => {
            let certificate = pki::load_certificate(&cert)?;
            let issuer = pki::load_certificate(&issuer)?;
            let hash = pki::hash_from_cli(hash)?;
            let mut request = OcspRequest::request_for(&certificate, &issuer, hash)?;
            if let Some(nonce) = &nonce {
                request.set_nonce(&hex::decode(nonce)?);
            }
            let output = if der {
                request.encode()
            } else {
                request.to_pem().into_bytes()
            };
            pki::write_output(out.as_deref(), &output)?;
        }
        OcspOp::Verify {
            input,
            issuer,
            cert,
            nonce,
        } => {
            let der = pki::load_der_payload(&input)?;
            let response = OcspResponse::parse(&der)?;
            if response.status != OcspResponseStatus::Successful {
                println!("Response status: {:?}", response.status);
                std::process::exit(1);
            }
            let issuer = pki::load_certificate(&issuer)?;
            if let Err(error) = response.verify(&issuer) {
                println!("Signature: FAILURE ({error})");
                std::process::exit(1);
            }
            println!("Signature: OK");
            let basic = response.basic()?;
            for single in &basic.tbs_response_data.responses {
                match &single.cert_status {
                    CertStatus::Good => {
                        println!(
                            "Status: good (thisUpdate {}, nextUpdate {})",
                            pki::format_time(single.this_update),
                            single
                                .next_update
                                .map(pki::format_time)
                                .unwrap_or_else(|| "-".to_string())
                        );
                    }
                    CertStatus::Revoked {
                        revocation_time,
                        revocation_reason,
                    } => {
                        println!(
                            "Status: revoked at {} ({})",
                            pki::format_time(*revocation_time),
                            revocation_reason
                                .map(|reason| reason.name())
                                .unwrap_or("unspecified")
                        );
                    }
                    CertStatus::Unknown => println!("Status: unknown"),
                }
                if let Some(cert) = &cert {
                    let certificate = pki::load_certificate(cert)?;
                    if !single.matches(&certificate, &issuer)? {
                        println!("CertID: does not match {cert}");
                        std::process::exit(1);
                    }
                    println!("CertID: matches {cert}");
                }
            }
            if let Some(nonce) = &nonce {
                response.check_nonce(Some(&hex::decode(nonce)?))?;
                println!("Nonce: OK");
            }
        }
        OcspOp::Info { input } => {
            let der = pki::load_der_payload(&input)?;
            let response = OcspResponse::parse(&der)?;
            println!("OCSP Response:");
            println!("    Status: {:?}", response.status);
            if let Ok(basic) = response.basic() {
                let data = &basic.tbs_response_data;
                println!("    Responder: {:?}", data.responder_id);
                println!("    Produced At: {}", pki::format_time(data.produced_at));
                println!("    Responses: {}", data.responses.len());
                for single in &data.responses {
                    println!(
                        "        Serial: {} ({:?})",
                        pki::serial_hex(&single.cert_id.serial_number),
                        single.cert_status
                    );
                }
                println!("    Certificates: {}", basic.certs.len());
                if let Ok(Some(nonce)) = response.nonce() {
                    println!("    Nonce: {}", pki::colon_hex(&nonce));
                }
            }
        }
    }
    Ok(())
}
