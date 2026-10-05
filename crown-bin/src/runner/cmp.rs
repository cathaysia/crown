use crate::args::{ArgsCmp, ArgsCrmf, CmpOp, CrmfOp};
use crate::utils::pki;
use crown::cmp::{PkiBody, PkiMessage, PkiStatusInfo};
use crown::crmf::{CertReqMessages, ProofOfPossession};

pub fn run_cmp(args: ArgsCmp) -> anyhow::Result<()> {
    match args.op {
        CmpOp::Info { input } => {
            let message = PkiMessage::parse(&pki::load_der_payload(&input)?)?;
            print!("{}", message_report(&message));
            Ok(())
        }
        CmpOp::Verify { input, password } => {
            let message = PkiMessage::parse(&pki::load_der_payload(&input)?)?;
            let valid = match &password {
                Some(password) => message.verify_password(password.as_bytes())?,
                None => message.verify_signature()?,
            };
            if valid {
                println!("OK");
                Ok(())
            } else {
                println!("FAILURE");
                std::process::exit(1);
            }
        }
    }
}

pub fn run_crmf(args: ArgsCrmf) -> anyhow::Result<()> {
    match args.op {
        CrmfOp::Info { input } => {
            let der = pki::load_der_payload(&input)?;
            // Accept a bare CertReqMessages or a CMP message carrying one.
            let messages = match CertReqMessages::parse(&der) {
                Ok(messages) => messages,
                Err(error) => match PkiMessage::parse(&der) {
                    Ok(message) => match message.body {
                        PkiBody::Ir(messages)
                        | PkiBody::Cr(messages)
                        | PkiBody::Kur(messages)
                        | PkiBody::Ccr(messages) => messages,
                        _ => return Err(error.into()),
                    },
                    Err(_) => return Err(error.into()),
                },
            };
            println!("CRMF CertReqMessages: {}", messages.messages.len());
            for (index, message) in messages.messages.iter().enumerate() {
                let template = &message.cert_req.cert_template;
                println!(
                    "    Message {}: certReqId {}",
                    index + 1,
                    pki::serial_hex(&message.cert_req.cert_req_id)
                );
                if let Some(subject) = &template.subject {
                    println!("        Subject: {subject}");
                }
                if let Some(issuer) = &template.issuer {
                    println!("        Issuer: {issuer}");
                }
                if let Some(public_key) = &template.public_key {
                    println!(
                        "        Public Key: {}",
                        pki::public_key_text(&public_key.public_key)
                    );
                }
                println!(
                    "        Proof of Possession: {}",
                    match &message.popo {
                        None => "none",
                        Some(ProofOfPossession::RaVerified) => "raVerified",
                        Some(ProofOfPossession::Signature(_)) => "signature",
                        Some(ProofOfPossession::KeyEncipherment(_)) => "keyEncipherment",
                        Some(ProofOfPossession::KeyAgreement(_)) => "keyAgreement",
                    }
                );
                if !template.extensions.is_empty() {
                    println!("        Extensions: {}", template.extensions.len());
                }
                if !message.reg_info.is_empty() {
                    println!("        Registration Info: {}", message.reg_info.len());
                }
            }
        }
    }
    Ok(())
}

fn message_report(message: &PkiMessage) -> String {
    use std::fmt::Write as _;
    let header = &message.header;
    let mut out = String::new();
    let _ = writeln!(out, "CMP Message:");
    let _ = writeln!(out, "    Version: {}", header.pvno);
    let _ = writeln!(
        out,
        "    Sender: {}",
        pki::general_name_text(&header.sender)
    );
    let _ = writeln!(
        out,
        "    Recipient: {}",
        pki::general_name_text(&header.recipient)
    );
    if let Some(time) = header.message_time {
        let _ = writeln!(out, "    Message Time: {}", pki::format_time(time));
    }
    let _ = writeln!(
        out,
        "    Protection Algorithm: {}",
        message
            .protection
            .as_ref()
            .map(|protection| protection.alg_id.oid.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    if let Some(kid) = &header.sender_kid {
        let _ = writeln!(out, "    Sender KID: {}", pki::colon_hex(kid));
    }
    if let Some(transaction) = &header.transaction_id {
        let _ = writeln!(out, "    Transaction ID: {}", pki::colon_hex(transaction));
    }
    if let Some(nonce) = &header.sender_nonce {
        let _ = writeln!(out, "    Sender Nonce: {}", pki::colon_hex(nonce));
    }
    if let Some(text) = &header.free_text {
        let _ = writeln!(out, "    Free Text: {text}");
    }
    let _ = writeln!(
        out,
        "    General Info: {}",
        header
            .general_info
            .iter()
            .map(|info| info.info_type.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(out, "    Body: {}", body_name(&message.body));
    match &message.body {
        PkiBody::Ir(messages)
        | PkiBody::Cr(messages)
        | PkiBody::Kur(messages)
        | PkiBody::Ccr(messages) => {
            let _ = writeln!(out, "        Requests: {}", messages.messages.len());
        }
        PkiBody::Error(content) => {
            let _ = write!(out, "{}", status_text(&content.pki_status_info));
        }
        PkiBody::CertConf(content) => {
            let _ = writeln!(
                out,
                "        Confirmed Certificates: {}",
                content.statuses.len()
            );
        }
        PkiBody::Genp(content) => {
            let _ = writeln!(out, "        Responses: {}", content.values.len());
        }
        PkiBody::Genm(content) => {
            let _ = writeln!(out, "        Info Types: {}", content.values.len());
        }
        _ => {}
    }
    let _ = writeln!(out, "    Extra Certificates: {}", message.extra_certs.len());
    for certificate in &message.extra_certs {
        let _ = writeln!(out, "        Subject: {}", certificate.subject());
    }
    out
}

fn body_name(body: &PkiBody) -> &'static str {
    match body {
        PkiBody::Ir(_) => "ir",
        PkiBody::Cr(_) => "cr",
        PkiBody::P10Cr(_) => "p10cr",
        PkiBody::Kur(_) => "kur",
        PkiBody::Rr(_) => "rr",
        PkiBody::Ccr(_) => "ccr",
        PkiBody::Pkiconf => "pkiconf",
        PkiBody::Genm(_) => "genm",
        PkiBody::Genp(_) => "genp",
        PkiBody::Error(_) => "error",
        PkiBody::CertConf(_) => "certConf",
        PkiBody::PollReq(_) => "pollReq",
        PkiBody::PollRep(_) => "pollRep",
        PkiBody::Other { .. } => "other",
    }
}

fn status_text(status: &PkiStatusInfo) -> String {
    let mut out = format!(
        "        Status: {} ({})\n",
        status.status,
        crown::cmp::pki_status_name(status.status)
    );
    for text in &status.status_string {
        out.push_str(&format!("        Status String: {text}\n"));
    }
    out
}
