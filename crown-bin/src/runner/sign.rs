use crate::args::{ArgsSign, SignAlgorithm};

pub fn run_sign(args: ArgsSign) -> anyhow::Result<()> {
    let op = args.op.to_lowercase();
    match (args.algorithm, op.as_str()) {
        (SignAlgorithm::Ed25519, "keygen") => {
            let mut seed = [0u8; 32];
            getrandom_fill(&mut seed);
            let public = crown::ed25519::public_from_secret(&seed);
            println!("secret={}", hex::encode(seed));
            println!("public={}", hex::encode(public));
        }
        (SignAlgorithm::Ed25519, "sign") => {
            let sk = hex::decode(&args.key)?;
            if sk.len() != 32 {
                anyhow::bail!("Ed25519 secret key must be 32 bytes");
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&sk);
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig = crown::ed25519::sign(&secret, &msg);
            match &args.signature {
                Some(path) => std::fs::write(path, sig)?,
                None => println!("{}", hex::encode(sig)),
            }
        }
        (SignAlgorithm::Ed25519, "verify") => {
            let pk = hex::decode(&args.key)?;
            if pk.len() != 32 {
                anyhow::bail!("Ed25519 public key must be 32 bytes");
            }
            let mut public = [0u8; 32];
            public.copy_from_slice(&pk);
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig_raw = std::fs::read(args.signature.as_ref().expect("--signature required"))?;
            if sig_raw.len() != 64 {
                anyhow::bail!("Ed25519 signature must be 64 bytes");
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&sig_raw);
            let ok = crown::ed25519::verify(&public, &sig, &msg);
            println!("{}", if ok { "OK" } else { "FAILURE" });
            if !ok {
                std::process::exit(1);
            }
        }
        (SignAlgorithm::Ed448, "keygen") => {
            let mut seed = [0u8; 57];
            getrandom_fill(&mut seed);
            let public = crown::ed448::public_from_secret(&seed);
            println!("secret={}", hex::encode(seed));
            println!("public={}", hex::encode(public));
        }
        (SignAlgorithm::Ed448, "sign") => {
            let sk = hex::decode(&args.key)?;
            if sk.len() != 57 {
                anyhow::bail!("Ed448 secret key must be 57 bytes");
            }
            let mut secret = [0u8; 57];
            secret.copy_from_slice(&sk);
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig = crown::ed448::sign(&secret, &msg, b"");
            match &args.signature {
                Some(path) => std::fs::write(path, sig)?,
                None => println!("{}", hex::encode(sig)),
            }
        }
        (SignAlgorithm::Ed448, "verify") => {
            let pk = hex::decode(&args.key)?;
            if pk.len() != 57 {
                anyhow::bail!("Ed448 public key must be 57 bytes");
            }
            let mut public = [0u8; 57];
            public.copy_from_slice(&pk);
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig_raw = std::fs::read(args.signature.as_ref().expect("--signature required"))?;
            if sig_raw.len() != 114 {
                anyhow::bail!("Ed448 signature must be 114 bytes");
            }
            let mut sig = [0u8; 114];
            sig.copy_from_slice(&sig_raw);
            let ok = crown::ed448::verify(&public, &sig, &msg, b"");
            println!("{}", if ok { "OK" } else { "FAILURE" });
            if !ok {
                std::process::exit(1);
            }
        }
        (SignAlgorithm::MlDsa44 | SignAlgorithm::MlDsa65 | SignAlgorithm::MlDsa87, "keygen") => {
            use crown::ml_dsa::{keygen, MlDsaVariant};
            let variant = match args.algorithm {
                SignAlgorithm::MlDsa44 => MlDsaVariant::MlDsa44,
                SignAlgorithm::MlDsa65 => MlDsaVariant::MlDsa65,
                _ => MlDsaVariant::MlDsa87,
            };
            let mut seed = [0u8; 32];
            getrandom_fill(&mut seed);
            let (pk, sk) = keygen(variant, &seed)?;
            println!("seed={}", hex::encode(seed));
            println!("public={}", hex::encode(pk.to_bytes()));
            println!("secret={}", hex::encode(sk.to_bytes()));
        }
        (SignAlgorithm::MlDsa44 | SignAlgorithm::MlDsa65 | SignAlgorithm::MlDsa87, "sign") => {
            use crown::ml_dsa::{sign, MlDsaPrivateKey, MlDsaVariant};
            let variant = match args.algorithm {
                SignAlgorithm::MlDsa44 => MlDsaVariant::MlDsa44,
                SignAlgorithm::MlDsa65 => MlDsaVariant::MlDsa65,
                _ => MlDsaVariant::MlDsa87,
            };
            let sk_bytes = hex::decode(&args.key)?;
            let sk = MlDsaPrivateKey::from_bytes(variant, &sk_bytes)?;
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig = sign(&sk, &msg, b"", None)?;
            match &args.signature {
                Some(path) => std::fs::write(path, sig)?,
                None => println!("{}", hex::encode(sig)),
            }
        }
        (SignAlgorithm::MlDsa44 | SignAlgorithm::MlDsa65 | SignAlgorithm::MlDsa87, "verify") => {
            use crown::ml_dsa::{verify, MlDsaPublicKey, MlDsaVariant};
            let variant = match args.algorithm {
                SignAlgorithm::MlDsa44 => MlDsaVariant::MlDsa44,
                SignAlgorithm::MlDsa65 => MlDsaVariant::MlDsa65,
                _ => MlDsaVariant::MlDsa87,
            };
            let pk_bytes = hex::decode(&args.key)?;
            let pk = MlDsaPublicKey::from_bytes(variant, &pk_bytes)?;
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig = std::fs::read(args.signature.as_ref().expect("--signature required"))?;
            let ok = verify(&pk, &msg, b"", &sig)?;
            println!("{}", if ok { "OK" } else { "FAILURE" });
            if !ok {
                std::process::exit(1);
            }
        }
        (
            SignAlgorithm::SlhDsaSha2128s
            | SignAlgorithm::SlhDsaSha2128f
            | SignAlgorithm::SlhDsaShake128s
            | SignAlgorithm::SlhDsaShake128f,
            "keygen",
        ) => {
            use crown::slh_dsa::keygen;
            let variant = slh_variant(args.algorithm);
            let mut seed = [0u8; 48]; // 3n for n=16
            getrandom_fill(&mut seed);
            let (pk, sk) = keygen(variant, &seed)?;
            println!("seed={}", hex::encode(seed));
            println!("public={}", hex::encode(pk.to_bytes()));
            println!("secret={}", hex::encode(sk.to_bytes()));
        }
        (
            SignAlgorithm::SlhDsaSha2128s
            | SignAlgorithm::SlhDsaSha2128f
            | SignAlgorithm::SlhDsaShake128s
            | SignAlgorithm::SlhDsaShake128f,
            "sign",
        ) => {
            use crown::slh_dsa::{sign, SlhDsaPrivateKey};
            let variant = slh_variant(args.algorithm);
            let sk_bytes = hex::decode(&args.key)?;
            let sk = SlhDsaPrivateKey::from_bytes(variant, &sk_bytes)?;
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig = sign(&sk, &msg, b"", false)?;
            match &args.signature {
                Some(path) => std::fs::write(path, sig)?,
                None => println!("{}", hex::encode(sig)),
            }
        }
        (
            SignAlgorithm::SlhDsaSha2128s
            | SignAlgorithm::SlhDsaSha2128f
            | SignAlgorithm::SlhDsaShake128s
            | SignAlgorithm::SlhDsaShake128f,
            "verify",
        ) => {
            use crown::slh_dsa::{verify, SlhDsaPublicKey};
            let variant = slh_variant(args.algorithm);
            let pk_bytes = hex::decode(&args.key)?;
            let pk = SlhDsaPublicKey::from_bytes(variant, &pk_bytes)?;
            let msg = std::fs::read(args.input.as_ref().expect("--input required"))?;
            let sig = std::fs::read(args.signature.as_ref().expect("--signature required"))?;
            let ok = verify(&pk, &msg, b"", &sig, false)?;
            println!("{}", if ok { "OK" } else { "FAILURE" });
            if !ok {
                std::process::exit(1);
            }
        }
        _ => anyhow::bail!("unsupported algorithm/op"),
    }
    Ok(())
}

fn slh_variant(a: crate::args::SignAlgorithm) -> crown::slh_dsa::SlhDsaVariant {
    use crown::slh_dsa::SlhDsaVariant;
    match a {
        crate::args::SignAlgorithm::SlhDsaSha2128s => SlhDsaVariant::Sha2_128s,
        crate::args::SignAlgorithm::SlhDsaSha2128f => SlhDsaVariant::Sha2_128f,
        crate::args::SignAlgorithm::SlhDsaShake128s => SlhDsaVariant::Shake_128s,
        _ => SlhDsaVariant::Shake_128f,
    }
}

fn getrandom_fill(buf: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .expect("failed to read /dev/urandom");
}
