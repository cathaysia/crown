use crate::args::{ArgsKem, KemAlgorithm};

fn variant_of(a: KemAlgorithm) -> crown::ml_kem::MlKemVariant {
    match a {
        KemAlgorithm::MlKem512 => crown::ml_kem::MlKemVariant::MlKem512,
        KemAlgorithm::MlKem768 => crown::ml_kem::MlKemVariant::MlKem768,
        KemAlgorithm::MlKem1024 => crown::ml_kem::MlKemVariant::MlKem1024,
    }
}

pub fn run_kem(args: ArgsKem) -> anyhow::Result<()> {
    use crown::ml_kem::{decapsulate, encapsulate, keygen, MlKemPrivateKey, MlKemPublicKey};
    let variant = variant_of(args.algorithm);
    match args.op.to_lowercase().as_str() {
        "keygen" => {
            let seed = hex::decode(&args.key)?;
            if seed.len() != 64 {
                anyhow::bail!("ML-KEM seed must be 64 bytes");
            }
            let mut s = [0u8; 64];
            s.copy_from_slice(&seed);
            let (pk, sk) = keygen(variant, &s)?;
            println!("public={}", hex::encode(pk.to_bytes()));
            println!("secret={}", hex::encode(sk.to_bytes()));
        }
        "encaps" => {
            let pk_bytes = hex::decode(&args.public)?;
            let pk = MlKemPublicKey::from_bytes(variant, &pk_bytes)?;
            let mut m = [0u8; 32];
            if args.message.is_empty() {
                use std::io::Read;
                std::fs::File::open("/dev/urandom")?.read_exact(&mut m)?;
            } else {
                let mb = hex::decode(&args.message)?;
                if mb.len() != 32 {
                    anyhow::bail!("message must be 32 bytes");
                }
                m.copy_from_slice(&mb);
            }
            let (ct, ss) = encapsulate(&pk, &m)?;
            match &args.output {
                Some(path) => std::fs::write(path, &ct)?,
                None => println!("ciphertext={}", hex::encode(&ct)),
            }
            println!("shared_secret={}", hex::encode(ss));
        }
        "decaps" => {
            let sk_bytes = hex::decode(&args.key)?;
            let sk = MlKemPrivateKey::from_bytes(variant, &sk_bytes)?;
            let ct = match &args.input {
                Some(path) => std::fs::read(path)?,
                None => hex::decode(&args.public)?,
            };
            let ss = decapsulate(&sk, &ct)?;
            println!("shared_secret={}", hex::encode(ss));
        }
        _ => anyhow::bail!("op must be keygen|encaps|decaps"),
    }
    Ok(())
}
