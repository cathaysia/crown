use crate::args::{ArgsMac, ArgsOtp, MacAlgorithm};

pub fn run_mac(args: ArgsMac) -> anyhow::Result<()> {
    let key = hex::decode(&args.key)?;
    let custom = hex::decode(&args.custom)?;
    let data = std::fs::read(&args.input)?;

    let tag = match args.algorithm {
        MacAlgorithm::SipHash => {
            if key.len() != 16 {
                anyhow::bail!("SipHash key must be 16 bytes");
            }
            let mut k = [0u8; 16];
            k.copy_from_slice(&key);
            let mut h = crown::mac::siphash::SipHash::new(&k, args.length)?;
            h.write(&data);
            h.sum()[..args.length.min(16)].to_vec()
        }
        MacAlgorithm::Kmac128 => {
            let mut h = crown::mac::kmac::Kmac128::new(&key, &custom)?;
            h.write(&data);
            let mut out = vec![0u8; args.length];
            h.sum(&mut out);
            out
        }
        MacAlgorithm::Kmac256 => {
            let mut h = crown::mac::kmac::Kmac256::new(&key, &custom)?;
            h.write(&data);
            let mut out = vec![0u8; args.length];
            h.sum(&mut out);
            out
        }
        MacAlgorithm::CmacAes => {
            use crown::block::aes::Aes;
            use crown::mac::cmac::Cmac;
            let cipher = Aes::new(&key)?;
            let mut h = Cmac::<Aes, 16>::new(cipher)?;
            h.write(&data);
            h.sum().to_vec()
        }
    };

    println!("{}", hex::encode(tag));
    Ok(())
}

pub fn run_otp(args: ArgsOtp) -> anyhow::Result<()> {
    let key = hex::decode(&args.key)?;
    let code = if args.kind.eq_ignore_ascii_case("hotp") {
        crown::otp::hotp(&key, args.counter, args.digits)
    } else {
        crown::otp::totp(&key, args.counter, args.step, args.digits, args.t0)
    };
    println!("{:0width$}", code, width = args.digits);
    Ok(())
}
