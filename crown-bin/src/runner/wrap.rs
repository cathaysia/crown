use crate::args::{ArgsFf1, ArgsWrap};

pub fn run_wrap(args: ArgsWrap) -> anyhow::Result<()> {
    let key = hex::decode(&args.key)?;
    let input = std::fs::read(&args.input)?;
    let output = if args.unwrap {
        if args.padded {
            crown::envelope::aes_key_unwrap_padded(&key, &input)?
        } else {
            crown::envelope::aes_key_unwrap(&key, &input)?
        }
    } else if args.padded {
        crown::envelope::aes_key_wrap_padded(&key, &input)?
    } else {
        crown::envelope::aes_key_wrap(&key, &input)?
    };
    std::fs::write(&args.output, output)?;
    Ok(())
}

pub fn run_ff1(args: ArgsFf1) -> anyhow::Result<()> {
    let key = hex::decode(&args.key)?;
    let tweak = hex::decode(&args.tweak)?;
    let out = if args.decrypt {
        crown::envelope::ff1_decrypt_decimal(&key, &tweak, &args.input)?
    } else {
        crown::envelope::ff1_encrypt_decimal(&key, &tweak, &args.input)?
    };
    println!("{out}");
    Ok(())
}
