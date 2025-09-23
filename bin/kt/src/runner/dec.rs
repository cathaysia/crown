use crate::args::ArgsDec;

pub fn run_dec(args: ArgsDec) -> anyhow::Result<()> {
    let ArgsDec {
        algorithm,
        key,
        iv,
        aad_file,
        in_file,
        out_file,
        tagin,
        rounds,
        padding_mode,
    } = args;
    let mut infile = std::fs::read(in_file)?;
    let key = hex::decode(key)?;
    let iv = hex::decode(iv)?;
    let aad = match aad_file {
        Some(aad_file) => std::fs::read(aad_file)?,
        None => vec![],
    };

    let aead_cipher = algorithm.new_aead(&key, rounds);
    if let Some(cipher) = aead_cipher {
        let cipher = cipher.unwrap();
        match tagin {
            Some(tagfile) => {
                let tag = std::fs::read(tagfile)?;
                cipher.open_in_place_separate_tag(&mut infile, &tag, &iv, &aad)?;
            }
            None => {
                cipher.open_in_place(&mut infile, &iv, &aad)?;
            }
        }
        std::fs::write(&out_file, &infile)?;
        return Ok(());
    }

    if let Some(cipher) = algorithm.new_stream(&key, &iv, rounds) {
        let mut cipher = cipher.unwrap();
        cipher.decrypt(&mut infile)?;
        std::fs::write(out_file, infile)?;
        return Ok(());
    }

    if let Some(cipher) = algorithm.new_block(&key, &iv, rounds) {
        let mut cipher = cipher.unwrap();
        cipher.set_padding(padding_mode.into());

        cipher.encrypt_alloc(&mut infile).unwrap();
        std::fs::write(out_file, infile)?;
    } else {
        unreachable!()
    }

    Ok(())
}
