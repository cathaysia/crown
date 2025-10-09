use crate::args::ArgsEnc;

pub fn run_enc(args: ArgsEnc) -> anyhow::Result<()> {
    let ArgsEnc {
        algorithm,
        key,
        iv,
        aad_file,
        in_file,
        out_file,
        tagout,
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
        match tagout {
            Some(tagout) => {
                let tag = cipher.seal_in_place_separate_tag(&mut infile, &iv, &aad)?;
                std::fs::write(tagout, tag)?;
            }
            None => {
                cipher.seal_in_place_append_tag(&mut infile, &iv, &aad)?;
            }
        }
        std::fs::write(&out_file, &infile)?;
        return Ok(());
    }

    if let Some(cipher) = algorithm.new_stream(&key, &iv, rounds) {
        let mut cipher = cipher.unwrap();
        cipher.encrypt(&mut infile)?;
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
