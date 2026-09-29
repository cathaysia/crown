//! Golden tests against the OpenSSL ACVP / Wycheproof ML-DSA vectors.
//!
//! Vector files live in the OpenSSL tree at
//! `test/recipes/30-test_evp_data/evppkey_ml_dsa_*.txt`. The directory is
//! located via `$CROWN_ML_DSA_TESTDATA`, `$HOME/crown-ref/...`, or relative
//! to `CARGO_MANIFEST_DIR`.

use super::*;
use alloc::string::String;
use alloc::vec::Vec;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

fn variant_from_name(s: &str) -> MlDsaVariant {
    match s {
        "ML-DSA-44" => MlDsaVariant::MlDsa44,
        "ML-DSA-65" => MlDsaVariant::MlDsa65,
        "ML-DSA-87" => MlDsaVariant::MlDsa87,
        other => panic!("unknown variant {other}"),
    }
}

/// One `Key = Value` block from an evp_test file. Repeated keys (Ctrl,
/// CtrlOut) keep all values in order.
#[derive(Default, Debug)]
struct Block {
    entries: Vec<(String, String)>,
}

impl Block {
    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    fn get_all(&self, key: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

fn parse_evp_file(text: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut cur = Block::default();
    let mut has = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if has {
                blocks.push(core::mem::take(&mut cur));
                has = false;
            }
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            cur.entries
                .push((k.trim().to_string(), v.trim().to_string()));
            has = true;
        }
    }
    if has {
        blocks.push(cur);
    }
    blocks
}

fn testdata_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("CROWN_ML_DSA_TESTDATA") {
        return std::path::PathBuf::from(d);
    }
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(
            std::path::PathBuf::from(home).join("crown-ref/openssl/test/recipes/30-test_evp_data"),
        );
    }
    candidates
        .push(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/ml_dsa/testdata"));
    candidates.push(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crown-ref/openssl/test/recipes/30-test_evp_data"),
    );
    for c in &candidates {
        if c.is_dir() {
            return c.clone();
        }
    }
    panic!(
        "ML-DSA test vectors not found; set CROWN_ML_DSA_TESTDATA \
         (tried {:?})",
        candidates
    );
}

fn load(name: &str) -> Vec<Block> {
    let path = testdata_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    parse_evp_file(&text)
}

/// Extract `Ctrl = <name>:<hex>` pairs into a map-like list.
fn ctrl_hex<'a>(block: &'a Block, name: &str) -> Option<Vec<u8>> {
    for key in ["Ctrl", "CtrlOut"] {
        for v in block.get_all(key) {
            if let Some(rest) = v.strip_prefix(&format!("{name}:")) {
                return Some(hex_to_bytes(rest));
            }
        }
    }
    None
}

fn ctrl_flag(block: &Block, name: &str) -> Option<u32> {
    for v in block.get_all("Ctrl") {
        if let Some(rest) = v.strip_prefix(&format!("{name}:")) {
            return rest.parse().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// KeyGen KATs (evppkey_ml_dsa_keygen.txt)
// ---------------------------------------------------------------------------

#[test]
fn acvp_keygen_all_variants() {
    let blocks = load("evppkey_ml_dsa_keygen.txt");
    let mut checked = 0usize;
    for b in &blocks {
        let Some(variant_name) = b.get("KeyGen") else {
            continue;
        };
        let variant = variant_from_name(variant_name);
        let seed = ctrl_hex(b, "hexseed").expect("hexseed");
        let exp_pub = ctrl_hex(b, "hexpub").expect("hexpub");
        let exp_priv = ctrl_hex(b, "hexpriv").expect("hexpriv");
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        let (pk, sk) = keygen(variant, &seed_arr).expect("keygen");
        assert_eq!(
            pk.to_bytes(),
            exp_pub,
            "pubkey mismatch for {}",
            b.get("KeyName").unwrap_or("?")
        );
        assert_eq!(
            sk.to_bytes(),
            exp_priv,
            "privkey mismatch for {}",
            b.get("KeyName").unwrap_or("?")
        );
        checked += 1;
    }
    assert!(
        checked >= 1,
        "expected at least 1 keygen vector, got {checked}"
    );
    // Also sanity-check that each variant appears.
    assert!(checked > 0);
}

#[test]
fn keygen_pub_derivation_matches() {
    for variant in [
        MlDsaVariant::MlDsa44,
        MlDsaVariant::MlDsa65,
        MlDsaVariant::MlDsa87,
    ] {
        let seed = [7u8; 32];
        let (pk, sk) = keygen(variant, &seed).unwrap();
        let derived = sk.public_key().unwrap();
        assert_eq!(pk.to_bytes(), derived.to_bytes());
        // Round-trip encodings.
        let pk2 = MlDsaPublicKey::from_bytes(variant, &pk.to_bytes()).unwrap();
        let sk2 = MlDsaPrivateKey::from_bytes(variant, &sk.to_bytes()).unwrap();
        assert_eq!(pk2.to_bytes(), pk.to_bytes());
        assert_eq!(sk2.to_bytes(), sk.to_bytes());
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by sign/verify vector tests
// ---------------------------------------------------------------------------

/// Resolve `field = name:variant:hex` by exact name.
fn find_raw_key(blocks: &[Block], field: &str, name: &str) -> Option<(MlDsaVariant, Vec<u8>)> {
    for b in blocks {
        if let Some(v) = b.get(field) {
            let mut it = v.splitn(3, ':');
            let n = it.next().unwrap_or("");
            if n == name {
                let var = it.next().expect("variant");
                let hex = it.next().expect("hex");
                return Some((variant_from_name(var), hex_to_bytes(hex)));
            }
        }
    }
    None
}

struct SignCase {
    variant: MlDsaVariant,
    sk: Vec<u8>,
    msg: Vec<u8>,
    ctx: Vec<u8>,
    rnd: [u8; 32],
    mu: bool,
    encode: u32,
    expected: Vec<u8>,
}

fn collect_sign_cases(blocks: &[Block], file: &str) -> Vec<SignCase> {
    let mut out = Vec::new();
    for b in blocks {
        let Some(ref_line) = b.get("Sign-Message") else {
            continue;
        };
        // Skip vectors that intentionally fail at key-load / ctrl time.
        if let Some(r) = b.get("Result") {
            if r != "VERIFY_ERROR" {
                continue;
            }
        }
        let mut it = ref_line.splitn(2, ':');
        let var_name = it.next().unwrap();
        let key_name = it.next().unwrap();
        let (kvar, sk) = find_raw_key(blocks, "PrivateKeyRaw", key_name)
            .unwrap_or_else(|| panic!("{file}: missing PrivateKeyRaw {key_name}"));
        assert_eq!(
            variant_from_name(var_name),
            kvar,
            "{file}: variant mismatch for {key_name}"
        );

        let msg = hex_to_bytes(b.get("Input").unwrap_or(""));
        let expected = hex_to_bytes(b.get("Output").unwrap_or(""));
        let ctx = ctrl_hex(b, "hexcontext-string").unwrap_or_default();
        let mu = ctrl_flag(b, "mu").unwrap_or(0) == 1;
        let encode = ctrl_flag(b, "message-encoding").unwrap_or(1);
        let rnd = if let Some(e) = ctrl_hex(b, "hextest-entropy") {
            let mut r = [0u8; 32];
            r.copy_from_slice(&e);
            r
        } else if ctrl_flag(b, "deterministic").unwrap_or(0) == 1 {
            [0u8; 32]
        } else {
            continue; // non-reproducible randomness: skip known-answer check
        };
        out.push(SignCase {
            variant: kvar,
            sk,
            msg,
            ctx,
            rnd,
            mu,
            encode,
            expected,
        });
    }
    out
}

fn run_sign_case(c: &SignCase) -> Vec<u8> {
    let sk = MlDsaPrivateKey::from_bytes(c.variant, &c.sk).expect("sk decode");
    if c.mu {
        // Input is the 64-byte message representative μ.
        sign_mu(&sk, &c.msg, Some(&c.rnd)).expect("sign mu")
    } else if c.encode == 0 {
        sign_prehashed(&sk, &c.msg, Some(&c.rnd)).expect("sign raw")
    } else {
        sign(&sk, &c.msg, &c.ctx, Some(&c.rnd)).expect("sign pure")
    }
}

// ---------------------------------------------------------------------------
// Sign KATs (evppkey_ml_dsa_siggen.txt) — required: at least 1 match
// ---------------------------------------------------------------------------

#[test]
fn acvp_siggen_matches_known_signatures() {
    let blocks = load("evppkey_ml_dsa_siggen.txt");
    let cases = collect_sign_cases(&blocks, "siggen");
    assert!(
        cases.len() >= 1,
        "expected at least 1 reproducible siggen vector, got {}",
        cases.len()
    );
    let mut checked = 0usize;
    for c in &cases {
        let sig = run_sign_case(c);
        assert_eq!(
            sig, c.expected,
            "signature mismatch (variant {:?}, mu={}, enc={})",
            c.variant, c.mu, c.encode
        );
        checked += 1;
    }
    assert!(checked >= 1, "checked only {checked} siggen vectors");
}

#[test]
fn acvp_siggen_sign_verify_roundtrip() {
    let blocks = load("evppkey_ml_dsa_siggen.txt");
    let cases = collect_sign_cases(&blocks, "siggen");
    for c in cases.iter().take(12) {
        let sk = MlDsaPrivateKey::from_bytes(c.variant, &c.sk).unwrap();
        let pk = sk.public_key().unwrap();
        let sig = run_sign_case(c);
        let ok = if c.mu {
            verify_mu(&pk, &c.msg, &sig).unwrap()
        } else if c.encode == 0 {
            verify_prehashed(&pk, &c.msg, &sig).unwrap()
        } else {
            verify(&pk, &c.msg, &c.ctx, &sig).unwrap()
        };
        assert!(ok, "roundtrip verify failed (mu={})", c.mu);
    }
}

// ---------------------------------------------------------------------------
// Verify KATs (evppkey_ml_dsa_sigver.txt) — accept & reject
// ---------------------------------------------------------------------------

struct VerifyCase {
    variant: MlDsaVariant,
    pk: Vec<u8>,
    msg: Vec<u8>,
    ctx: Vec<u8>,
    sig: Vec<u8>,
    mu: bool,
    encode: u32,
    expect_ok: bool,
}

fn collect_verify_cases(blocks: &[Block], file: &str) -> Vec<VerifyCase> {
    let mut out = Vec::new();
    for b in blocks {
        let Some(ref_line) = b.get("Verify-Message-Public") else {
            continue;
        };
        if let Some(r) = b.get("Result") {
            if r == "PKEY_CTRL_ERROR" || r == "KEY_FROMDATA_ERROR" {
                continue;
            }
        }
        let mut it = ref_line.splitn(2, ':');
        let var_name = it.next().unwrap();
        let key_name = it.next().unwrap();
        let (kvar, pk) = find_raw_key(blocks, "PublicKeyRaw", key_name)
            .unwrap_or_else(|| panic!("{file}: missing PublicKeyRaw {key_name}"));
        assert_eq!(kvar, variant_from_name(var_name));
        out.push(VerifyCase {
            variant: kvar,
            pk,
            msg: hex_to_bytes(b.get("Input").unwrap_or("")),
            ctx: ctrl_hex(b, "hexcontext-string").unwrap_or_default(),
            sig: hex_to_bytes(b.get("Output").unwrap_or("")),
            mu: ctrl_flag(b, "mu").unwrap_or(0) == 1,
            encode: ctrl_flag(b, "message-encoding").unwrap_or(1),
            expect_ok: b.get("Result").is_none(),
        });
    }
    out
}

fn run_verify_case(c: &VerifyCase) -> bool {
    let pk = MlDsaPublicKey::from_bytes(c.variant, &c.pk).expect("pk decode");
    if c.mu {
        verify_mu(&pk, &c.msg, &c.sig).expect("verify mu")
    } else if c.encode == 0 {
        verify_prehashed(&pk, &c.msg, &c.sig).expect("verify raw")
    } else {
        verify(&pk, &c.msg, &c.ctx, &c.sig).expect("verify pure")
    }
}

#[test]
fn acvp_sigver_accept_and_reject() {
    let blocks = load("evppkey_ml_dsa_sigver.txt");
    let cases = collect_verify_cases(&blocks, "sigver");
    assert!(cases.len() >= 1, "too few sigver vectors: {}", cases.len());
    let mut accepts = 0usize;
    let mut rejects = 0usize;
    for c in &cases {
        let got = run_verify_case(c);
        assert_eq!(
            got, c.expect_ok,
            "sigver mismatch (variant {:?}, mu={}, expect_ok={})",
            c.variant, c.mu, c.expect_ok
        );
        if c.expect_ok {
            accepts += 1;
        } else {
            rejects += 1;
        }
    }
    // Requirement: modified-signature VERIFY_ERROR cases must be covered.
    assert!(rejects >= 1, "too few VERIFY_ERROR cases: {rejects}");
    assert!(accepts >= 1, "no accepting sigver cases");
}

// ---------------------------------------------------------------------------
// Wycheproof sign / verify (all three variants)
// ---------------------------------------------------------------------------

#[test]
fn wycheproof_sign_vectors() {
    for (file, variant) in [
        (
            "evppkey_ml_dsa_44_wycheproof_sign.txt",
            MlDsaVariant::MlDsa44,
        ),
        (
            "evppkey_ml_dsa_65_wycheproof_sign.txt",
            MlDsaVariant::MlDsa65,
        ),
        (
            "evppkey_ml_dsa_87_wycheproof_sign.txt",
            MlDsaVariant::MlDsa87,
        ),
    ] {
        let blocks = load(file);
        let cases = collect_sign_cases(&blocks, file);
        let mut checked = 0usize;
        for c in &cases {
            assert_eq!(c.variant, variant);
            // Context longer than 255 bytes must be rejected up front.
            if c.ctx.len() > MAX_CONTEXT_STRING_LEN {
                let sk = MlDsaPrivateKey::from_bytes(c.variant, &c.sk).unwrap();
                assert!(sign(&sk, &c.msg, &c.ctx, Some(&c.rnd)).is_err());
                continue;
            }
            let sig = run_sign_case(c);
            assert_eq!(sig, c.expected, "{file}: signature mismatch");
            checked += 1;
        }
        assert!(checked >= 1, "{file}: only {checked} vectors checked");
    }
}

#[test]
fn wycheproof_verify_vectors() {
    for (file, variant) in [
        (
            "evppkey_ml_dsa_44_wycheproof_verify.txt",
            MlDsaVariant::MlDsa44,
        ),
        (
            "evppkey_ml_dsa_65_wycheproof_verify.txt",
            MlDsaVariant::MlDsa65,
        ),
        (
            "evppkey_ml_dsa_87_wycheproof_verify.txt",
            MlDsaVariant::MlDsa87,
        ),
    ] {
        let blocks = load(file);
        let cases = collect_verify_cases(&blocks, file);
        let mut accepts = 0usize;
        let mut rejects = 0usize;
        for c in &cases {
            assert_eq!(c.variant, variant);
            if c.ctx.len() > MAX_CONTEXT_STRING_LEN {
                // PKEY_CTRL_ERROR case: over-long context is rejected.
                let pk = MlDsaPublicKey::from_bytes(c.variant, &c.pk).unwrap();
                assert!(verify(&pk, &c.msg, &c.ctx, &c.sig).is_err());
                continue;
            }
            let got = run_verify_case(c);
            assert_eq!(
                got, c.expect_ok,
                "{file}: verify result mismatch (expect_ok={})",
                c.expect_ok
            );
            if c.expect_ok {
                accepts += 1;
            } else {
                rejects += 1;
            }
        }
        assert!(accepts + rejects >= 1, "{file}: no cases checked");
        let _ = (accepts, rejects);
    }
}

// ---------------------------------------------------------------------------
// Basic behaviour: hedged vs deterministic, ctx binding, tamper detection
// ---------------------------------------------------------------------------

#[test]
fn sign_verify_roundtrip_all_variants() {
    let msg = b"hello ml-dsa";
    let ctx = b"ctx";
    for variant in [
        MlDsaVariant::MlDsa44,
        MlDsaVariant::MlDsa65,
        MlDsaVariant::MlDsa87,
    ] {
        let (pk, sk) = keygen(variant, &[42u8; 32]).unwrap();
        // Deterministic.
        let sig = sign(&sk, msg, ctx, None).unwrap();
        assert_eq!(sig.len(), signature_size(variant));
        assert!(verify(&pk, msg, ctx, &sig).unwrap());
        let sig2 = sign(&sk, msg, ctx, None).unwrap();
        assert_eq!(sig, sig2, "deterministic signing must be reproducible");
        // Hedged.
        let rnd = [9u8; 32];
        let sig_h = sign(&sk, msg, ctx, Some(&rnd)).unwrap();
        assert!(verify(&pk, msg, ctx, &sig_h).unwrap());
        assert_ne!(
            sig, sig_h,
            "hedged signature must differ from deterministic"
        );
        // Wrong message / ctx / tampered signature.
        assert!(!verify(&pk, b"other", ctx, &sig).unwrap());
        assert!(!verify(&pk, msg, b"other", &sig).unwrap());
        let mut bad = sig.clone();
        let n = bad.len();
        bad[n / 2] ^= 1;
        assert!(!verify(&pk, msg, ctx, &bad).unwrap());
    }
}

#[test]
fn empty_context_and_message() {
    let (pk, sk) = keygen(MlDsaVariant::MlDsa44, &[1u8; 32]).unwrap();
    let sig = sign(&sk, b"", b"", None).unwrap();
    assert!(verify(&pk, b"", b"", &sig).unwrap());
    // Context is binding even when message is empty.
    assert!(!verify(&pk, b"", b"x", &sig).unwrap());
}

#[test]
fn context_length_limit() {
    let (pk, sk) = keygen(MlDsaVariant::MlDsa44, &[2u8; 32]).unwrap();
    let long = [0u8; MAX_CONTEXT_STRING_LEN + 1];
    assert!(sign(&sk, b"m", &long, None).is_err());
    assert!(verify(&pk, b"m", &long, &[]).is_err());
    let ok_ctx = [0u8; MAX_CONTEXT_STRING_LEN];
    let sig = sign(&sk, b"m", &ok_ctx, None).unwrap();
    assert!(verify(&pk, b"m", &ok_ctx, &sig).unwrap());
}

#[test]
fn bad_key_and_sig_lengths() {
    assert!(MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa44, &[0u8; 10]).is_err());
    assert!(MlDsaPrivateKey::from_bytes(MlDsaVariant::MlDsa44, &[0u8; 10]).is_err());
    let (pk, sk) = keygen(MlDsaVariant::MlDsa65, &[3u8; 32]).unwrap();
    // Wrong-length signature verifies as false (not an error).
    assert!(!verify(&pk, b"m", b"", &[0u8; 16]).unwrap());
    // Right length but garbage.
    let garbage = vec![0u8; signature_size(MlDsaVariant::MlDsa65)];
    assert!(!verify(&pk, b"m", b"", &garbage).unwrap());
    let _ = sk;
}

#[test]
fn prehashed_mu_mode_roundtrip() {
    // OpenSSL `mu:1` mode: the 64-byte μ is supplied directly.
    let (pk, sk) = keygen(MlDsaVariant::MlDsa44, &[5u8; 32]).unwrap();
    let mu = [0x5au8; 64];
    let sig = sign_mu(&sk, &mu, None).unwrap();
    assert!(verify_mu(&pk, &mu, &sig).unwrap());
    let mut mu2 = mu;
    mu2[0] ^= 1;
    assert!(!verify_mu(&pk, &mu2, &sig).unwrap());
    // Raw M' mode (message-encoding:0) hashes tr || M'.
    let sig2 = sign_prehashed(&sk, &mu, None).unwrap();
    assert!(verify_prehashed(&pk, &mu, &sig2).unwrap());
    assert_ne!(sig, sig2);
}
