use clap::{Parser, Subcommand, ValueEnum};

use super::HashAlgorithm;

/// X.509 certificates, CSRs and CRLs.
#[derive(Debug, Parser)]
pub struct ArgsX509 {
    #[clap(subcommand)]
    pub op: X509Op,
}

/// X.509 operations.
#[derive(Debug, Subcommand)]
pub enum X509Op {
    /// Print a certificate as text.
    Info {
        /// Certificate file (PEM or DER).
        input: String,
    },
    /// Print a certificate fingerprint.
    Fingerprint {
        /// Certificate file (PEM or DER).
        input: String,
        /// Fingerprint digest.
        #[clap(long, default_value = "sha256")]
        hash: HashAlgorithm,
    },
    /// Verify a certificate against its issuer.
    Verify {
        /// Certificate file (PEM or DER).
        input: String,
        /// Issuer certificate file (PEM or DER).
        #[clap(long)]
        issuer: String,
        /// Skip the validity-period check.
        #[clap(long, default_value_t = false)]
        no_check_time: bool,
        /// SM2 identity string (defaults to the GM/T value).
        #[clap(long)]
        sm2_id: Option<String>,
    },
    /// Print a PKCS#10 CSR as text.
    CsrInfo {
        /// CSR file (PEM or DER).
        input: String,
    },
    /// Verify a CSR self-signature.
    CsrVerify {
        /// CSR file (PEM or DER).
        input: String,
        /// SM2 identity string (defaults to the GM/T value).
        #[clap(long)]
        sm2_id: Option<String>,
    },
    /// Print a CRL as text.
    CrlInfo {
        /// CRL file (PEM or DER).
        input: String,
    },
    /// Verify a CRL signature against its issuer certificate.
    CrlVerify {
        /// CRL file (PEM or DER).
        input: String,
        /// Issuer certificate file (PEM or DER).
        #[clap(long)]
        issuer: String,
        /// SM2 identity string (defaults to the GM/T value).
        #[clap(long)]
        sm2_id: Option<String>,
    },
    /// Check whether a serial number is listed in a CRL.
    CrlCheck {
        /// CRL file (PEM or DER).
        input: String,
        /// Issuer certificate file (PEM or DER).
        #[clap(long)]
        issuer: String,
        /// Certificate serial number in hex.
        #[clap(long)]
        serial: String,
        /// SM2 identity string (defaults to the GM/T value).
        #[clap(long)]
        sm2_id: Option<String>,
    },
}

/// CMS / PKCS#7 signed data.
#[derive(Debug, Parser)]
pub struct ArgsPkcs7 {
    #[clap(subcommand)]
    pub op: Pkcs7Op,
}

/// PKCS#7 / CMS operations.
#[derive(Debug, Subcommand)]
pub enum Pkcs7Op {
    /// Print a CMS structure as text.
    Info {
        /// CMS file (PEM or DER).
        input: String,
    },
    /// Sign a file, producing a CMS SignedData.
    Sign {
        /// Content file to sign.
        input: String,
        /// Signer private key (PKCS#8 PEM or DER).
        #[clap(long)]
        key: String,
        /// Password for an encrypted PKCS#8 key.
        #[clap(long)]
        password: Option<String>,
        /// Signer certificate (PEM or DER).
        #[clap(long)]
        cert: String,
        /// Additional certificates to embed (repeatable).
        #[clap(long)]
        chain: Vec<String>,
        /// Produce a detached signature (omit the content).
        #[clap(long, default_value_t = false)]
        detached: bool,
        /// Digest algorithm.
        #[clap(long, default_value = "sha256")]
        hash: HashAlgorithm,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
        /// SM2 identity string (defaults to the GM/T value).
        #[clap(long)]
        sm2_id: Option<String>,
    },
    /// Verify a CMS SignedData.
    Verify {
        /// CMS file (PEM or DER).
        input: String,
        /// Detached content file.
        #[clap(long)]
        content: Option<String>,
        /// SM2 identity string (defaults to the GM/T value).
        #[clap(long)]
        sm2_id: Option<String>,
    },
    /// Write the encapsulated content to a file.
    Extract {
        /// CMS file (PEM or DER).
        input: String,
        /// Output file.
        #[clap(long)]
        out: String,
    },
}

/// PKCS#12 key and certificate containers.
#[derive(Debug, Parser)]
pub struct ArgsPkcs12 {
    #[clap(subcommand)]
    pub op: Pkcs12Op,
}

/// PKCS#12 operations.
#[derive(Debug, Subcommand)]
pub enum Pkcs12Op {
    /// Print the MAC and bag summary of a PFX.
    Info {
        /// PFX file (DER or PEM).
        input: String,
        /// PFX password.
        #[clap(long, default_value = "")]
        password: String,
    },
    /// Verify the PFX MAC.
    Verify {
        /// PFX file (DER or PEM).
        input: String,
        /// PFX password.
        #[clap(long, default_value = "")]
        password: String,
    },
    /// Export a PFX from a private key and certificate.
    Export {
        /// Private key (PKCS#8 PEM or DER).
        #[clap(long)]
        key: String,
        /// Password for the input key, when encrypted.
        #[clap(long)]
        key_password: Option<String>,
        /// Certificate file (PEM or DER).
        #[clap(long)]
        cert: String,
        /// Additional certificates to include (repeatable).
        #[clap(long)]
        chain: Vec<String>,
        /// Friendly name for the key and certificate bags.
        #[clap(long)]
        name: Option<String>,
        /// MAC and PBE iteration count.
        #[clap(long, default_value_t = 2048)]
        iterations: u32,
        /// PFX password.
        #[clap(long, default_value = "")]
        password: String,
        /// Write PEM instead of DER.
        #[clap(long, default_value_t = false)]
        pem: bool,
        /// Output file.
        #[clap(long)]
        out: String,
    },
    /// Extract the key and certificates.
    Extract {
        /// PFX file (DER or PEM).
        input: String,
        /// PFX password.
        #[clap(long, default_value = "")]
        password: String,
        /// Write the private key (PKCS#8 PEM) here.
        #[clap(long)]
        key: Option<String>,
        /// Write the first certificate (PEM) here.
        #[clap(long)]
        cert: Option<String>,
        /// Write the remaining certificates (PEM) here.
        #[clap(long)]
        chain: Option<String>,
    },
}

/// PKCS#8 private keys and encrypted keys.
#[derive(Debug, Parser)]
pub struct ArgsPkey {
    #[clap(subcommand)]
    pub op: PkeyOp,
}

/// PKCS#8 operations.
#[derive(Debug, Subcommand)]
pub enum PkeyOp {
    /// Print private key information.
    Info {
        /// Private key file (PEM or DER).
        input: String,
        /// Password for an encrypted PKCS#8 key.
        #[clap(long, default_value = "")]
        password: String,
    },
    /// Decrypt an encrypted PKCS#8 key into a plain PKCS#8 key.
    Decrypt {
        /// Encrypted PKCS#8 file (PEM or DER).
        input: String,
        /// Password.
        #[clap(long)]
        password: String,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Encrypt a PKCS#8 key with PBES2.
    Encrypt {
        /// Plain PKCS#8 file (PEM or DER).
        input: String,
        /// Password.
        #[clap(long)]
        password: String,
        /// Content cipher.
        #[clap(long, default_value = "aes-256-cbc")]
        cipher: PbeCipher,
        /// PBKDF2 iteration count.
        #[clap(long, default_value_t = 2048)]
        iterations: u32,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Print the public key (SubjectPublicKeyInfo) of a private key.
    Pubout {
        /// Private key file (PEM or DER).
        input: String,
        /// Password for an encrypted PKCS#8 key.
        #[clap(long, default_value = "")]
        password: String,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
}

/// PBES2 content cipher.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum PbeCipher {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    DesEde3Cbc,
}
