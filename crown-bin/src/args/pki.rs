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
    /// Verify a certificate (single issuer or a full path-validation chain).
    Verify {
        /// Certificate file (PEM or DER).
        input: String,
        /// Issuer certificate for single-step verification (PEM or DER).
        #[clap(long)]
        issuer: Option<String>,
        /// Trust anchor for RFC 5280 path validation (repeatable).
        #[clap(long = "trust")]
        trust: Vec<String>,
        /// Untrusted intermediate certificate (repeatable).
        #[clap(long = "untrusted")]
        untrusted: Vec<String>,
        /// CRL file used for revocation checking (repeatable).
        #[clap(long = "crl")]
        crls: Vec<String>,
        /// Check the leaf certificate for revocation.
        #[clap(long, default_value_t = false)]
        crl_check: bool,
        /// Check every chain certificate for revocation.
        #[clap(long, default_value_t = false)]
        crl_check_all: bool,
        /// Enable certificate policy processing.
        #[clap(long, default_value_t = false)]
        policy_check: bool,
        /// Require an explicit policy.
        #[clap(long, default_value_t = false)]
        explicit_policy: bool,
        /// Extra-strict extension checks.
        #[clap(long, default_value_t = false)]
        x509_strict: bool,
        /// Accept a chain ending in a non-self-signed trust anchor
        /// (`X509_V_FLAG_PARTIAL_CHAIN`).
        #[clap(long, default_value_t = false)]
        partial_chain: bool,
        /// Required leaf purpose.
        #[clap(long, default_value = "any")]
        purpose: CertPurpose,
        /// Skip the validity-period check.
        #[clap(long, default_value_t = false)]
        no_check_time: bool,
        /// SM2 identity string (defaults to the GM/T value).
        #[clap(long)]
        sm2_id: Option<String>,
    },
    /// Create a self-signed certificate from a PKCS#8 private key.
    SelfSign {
        /// Private key file (PEM or DER).
        #[clap(long)]
        key: String,
        /// Password for an encrypted key.
        #[clap(long, default_value = "")]
        key_password: String,
        /// Subject name, e.g. "C=CN,O=Org,CN=example.com".
        #[clap(long)]
        subject: String,
        /// Validity in days.
        #[clap(long, default_value_t = 365)]
        days: u64,
        /// Serial number in hex (random when omitted).
        #[clap(long)]
        serial: Option<String>,
        /// DNS subject alternative name (repeatable).
        #[clap(long = "san")]
        sans: Vec<String>,
        /// Mark the certificate as a CA.
        #[clap(long, default_value_t = false)]
        ca: bool,
        /// Digest algorithm.
        #[clap(long, default_value = "sha256")]
        hash: HashAlgorithm,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Sign a PKCS#10 request with a CA certificate and key.
    Issue {
        /// CSR file (PEM or DER).
        #[clap(long)]
        csr: String,
        /// CA certificate file (PEM or DER).
        #[clap(long)]
        ca: String,
        /// CA private key file (PEM or DER).
        #[clap(long)]
        ca_key: String,
        /// Password for an encrypted CA key.
        #[clap(long, default_value = "")]
        ca_password: String,
        /// Validity in days.
        #[clap(long, default_value_t = 365)]
        days: u64,
        /// Serial number in hex (random when omitted).
        #[clap(long)]
        serial: Option<String>,
        /// DNS subject alternative name (repeatable).
        #[clap(long = "san")]
        sans: Vec<String>,
        /// Mark the issued certificate as a CA.
        #[clap(long = "is-ca", default_value_t = false)]
        is_ca: bool,
        /// Digest algorithm.
        #[clap(long, default_value = "sha256")]
        hash: HashAlgorithm,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Create a CRL signed by a CA.
    Crl {
        /// CA certificate file (PEM or DER).
        #[clap(long)]
        ca: String,
        /// CA private key file (PEM or DER).
        #[clap(long)]
        ca_key: String,
        /// Password for an encrypted CA key.
        #[clap(long, default_value = "")]
        ca_password: String,
        /// Revoked serial in hex, optionally "SERIAL:reason" (repeatable).
        #[clap(long = "revoke")]
        revoke: Vec<String>,
        /// Validity in days.
        #[clap(long, default_value_t = 30)]
        days: u64,
        /// CRL number (omitted when not given).
        #[clap(long)]
        crl_number: Option<u64>,
        /// Digest algorithm.
        #[clap(long, default_value = "sha256")]
        hash: HashAlgorithm,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
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
    /// Print an attribute certificate (RFC 5755) as text.
    AcInfo {
        /// Attribute certificate file (PEM or DER).
        input: String,
    },
    /// Verify an attribute certificate against its issuer.
    AcVerify {
        /// Attribute certificate file (PEM or DER).
        input: String,
        /// Issuer certificate file (PEM or DER).
        #[clap(long)]
        issuer: String,
        /// Skip the validity-period check.
        #[clap(long, default_value_t = false)]
        no_check_time: bool,
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
        /// Signer private key (PKCS#8 PEM or DER; repeat for multiple signers).
        #[clap(long = "key", required = true)]
        keys: Vec<String>,
        /// Password for an encrypted PKCS#8 key.
        #[clap(long)]
        password: Option<String>,
        /// Signer certificate (PEM or DER; repeat for multiple signers).
        #[clap(long = "cert", required = true)]
        certs: Vec<String>,
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
    /// Encrypt content to one or more CMS recipients.
    Encrypt {
        /// Content file to encrypt.
        input: String,
        /// Recipient certificate (repeatable).
        #[clap(long = "recip")]
        recipients: Vec<String>,
        /// Add a password recipient.
        #[clap(long)]
        password: Option<String>,
        /// Content cipher.
        #[clap(long, default_value = "aes-256-cbc")]
        cipher: CmsCipher,
        /// PBKDF2 iteration count for the password recipient.
        #[clap(long, default_value_t = 2048)]
        iterations: u32,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Decrypt a CMS EnvelopedData object.
    Decrypt {
        /// CMS file (PEM or DER).
        input: String,
        /// Recipient private key (PKCS#8 PEM or DER).
        #[clap(long)]
        key: Option<String>,
        /// Password for an encrypted key.
        #[clap(long)]
        key_password: Option<String>,
        /// Recipient certificate (PEM or DER).
        #[clap(long)]
        cert: Option<String>,
        /// Password recipient password.
        #[clap(long)]
        password: Option<String>,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Verify a CMS AuthenticatedData object.
    AuthVerify {
        /// CMS AuthenticatedData file (PEM or DER).
        input: String,
        /// Recipient private key (PKCS#8 PEM or DER).
        #[clap(long)]
        key: Option<String>,
        /// Recipient certificate (PEM or DER).
        #[clap(long)]
        cert: Option<String>,
        /// Password recipient password.
        #[clap(long)]
        password: Option<String>,
        /// KEK recipient key (hex).
        #[clap(long)]
        kek: Option<String>,
        /// KEK recipient identifier.
        #[clap(long, default_value = "")]
        kek_id: String,
        /// Output file for the authenticated content (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
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

/// CMP (RFC 4210) messages.
#[derive(Debug, Parser)]
pub struct ArgsCmp {
    #[clap(subcommand)]
    pub op: CmpOp,
}

/// CMP operations.
#[derive(Debug, Subcommand)]
pub enum CmpOp {
    /// Print a CMP message as text.
    Info {
        /// CMP message file (DER or PEM).
        input: String,
    },
    /// Verify a CMP message's protection.
    Verify {
        /// CMP message file (DER or PEM).
        input: String,
        /// Password for password-based protection.
        #[clap(long)]
        password: Option<String>,
    },
}

/// CRMF (RFC 4211) certificate request messages.
#[derive(Debug, Parser)]
pub struct ArgsCrmf {
    #[clap(subcommand)]
    pub op: CrmfOp,
}

/// CRMF operations.
#[derive(Debug, Subcommand)]
pub enum CrmfOp {
    /// Print CRMF certificate request messages as text.
    Info {
        /// CRMF file (DER or PEM).
        input: String,
    },
}

/// RFC 3161 timestamping.
#[derive(Debug, Parser)]
pub struct ArgsTs {
    #[clap(subcommand)]
    pub op: TsOp,
}

/// Timestamp operations.
#[derive(Debug, Subcommand)]
pub enum TsOp {
    /// Build a timestamp request for a file.
    Request {
        /// Data file to timestamp.
        #[clap(long)]
        data: String,
        /// Imprint digest algorithm.
        #[clap(long, default_value = "sha256")]
        hash: HashAlgorithm,
        /// Ask the TSA to include its certificate.
        #[clap(long, default_value_t = false)]
        cert_req: bool,
        /// Nonce in hex (a random nonce is used when omitted).
        #[clap(long)]
        nonce: Option<String>,
        /// Omit the nonce entirely.
        #[clap(long, default_value_t = false)]
        no_nonce: bool,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Answer a timestamp request (act as a TSA).
    Reply {
        /// Query file (PEM or DER).
        #[clap(long)]
        query: String,
        /// TSA certificate (PEM or DER).
        #[clap(long)]
        signer: String,
        /// TSA private key (PEM or DER).
        #[clap(long)]
        key: String,
        /// Password for an encrypted key.
        #[clap(long, default_value = "")]
        key_password: String,
        /// Additional certificates to embed (repeatable).
        #[clap(long)]
        chain: Vec<String>,
        /// TSA policy OID (dotted).
        #[clap(long, default_value = "1.3.6.1.4.1.13762.3")]
        policy: String,
        /// Serial number in hex (random when omitted).
        #[clap(long)]
        serial: Option<String>,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Verify a timestamp response.
    Verify {
        /// Response file (PEM or DER).
        #[clap(long)]
        input: String,
        /// TSA certificate (PEM or DER).
        #[clap(long)]
        tsa: String,
        /// Query file to check the imprint and nonce against.
        #[clap(long)]
        query: Option<String>,
        /// Data file to check the message imprint against.
        #[clap(long)]
        data: Option<String>,
    },
    /// Print a timestamp response as text.
    Info {
        /// Response file (PEM or DER).
        #[clap(long)]
        input: String,
    },
}

/// OCSP requests and responses.
#[derive(Debug, Parser)]
pub struct ArgsOcsp {
    #[clap(subcommand)]
    pub op: OcspOp,
}

/// OCSP operations.
#[derive(Debug, Subcommand)]
pub enum OcspOp {
    /// Build an OCSP request for a certificate.
    Request {
        /// Certificate to query (PEM or DER).
        #[clap(long)]
        cert: String,
        /// Issuer certificate (PEM or DER).
        #[clap(long)]
        issuer: String,
        /// Hash algorithm for the certificate identifier.
        #[clap(long, default_value = "sha1")]
        hash: HashAlgorithm,
        /// Add a caller-supplied nonce in hex.
        #[clap(long)]
        nonce: Option<String>,
        /// Write DER instead of PEM.
        #[clap(long, default_value_t = false)]
        der: bool,
        /// Output file (defaults to stdout).
        #[clap(long)]
        out: Option<String>,
    },
    /// Verify an OCSP response signature.
    Verify {
        /// OCSP response file (PEM or DER).
        input: String,
        /// Issuer certificate (PEM or DER).
        #[clap(long)]
        issuer: String,
        /// Optional queried certificate, to check the response status.
        #[clap(long)]
        cert: Option<String>,
        /// Expected nonce in hex, when the request used one.
        #[clap(long)]
        nonce: Option<String>,
    },
    /// Print an OCSP response as text.
    Info {
        /// OCSP response file (PEM or DER).
        input: String,
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

/// Leaf certificate purpose for path validation.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum CertPurpose {
    Any,
    SslServer,
    SslClient,
    SmimeSign,
    SmimeEncrypt,
    CodeSigning,
    OcspHelper,
    TimeStamping,
    CrlSign,
}

/// CMS content cipher.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum CmsCipher {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    DesEde3Cbc,
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
