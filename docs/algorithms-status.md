# Algorithm & asm porting status

Snapshot as of 2026-10-04 (parity follow-ups: CBC-HMAC-SHA AEADs, CTS variants,
KW-INV, DES3-WRAP, CFB1/8, GCM-SIV key lengths, RSA/ECDSA/DSA digest
coverage, DSA parameter generation, RFC 7919 ffdhe groups; SM2 encryption
and key exchange; Keccak-224/384, KECCAK-KMAC-128/256 and SHA2-256-192;
X.509 / PKCS#7 / PKCS#12).
Reference trees: `crown-ref/openssl` (Apache-2.0)
and `crown-ref/boringssl` (the BoringSSL stitched AEADs; both vendors are
dual-licensed under the CRYPTOGAMS license for the perlasm modules).

## 1. x86_64 perlasm → jsasm porting status

### Done (wired into crown, symbol parity with perl re-verified)

| OpenSSL script | crown file |
|---|---|
| `crypto/aes/asm/aes-x86_64.pl` | `crown/src/block/aes/ttable.ts` |
| `crypto/aes/asm/aesni-x86_64.pl` | `crown/src/block/aes/aesni/x86_64.ts` (+ NOTES.md) |
| `crypto/aes/asm/bsaes-x86_64.pl` | `crown/src/block/aes/bsaes/x86_64.ts` (+ NOTES.md) |
| `crypto/aes/asm/vpaes-x86_64.pl` | `crown/src/block/aes/vpaes/x86_64.ts` |
| `crypto/bn/asm/x86_64-mont.pl` | `crown/src/bn/x86_64.ts` (`bn_mul_mont`; byte-identical reassembly verified) |
| `crypto/bn/asm/x86_64-mont5.pl` | `crown/src/bn/mont5_x86_64.ts` (`bn_power5`/gather5 + the `bn_sqr8x_internal`/`bn_sqrx8x_internal` continuations mont.pl needs) |
| `crypto/bn/asm/rsaz-x86_64.pl` | `crown/src/bn/rsaz_x86_64.ts` (512-bit RSAZ helpers; `$addx=1` pin) |
| `crypto/bn/asm/rsaz-avx2.pl` | `crown/src/bn/rsaz_avx2_x86_64.ts` (1024-bit AVX2 RSAZ helpers; `$avx>1`/`$addx=1` pins; + NOTES.md) |
| `crypto/camellia/asm/cmll-x86_64.pl` | `crown/src/block/camellia/x86_64.ts` |
| `crypto/chacha/asm/chacha-x86_64.pl` | `crown/src/stream/chacha20/x86_64.ts` |
| `boringSSL crypto/cipher/asm/chacha20_poly1305_x86_64.pl` | `crown/src/aead/chacha20poly1305/x86_64.ts` (`_CET_ENDBR` expanded, SSE4.1+AVX2 dispatch in Rust) |
| `crypto/ec/asm/x25519-x86_64.pl` | `crown/src/ed25519/x86_64.ts` (fe51 for ed25519, fe64 for x25519; `$addx=1` pin) |
| `crypto/ec/asm/ecp_nistz256-x86_64.pl` | `crown/src/ec/nistz256/x86_64.ts` (+ NOTES.md; `driver.rs` dispatches P-256 scalar mult, w5 + precomputed w7) |
| `crypto/md5/asm/md5-x86_64.pl` | `crown/src/hash/md5/block/x86_64.ts` |
| `crypto/modes/asm/aesni-gcm-x86_64.pl` | `crown/src/aead/gcm/x86_64.ts` (stitch; wired into AES-GCM seal/open for the bulk) |
| `crypto/modes/asm/ghash-x86_64.pl` | `crown/src/block/aes/gcm/x86_64.ts` (dispatch live in `block::aes::gcm::ghash`; `gcm_init_avx` + `gcm_ghash_avx` ported and wired; `gcm_gmult_avx` is the upstream alias of the clmul body) |
| `crypto/poly1305/asm/poly1305-x86_64.pl` | `crown/src/mac/poly1305/x86_64.ts` |
| `crypto/rc4/asm/rc4-x86_64.pl` | `crown/src/stream/rc4/xor_key_stream/x86_64.ts` |
| `crypto/rc4/asm/rc4-md5-x86_64.pl` | `crown/src/stream/rc4/md5_enc/x86_64.ts` (+ NOTES.md) |
| `crypto/sha/asm/sha1-x86_64.pl` | `crown/src/hash/sha1/block/x86_64.ts` |
| `crypto/sha/asm/sha512-x86_64.pl` | `crown/src/hash/sha256/block/x86_64.ts` + `sha512/block/x86_64.ts` |
| `crypto/sha/asm/keccak1600-x86_64.pl` | `crown/src/hash/sha3/x86_64.ts` |
| `crypto/sm3/asm/sm3-x86_64.pl` | `crown/src/hash/sm3/x86_64.ts` |
| `crypto/sm4/asm/sm4-x86_64.pl` | `crown/src/block/sm4/x86_64.ts` |
| `crypto/whrlpool/asm/wp-x86_64.pl` | `crown/src/hash/whirlpool/x86_64.ts` (+ NOTES.md) |
| `crypto/ml_dsa/asm/ml_dsa_ntt-x86_64.pl` (upstream master) | `crown/src/ml_dsa/ntt_x86_64.ts` (frozen perl output; AVX2 dispatches `ntt`/`ntt_inverse`/`ntt_mult`) |
| `crypto/aes/asm/aesni-xts-avx512.pl` | `crown/src/block/aes/xts_avx512/x86_64.ts` (VAES+AVX512 XTS; `aesni_xts_avx512_eligible` gates the 128/256-bit bodies, wired into `modes::xts`) |

The ports whose perl probe used to be evaluated without `$ENV{CC}` (so
`$avx`/`$addx`/`$shaext` never fired) have been regenerated from the stock
configuration and now carry the full tier set: `chacha-x86_64.pl` (8x AVX2,
8x AVX512VL, 16x AVX512F, 4x XOP), `sha1-x86_64.pl` (AVX, AVX2),
`sha512-x86_64.pl` (AVX/AVX2/XOP for both SHA-256 and SHA-512),
`ecp_nistz256-x86_64.pl` (`$addx=1` ADX/BMI2 bodies and `$avx=2` AVX2
gathers), `poly1305-x86_64.pl` (AVX, AVX2, AVX512F+VL+BW with VPMADD52) and
`aesni-sha256-x86_64.pl` (shaext, XOP, AVX2). Their `.ts` files are
byte-comparable with the upstream perlasm output; the entry points
self-dispatch on `OPENSSL_ia32cap_P` except poly1305, which uses
`poly1305_init`'s function table like `crypto/poly1305/poly1305.c`.

### Remaining, by bucket

- **hash bucket: complete.** Everything with a crown-side consumer is translated.
  Re-generated each perl and compared exported symbols against the `.ts` files;
  all match.
- **aead-related:** `aesni-gcm`, `chacha20_poly1305`, `aesni-sha1-x86_64.pl`
  and `aesni-sha256-x86_64.pl` are ported and wired: the TLS
  `AES-CBC-HMAC-SHA{1,256}` AEADs live in `aead::cbc_hmac` (software path on
  all targets, stitched bulk on x86_64+AES-NI). `sha1-mb-x86_64.pl` and
  `sha256-mb-x86_64.pl` are translated (`hash/sha1/mb`, `hash/sha256/mb`)
  but unwired: the multi-block ciphers are only consumed by the TLS
  CBC-HMAC stitched ciphers' pipelined path, which crown does not implement.
- **not ported, crown consumer exists:**
  `crypto/modes/asm/aes-gcm-avx512.pl` (VAES+VPCLMULQDQ+AVX512 GCM; 4985-line
  script plus the `cipher_aes_gcm_hw_vaes_avx512.inc` driver, which needs a
  second GCM context that mirrors `GCM128_CONTEXT`) and
  `crypto/bn/asm/rsaz-{2k,3k,4k}-{avx512,avxifma}.pl` + `rsaz_exp_x2.c` (the
  52-bit-digit AMS driver for RSA-2048/3072/4096 modulus halves). Both need
  AVX512 (and AVX512-IFMA / AVX-IFMA) hardware that the development machine
  and the CI runners do not have, so neither the translation nor the
  dispatch could be validated end-to-end yet.
- **translated but unwired, low value:** `aesni_ocb_encrypt/decrypt`
  (OCB3 is generic in crown) needs the caller-managed L-table/offset/checksum
  protocol from `crypto/modes/ocb128.c`; `aesni_ccm64_encrypt_blocks/
  decrypt_blocks` needs the message-body driver from `crypto/modes/ccm128.c`;
  `SHA3_absorb`/`SHA3_squeeze` (the sponge loops stay in Rust; the fused asm
  is worth roughly 5-10% and carries delicate `next`-call bookkeeping).
- **no crown consumer:** `keccak1600x4-avx512vl.pl` (4-way SHA3; crown sha3 is single-stream;
  `keccak1600-avx2/avx512/avx512vl.pl` are not even referenced by this
  OpenSSL's `build.info`).
- **remaining:** `bn/` `gf2m` (the `mul_2x2` primitive is translated and
  tested, but binary-field EC — the only consumer — is not implemented;
  see `crown/src/bn/gf2m.rs`). Everything else is now translated and
  dispatched: `ec/` (`x25519-x86_64.pl`, `ecp_nistz256-x86_64.pl` via
  `ec::nistz256::driver`), `bn/` (`mont`, `mont5`, `rsaz-x86_64` and
  `rsaz-avx2` via `bn::rsaz::mod_exp`), `aes/` (`aesni-xts-avx512.pl` via
  `modes::xts`) and `ml_dsa/` (`ml_dsa_ntt`).

### Wiring status

All of the previously "dispatch pending" asm is wired: `bn_mul_mont`
and the mont5 `bn_power5`/gather5 family drive `Montgomery::pow_consttime`
(RSA private-key paths); fe51/fe64 feed ed25519 and x25519; the
chacha20-poly1305 and aesni-gcm stitches back their AEADs; ghash's
`gcm_ghash_avx` is live; vpaes/bsaes sit in the AES block/CBC/XTS dispatch;
rc4 and aes-ctr32 are live. `wp-x86_64.pl` is ported and wired into
`hash/whirlpool` behind `feature="asm"` (software `block_soft` remains the
fallback and the test oracle).

The AES-NI bulk routines that only had Rust per-block loops behind them are
now wired: `modes::xts` hands a whole data unit to
`aesni_xts_avx512_*_avx512` (when VAES+AVX512 and the 128/256-bit key
schedule allow it) or `aesni_xts_encrypt`/`aesni_xts_decrypt`, both of which
handle ciphertext stealing; ECB reaches `aesni_ecb_encrypt` through the new
defaulted `BlockCipher::bulk_crypt` hook. The GB tweak convention and the
non-AES ciphers stay on the portable path.

The RSAZ 512/1024 helpers (`rsaz-x86_64.pl` / `rsaz-avx2.pl`) are
dispatched: `crown::bn::rsaz::mod_exp` ports `rsaz_exp.c` and
`Montgomery::pow_consttime` routes 512-/1024-bit moduli (RSA-1024/2048
CRT halves) through it, with the mont5 stack as fallback — see
`crown/src/bn/rsaz/NOTES.md`.

The nistz256 module is dispatched the same way: `ec::nistz256::driver`
ports `ecp_nistz256.c` (w5 windowed ladder for variable points, the
precomputed w7 generator table for `mul_base`) and `crate::ec` routes
P-256 through it — see `crown/src/ec/nistz256/NOTES.md`. Its ADX/BMI2 and
AVX2-gather tiers self-dispatch inside the assembly.

ML-DSA's `ml_dsa_ntt` is ported as a frozen build of the upstream perl
output (the vendored 3.5.8 tree predates the script) and dispatches
`ntt`/`ntt_inverse`/`ntt_mult` when AVX2 is available — see
`crown/src/ml_dsa/NOTES.md`.

## 2. Algorithm coverage: crown vs OpenSSL (default provider)

### crown gaps — hash (4) — ALL CLOSED 2026-09-26

| algorithm | openssl source | crown status |
|---|---|---|
| RIPEMD-160 | `crypto/ripemd` (no x86_64 asm upstream) | implemented (`hash/ripemd160`), RFC 2289 vectors |
| Whirlpool | `crypto/whrlpool` + `wp-x86_64.pl` | implemented (`hash/whirlpool`), ISO/IEC 10118-3 vectors verified against a locally compiled OpenSSL reference; `wp-x86_64.pl` ported and wired under `feature="asm"` |
| MDC-2 | `crypto/mdc2` (DES-based) | implemented (`hash/mdc2`), both pad types (PAD_1/PAD_2) with OpenSSL vectors |
| MD5-SHA1 | `md5_sha1_prov.c` (TLS composite) | implemented (`hash/md5_sha1`) |

All four are registered in `envelope::EvpHash` (`new_ripemd160`, `new_whirlpool`,
`new_mdc2`, `new_md5_sha1`).

### crown gaps — hash leftovers — ALL CLOSED 2026-10-03

| algorithm | openssl source | crown status |
|---|---|---|
| Keccak-224 / Keccak-384 | `providers/implementations/digests/sha3_prov.c` (`\x01` pad) | implemented (`hash/sha3::new_legacy_keccak224/384`); the 224/256/384/512 widths are registered in `envelope::EvpHash` as `new_keccak224/…/new_keccak512` |
| KECCAK-KMAC-128 / KECCAK-KMAC-256 | `sha3_prov.c` (`IMPLEMENT_KMAC_functions`, `\x04` pad, XOF) | implemented (`hash/sha3::new_keccak_kmac128/256`); plain Keccak sponge with KMAC's padding, default 32/64-byte output plus arbitrary squeeze via `CoreRead`; registered as `new_keccak_kmac_128/256` |
| SHA2-256-192 | `crypto/sha/sha256.c` (`ossl_sha256_192_init`, truncated output) | implemented (`hash/sha256::new256_192` / `sum256_192`): standard SHA-256 truncated to its leftmost 192 bits (RFC 8554 SHA-256/192); registered as `new_sha2_256_192` |

Verified against the locally built OpenSSL 3.5.8 CLI
(`openssl dgst -keccak-224|384|512`, `-keccak-kmac-128|256 [-xoflen N]`,
`-sha256-192`) for empty, `abc` and a 349-byte multi-block message, plus a
randomized RustCrypto `sha3` interop test for the four legacy Keccak widths.

### crown gaps — MAC — ALL CLOSED 2026-09-26 (software; envelope EvpMac surface does not exist yet)

| MAC | crown status |
|---|---|
| CMAC | implemented (`mac/cmac`, generic over `BlockCipher` + const block size; RFC 4493 AES-128 + OpenSSL 3DES-CMAC vectors) |
| GMAC | implemented (`mac/gmac`, incremental GHASH over any 16-byte-block `BlockCipher`, 96-bit IV; OpenSSL-generated vectors) |
| SipHash-2-4 (64/128-bit) | implemented (`mac/siphash`; 30 canonical reference vectors + streaming) |
| KMAC128/KMAC256 (+XOF) | implemented (`mac/kmac`, on existing cSHAKE; SP 800-185 sample vectors cross-checked against OpenSSL CLI and a validated local Keccak reference) |
| BLAKE2BMAC/BLAKE2SMAC | already covered by keyed BLAKE2 (`Blake2bVariable::new(Some(key))`) |

### crown gaps — modes/AEAD — ALL CLOSED 2026-09-26 (software; envelope surface unchanged)

| algorithm | openssl source | crown status |
|---|---|---|
| AES-XTS (128/256) | `crypto/modes/xts128.c` + `cipher_aes_xts.c` | implemented (`modes/xts`), IEEE 1619-2007 vectors + ciphertext-stealing set from `evpciph_aes_common.txt`; duplicate-key and 2^20-block limits enforced |
| SM4-XTS | `cipher_sm4_xts.c` | implemented (`modes/xts`, `Xts<Sm4>`), both IEEE and GB/T 17964-2021 (`encrypt_gb`) variants, vectors from `evpciph_sm4.txt` |
| AES-SIV (128/192/256) | `crypto/modes/siv128.c` + `cipher_aes_siv.c` | implemented (`aead/siv`), RFC 5297 A.1/A.2 + `evpciph_aes_siv.txt` vectors; tag = SIV, nonce passed as AAD like OpenSSL |
| FF1 (SP 800-38G) | — | implemented (`modes/ff1`): AES-CBC-MAC Feistel, 10 rounds, radix 2..=65536, AES-128/192/256 by key length, decimal helper; NIST FF1samples.pdf #1/#2/#3 (radix 10 and 36) |
| AES-GCM-SIV (128/192/256) | `cipher_aes_gcm_siv*.c` | implemented (`aead::gcm_siv`); 192/256 follow OpenSSL's extension (message-encryption key length = master key length), vectors from a locally built OpenSSL 3.5.8 |
| ASCON-AEAD128 | `ascon` | implemented (`aead::ascon`) |
| Key Wrap (KW/KWP + INV variants) | `crypto/modes/wrap128.c` | implemented (`modes::kw`); `WRAP-INV`/`WRAP-PAD-INV` run the RFC 3394 loop with the inverse cipher |
| CTS (CS1/CS2/CS3) | `crypto/modes/cts128.c` + `cipher_cts.c` | implemented (`modes::cts`); CS3 partial layout matches OpenSSL/Kerberos (RFC 2040 §8 post-errata) |
| DES-X(EX) | `cipher_desx.c` | implemented (`block::des::Desx`) |
| DES3-WRAP | RFC 3217 (`e_des3.c`) | implemented (`modes::kw::des3_key_wrap`); no parity fixup, matching OpenSSL's `DES3-WRAP` |

### crown gaps — KDF — ALL CLOSED 2026-09-26 (software; envelope surface does not exist yet)

| KDF | openssl source | crown status |
|---|---|---|
| TLS1-PRF | `kdfs/tls1_prf.c` | implemented (`kdf/tls1_prf`), TLS 1.2 single-hash + TLS 1.0/1.1 MD5-SHA1 dual PRF; NIST vectors from `evpkdf_tls12_prf.txt`/`evpkdf_tls11_prf.txt` |
| SSKDF | `kdfs/sskdf.c` | implemented (`kdf/sskdf`): hash, HMAC and KMAC128/256 H(x); `evpkdf_ss.txt` vectors |
| X963KDF | `kdfs/sskdf.c` (shared) | implemented (`kdf/sskdf::x963_derive_hash`), counter appended; NIST `evpkdf_x963.txt` vectors |
| X942KDF | `kdfs/x942kdf.c` | implemented (`kdf/x942kdf`) with DER OtherInfo encoder (keyInfo/partyU/partyV/suppPub/suppPriv, keybits = 8×KEK len of the CEK alg); RFC 3565 + generated vectors, cross-checked against the OpenSSL 3.5.8 CLI |
| SSHKDF | `kdfs/sshkdf.c` | implemented (`kdf/sshkdf`), types A-F; NIST CAVS `evpkdf_ssh.txt` vectors |
| KRB5KDF | `kdfs/krb5kdf.c` | implemented (`kdf/krb5kdf`): n-fold + block chaining, AES-128/256-CBC and DES3 (parity fixup + raw 21-byte form); RFC 3961 vectors |
| PKCS12KDF | `kdfs/pkcs12kdf.c` | implemented (`kdf/pkcs12kdf`), ids 1/2/3; vectors generated with the OpenSSL CLI |
| PBKDF1 | `kdfs/pbkdf1.c` | implemented (`kdf/pbkdf1`); `evpkdf_pbkdf1.txt` vectors incl. MD2 |
| KBKDF | `kdfs/kbkdf.c` | implemented (`kdf/kbkdf`): SP 800-108 counter/feedback with HMAC/CMAC (r=8/16/32, L/separator switches) + single-shot KMAC128/256; `evpkdf_kbkdf_*.txt` + CLI vectors |
| SRTP-KDF | `kdfs/srtpkdf.c` | implemented (`kdf/srtpkdf`), RFC 3711 AES-CM labels 0-7 with kdr rate handling; `evpkdf_srtp.txt` vectors |
| IKEv2-KDF | `kdfs/ikev2kdf.c` | implemented (`kdf/ikev2kdf`): GEN/REKEY seedkey + DKM (Child SA/DH) with the RFC 7296 left-padding rules; `evpkdf_ikev2.txt` vectors |

Digest parameters are runtime-selectable via `kdf::{HashFactory, HmacFactory}`
(fn pointers onto `EvpHash::new_*` / `EvpHash::new_*_hmac`), mirroring
EVP_KDF's digest option. HKDF/PBKDF2/scrypt/argon2 already existed
(`kdf/hkdf`, `password_hash`).

### crown gaps — asymmetric — partially closed 2026-09-28 (software)

| algorithm | openssl source | crown status |
|---|---|---|
| Ed25519 | `crypto/ec/curve25519.c` | implemented (`ed25519`): 51-bit-limb field arithmetic, ref10 invert/pow22523 chains, extended-coordinate group ops, constant-time 4-bit-window scalar mult; RFC 8032 section 7.1 vectors, CLI cross-checked |
| Ed448 | `crypto/ec/curve448/` | implemented (`ed448` + shared `curve448::fe`): untwisted Edwards edwards448 (a=1, d=-39081) in extended coordinates, RFC 8032 §5.2.4 complete add/dbl, dom4/SHAKE256 sign-verify with required context; pure Ed448 (phflag=0) + Ed448ph (phflag=1, PH=SHAKE256(.,64)); RFC 8032 §7.4 vectors (blank, 1/11/12/13/64/256/1023 octets, 1 octet with context) and §7.5 Ed448ph vectors (abc blank-context, abc context "foo") |
| RSA | `crypto/rsa` + `crypto/bn` | implemented (`rsa` on `bn`): raw/PKCS#1 v1.5/OAEP encryption, PKCS#1 v1.5/PSS signatures, CRT private path, key generation (top-two-bit primes, small-prime sieve, 64 MR rounds, FIPS 186-4 distance), PKCS#1 DER + PKCS#8 parse; all directions cross-checked against the OpenSSL 3.5.8 CLI |
| RSA-PSS/other digests | | PSS accepts every registered digest; PKCS#1 v1.5 accepts md5, sha1, sha224/256/384/512, sha512-224, sha512-256, sha3-224/256/384/512, sm3 (OpenSSL's sm3WithRSAEncryption-OID quirk reproduced) and ripemd160 via the DigestInfo table; md5-sha1 is signed raw. Signatures cross-checked byte-exact against the OpenSSL CLI |
| X25519 | `crypto/ec/curve25519.c` | implemented (`x25519`): Montgomery ladder over radix-2^64 field ops, fe64 asm (`x25519_fe64_*`) wired in when `asm` is on; RFC 7748 §5.2/§6.1 vectors |
| X448 | `crypto/ec/curve448/` | implemented (`x448` + shared `curve448::fe`): Montgomery ladder over radix-2^56 (8×56-bit limbs) field ops for p = 2^448-2^224-1, software only; RFC 7748 §5.2 vectors 1-2, §5.2 iterative (1 iter), §6.2 Diffie-Hellman |
| DSA/ECDSA digests | | ECDSA and DSA accept sha1, sha224, sha256, sha384, sha512, sha3-224/256/384/512, sm3, ripemd160 (ECDSA also ripemd160); OpenSSL CLI cross-checked both ways |
| ML-KEM/ML-DSA/SLH-DSA/LMS | | ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) implemented; LMS not started |
| RAND | `crypto/rand` | not started; randomized RSA operations take a caller-supplied `Rng` instead |

### crown gaps — PKI (`asn1`/`x509`/`pkcs7`/`pkcs12`) — CLOSED 2026-10-04 (software)

| area | openssl source | crown status |
|---|---|---|
| ASN.1 DER/BER | `crypto/asn1` | `asn1`: strict DER reader/writer plus BER indefinite lengths and constructed OCTET STRINGs (real PKCS#7 files), `ObjectIdentifier` with the PKI OID registry, PEM armour with a built-in base64 codec, UTCTime/GeneralizedTime |
| X.509 certificates | `crypto/x509` | `x509::Certificate`: parse/encode (byte-exact re-encode), PEM, v1/v2/v3, RDNs with UTF8/Printable/IA5/Teletex/BMP strings, validity, unique IDs, all common extensions (basicConstraints, keyUsage, extKeyUsage, SAN/IAN, SKI/AKI, CRL DP, AIA, certificatePolicies), fingerprint, signing and verification |
| X.509 CSRs | `crypto/x509/x509_req.c` | `x509::CertificationRequest`: parse/encode, attributes, proof-of-possession verification, builder |
| CRLs | `crypto/x509/x509_crl.c` | `x509::CertificateList`: parse/encode, entry extensions, signature verification, `is_revoked`, builder |
| Public keys | `crypto/x509/x_pubkey.c` | `SubjectPublicKeyInfo` for RSA, NIST EC (P-256/384/521), Ed25519/Ed448, X25519/X448, SM2, DSA, ML-DSA, SLH-DSA |
| PKCS#8 | `crypto/pkcs8` | `x509::PrivateKeyInfo` (RSA/EC/Ed/X/SM2/DSA/ML-DSA/SLH-DSA, OpenSSL ML-DSA seed+expanded wrapper) and `EncryptedPrivateKeyInfo` |
| PBE | `crypto/evp/p5_crpt*`, `p12_crpt.c` | `x509::pbe`: PBKDF2 (runtime PRF), PBES2 (AES-128/192/256-CBC, 3DES-CBC) and the legacy PKCS#12 schemes (RC4-40/128, RC2-40, 2/3-key 3DES) with the BMP password encoding |
| PKCS#7 / CMS | `crypto/pkcs7`, `crypto/cms` | `pkcs7::SignedData`: parse/verify/create, attached and detached, signed attributes (contentType/messageDigest/signingTime) with byte-exact SET re-tagging, RSA PKCS#1 v1.5 (CMS `rsaEncryption` signatureAlgorithm + separate digest) and PSS, ECDSA, Ed25519/Ed448, SM2, DSA, ML-DSA, SLH-DSA; BER input accepted. EnvelopedData is not implemented |
| PKCS#12 | `crypto/pkcs12` | `pkcs12::Pfx`: parse/encode, MAC verification (HMAC-SHA1/SHA256 with the PKCS#12 KDF and OpenSSL's empty-password rule), bag decoding (key/shrouded key/cert/CRL/secret/safeContents), attributes (friendlyName/localKeyId), PBES2 + legacy PBE encrypted content, builder producing OpenSSL-readable files |

Signature dispatch is shared (`x509::SignatureAlgorithm`), including the
`rsaEncryption`-in-CMS special case, MD2/MD4/MD5/SHA-1/SHA-2/SHA-3/SM3/
RIPEMD-160 digests, and an explicit SM2 identity override because OpenSSL's
provider CLI signs SM2 with an empty ID unless `distid` is given (the GM/T
default identity is used by default).

Verification scope at the time of this section: `Certificate::verify`/
`verify_signature` covered name chaining, validity windows, CA
basicConstraints/keyUsage and the signature. Superseded by the sections below
(`PKI completion` 2026-10-05 and `PKI round 2` 2026-10-06), which add full
RFC 5280 path validation, OCSP, CMS `EnvelopedData`, CMP, request signing and
name matching.

### PKI consumer wiring (CLI / C ABI / playground) — 2026-10-05

| consumer | exposed |
|---|---|
| `crown-bin` | `crown x509 info`/`fingerprint`/`verify`, `x509 csr-info`/`csr-verify`, `x509 crl-info`/`crl-verify`/`crl-check`; `crown pkcs7 sign`/`verify`/`info`/`extract` (attached and detached, PEM or DER, optional SM2 identity and extra chain certificates); `crown pkcs12 export`/`info`/`verify`/`extract`; `crown pkey info`/`decrypt`/`encrypt`/`pubout` (PKCS#8 and PBES2). Outputs cross-checked both directions with the OpenSSL 3.5.8 CLI: OpenSSL verifies crown-built CMS and reads crown-built PFX (MAC, key, certificates, attributes), and crown reads OpenSSL DER/PEM/BER outputs |
| `crown-cabi` (`crown.h`) | Opaque `Certificate`/`Csr`/`Crl`/`Pkcs7`/`Pkcs12` handles with parse/free; DER and PEM output; subject/issuer/serial/validity/fingerprint/SPKI queries; signature and full chain verification with an optional SM2 identity; CSR self-signature and CRL signature verification plus revocation checks; CMS signer/certificate enumeration, content extraction and verification; PKCS#12 MAC status, bag enumeration (kind, friendlyName, certificate/CRL/PKCS#8 extraction); PKCS#8 decrypt/encrypt (PBES2) and public-key metadata. Buffer outputs use the query pattern (`-2` with the required length) |
| `crown-wasm` + playground | `x509_parse` (certificate/CSR/CRL auto-detect, JSON report), `pkcs7_parse`/`pkcs7_verify`, `pkcs12_parse`, `pkcs8_decrypt`; the playground gains a `Certificates (X.509)` page covering all four modes |

The committed `crown-cabi/include/crown.h` is regenerated from the sources
with `cargo +nightly build -p crown-cabi --features cbindgen` (cbindgen's
expansion needs nightly); this round also pulled in previously missing
declarations that predated it.

### PKI completion: path validation, OCSP and CMS — 2026-10-05

| area | crown status |
|---|---|
| RFC 5280 path validation | `x509::verify`: `Store` (trust anchors + CRLs), `VerifyOptions` (time, max depth, purpose, flags, untrusted intermediates, initial policy set), chain building (AKI/SKI disambiguation, loop protection), signature/validity checks, CA basicConstraints/keyUsage/pathLenConstraint, EKU purposes (TLS server/client, S/MIME sign/encrypt, code signing, OCSP helper, time stamping, CRL signing), name constraints (DNS/email/IP/URI/directoryName/otherName, permitted+excluded subtrees), policy processing (anyPolicy, mappings, requireExplicitPolicy, inhibitAnyPolicy), CRL and delta-CRL revocation with scope/reason checks, OpenSSL `X509_V_ERR_*` codes. Fixtures under `crown/tests/data/pki/verify/` cross-pinned against `openssl verify` (47/48/25/23/43 and the OK cases) |
| new X.509 extensions | typed parse/encode + builders for nameConstraints, policyConstraints, inhibitAnyPolicy, policyMappings, subjectInfoAccess, cRLNumber, deltaCRLIndicator, issuingDistributionPoint (reason flags), reasonCode, invalidityDate, certificateIssuer, freshestCRL, tlsfeature, OCSP no-check, noRevAvail |
| OCSP (RFC 6960) | `ocsp`: request build/parse with nonce, `OcspResponse` status, `BasicOcspResponse`/`ResponseData`/`SingleResponse`/`ResponderId`/`CertStatus`, `CertId` hashing (issuer name + public-key BIT STRING), `OcspResponder` signing, verification with delegated-responder chaining, OCSP-signing EKU and nonce checks; OpenSSL `ocsp` CLI cross-checked both directions |
| CMS (RFC 5652) | `cms`: `EnvelopedData` (RSA PKCS#1 v1.5 and OAEP, ECDH key agreement P-256/384/521, KEK and password recipients; AES-CBC/GCM and 3DES content ciphers), `AuthEnvelopedData` (GCM), `EncryptedData`, `DigestedData`; builder and recipient-side decryption; interoperable with `openssl cms -encrypt/-decrypt` both ways |
| issuance helpers | `CertificateBuilder::from_request` (CSR to certificate), `RevokedCertificate::{new, reason, invalidity_date}`; fixed a pre-existing `TbsCertList` encoder bug (CRL extensions were written with tag [3] instead of [0], so crown could not re-read its own CRLs with extensions and OpenSSL rejected them) |
| consumers | CLI: `x509 verify --trust/--untrusted/--crl/--crl-check/--purpose/--policy-check`, `x509 self-sign`, `x509 issue`, `x509 crl`, `pkcs7 encrypt`/`decrypt`, `ocsp request`/`verify`/`info` (SEC1/PKCS#1 legacy keys accepted). C ABI: `certificate_store_*` chain verification, `cms_encrypt`/`cms_decrypt`/`cms_decrypt_password`, `ocsp_response_verify`. wasm: `x509_verify`, `cms_encrypt`/`cms_decrypt`, `ocsp_verify`; playground modes for chain validation, CMS and OCSP |

| CMP (RFC 4210/9481) | `cmp`: `PkiMessage` (DER/PEM) with `PkiHeader` (pvno 1/2/3, generalInfo helpers for implicitConfirm/confirmWaitTime/certProfile/caCerts), bodies ir/cr/kur/p10cr/rr/ccr/genm/genp/error/certConf/pkiconf/pollReq/pollRep (others preserved), `PkiStatusInfo`, `CertConfirmContent`; protection: signature-based (PKCS#1 v1.5/ECDSA over the RFC 4210 protected part) and password-based (`id-PasswordBasedMac` PBMParameter with constant-time MAC compare). OpenSSL CLI interop: fixtures from `openssl cmp -reqout` parse/re-encode byte-exactly and verify; a crown-built IR is enrolled end-to-end by `openssl cmp`'s mock server (IP → CertConf → PKIConf) and rejected with a wrong password. The client/server transaction state machine (polling, confirmation sequencing, enrollment policy, message routing) and ip/cp/kup/krp/rp/rann bodies are out of scope — this is the message/codec + protection layer |
| CRMF (RFC 4211) | `crmf`: `CertReqMessages`/`CertReqMsg`/`CertRequest`/`CertTemplate` (all optional fields), `OptionalValidity`, proof-of-possession (`raVerified`/signature with `PopoSigningKey` sign+verify/keyEncipherment/keyAgreement), `EncryptedValue`/`PKMACValue`/`PbmParameter` structures, `id-regInfo-certReq` |
| RFC 3161 timestamping | `ts`: `TimeStampReq`/`TimeStampResp` (DER/PEM), `TstInfo` with accuracy/ordering/nonce/tsa, `TimeStampSigner` producing CMS `SignedData` tokens with `signingCertificateV2` signed attributes, `verify`/`verify_request` (imprint + nonce), ESS v1/v2 signing-certificate attributes; OpenSSL `ts` CLI interop both ways (crown verifies OpenSSL responses and `openssl ts -verify` accepts crown tokens) |
| ESS | `ts::SigningCertificateV2` / `EsCertIdV2` (and the v1 form) usable as `id-aa-signingCertificate[V2]` signed attributes |
| attribute certificates (RFC 5755) | `x509::ac`: `AttributeCertificate`/`AttributeCertificateInfo` parse/encode (OpenSSL's `acert*.pem` fixtures re-encode byte-exactly), holder/issuer/V2Form/IssuerSerial/ObjectDigestInfo, validity, attributes, signing and verification, holder matching; accepts the RFC 3281 untagged-extensions form some toolkits still emit |
| CMS `AuthenticatedData` (RFC 5652 9.1) | `cms::AuthenticatedData` with RSA/ECDH/KEK/password recipients, HMAC-SHA-1/224/256/384/512, authAttrs, builder, MAC verification and content recovery; OpenSSL `asn1parse` accepts the output |
| multi-signer CMS | `cms::SignedDataMultiBuilder` (one content, any number of signers with per-signer digest/signature algorithm and extra signed attributes); OpenSSL `cms -verify` verifies the crown-built output |
| write-side legacy keys | the CLI accepts SEC1 `EC PRIVATE KEY` and PKCS#1 `RSA PRIVATE KEY` files |

Still not ported (OpenSSL-only PKI surface):

- Automated fetching of AIA/CRL distribution points and OCSP-based revocation
  inside `verify_certificate`: intermediates and CRLs are caller-supplied.
  The building blocks exist since PKI round 2 (`x509::http`, the
  `ocsp_urls`/`ca_issuer_urls`/`crl_urls`/`freshest_crl_urls` helpers and
  `OcspRequest::post_to`), but `verify_certificate` itself never performs
  network I/O.
- CMS `CompressedData` (needs a compression backend) and the CMP client/server
  transaction state machine (message-level support is implemented).

### crown gaps — other buckets (closed 2026-10-03)

- ARIA/SM4/Camellia/SEED GCM/CCM are wired through the generic
  `aead/gcm` and `aead/ccm`.
- CFB1/CFB8 (1-/8-bit feedback, OpenSSL `AES-*-CFB1/CFB8` et al.) are
  implemented in `modes::cfb` alongside CFB128; vectors from a locally
  built OpenSSL 3.5.8.
- TLS `AES-CBC-HMAC-SHA1/SHA256` AEADs: `aead::cbc_hmac` (software +
  stitched x86_64 asm); OpenSSL-generated golden vectors.

### AEAD/modes additions (this round, software only)

| Algorithm | Spec | crown module | Tests |
|---|---|---|---|
| AES Key Wrap | RFC 3394 | `modes::kw::{key_wrap, key_unwrap}` | RFC 3394 §4.1–4.3 |
| AES Key Wrap with Padding | RFC 5649 | `modes::kw::{key_wrap_padded, key_unwrap_padded}` | RFC 5649 §6 (192-bit KEK, 20- and 7-octet keys) |
| DES-X | — | `block::des::Desx` (`k1 ⊕ DES_k(x ⊕ k2)`) | roundtrip + known DESX vector + zero-whitening ≡ DES |
| CBC-CS3 (ciphertext stealing) | NIST SP 800-38A addendum / RFC 3962 | `modes::cts::Cts` | full-block swap, partial-block steal, length/IV validation |
| AES-GCM-SIV | RFC 8452 | `aead::gcm_siv::AesGcmSiv` (`Aead<16>`) | RFC 8452 App. C.1 (empty/empty, 8-byte PT, 1-byte AAD + 8-byte PT) |
| Ascon-AEAD128 | NIST SP 800-232 | `aead::ascon::AsconAead128` (`Aead<16>`) | 3 KATs vs Ascon v1.2 reference (empty/empty, empty/8-byte PT, 8-byte AAD + 8-byte PT) |

### crown extras (OpenSSL has none)

Anubis, Kasumi, Khazad, MULTI2, Noekeon, RC6, Safer, Skipjack, TEA/XTEA,
Twofish, Salsa20, Rabbit, SOSEMANUK, SOBER128, EAX, bcrypt.

## 3. Test-vector sources for this round

- OpenSSL 3.5.8 system CLI (`openssl dgst` / `openssl mac` / `openssl kdf`)
  where available; the Keccak leftover vectors (legacy Keccak-224..512,
  KECCAK-KMAC-128/256 incl. `-xoflen` squeezes, SHA2-256-192) come from the
  locally built `crown-ref/openssl/apps/openssl` (3.5.8).
- `crown-ref/openssl/test/recipes/30-test_evp_data/`:
  `evpmd_mdc2.txt`, `evpmd_whirlpool.txt` (ISO/IEC 10118-3 set),
  `evpmac_siphash.txt`, `evpmac_cmac_des.txt`, `cmactest.c` (RFC 4493),
  `evpkdf_kbkdf_kmac.txt`, `evpciph_aes_common.txt` / `evpciph_sm4.txt` (XTS),
  `evpciph_aes_siv.txt` (RFC 5297), `evpkdf_tls1{1,2}_prf.txt`,
  `evpkdf_ss.txt`, `evpkdf_x963.txt`, `evpkdf_x942.txt`, `evpkdf_ssh.txt`,
  `evpkdf_krb5.txt`, `evpkdf_pbkdf1.txt`, `evpkdf_kbkdf_counter.txt`,
  `evpkdf_srtp.txt`, `evpkdf_ikev2.txt`, `tested25519.pem` (Ed25519 CLI
  interop), `openssl genrsa`/`openssl dgst`/`openssl pkeyutl` artifacts
  (RSA interop in both directions).
- `crown-ref/boringssl/crypto/cipher/test/chacha20_poly1305_tests.txt`
  (stitched chacha20-poly1305 asm seal/open).
- `crown/tests/data/pki/` (committed): certificates/CSRs/CRLs/PKCS#7/
  PKCS#12/PKCS#8 generated with the locally built OpenSSL 3.5.8 CLI
  (`req -x509`, `x509 -req`, `ca -gencrl`, `cms -sign`, `pkcs12 -export`
  both modern and `-legacy`, `pkcs8 -topk8` plain/PBES2/`-v1 PBE-SHA1-3DES`);
  cross-checked in both directions (crown parses OpenSSL output and the
  OpenSSL CLI verifies crown-built CMS/PFX).
- RFC 2289 (RIPEMD-160), RFC 4493 (AES-CMAC), RFC 5297 (AES-SIV),
  RFC 8032 (Ed25519), RFC 8017 (RSA),
  RFC 3711 (SRTP KDF), RFC 3961 (KRB5KDF), McGrew/Viega GCM test case 4
  (GMAC), NIST SP 800-185 (KMAC samples), NIST CAVS (SSHKDF, X963KDF,
  TLS PRF).

## 4. Golden-vector integration tests

`crown/tests/` runs the two vendored vector trees (submodules
`crown/tests/wycheproof/data` and `crown/tests/cryptography`). Every target
drives whole families and asserts a minimum number of verified vectors, so a
harness cannot silently degrade into skipping everything again.

| target | source | algorithms |
|---|---|---|
| `aead.rs` | wycheproof (`aead.json`, `mac*.json` schemas) | GCM, EAX, CCM, SIV, ChaCha20/XChaCha20-Poly1305, SM4-GCM/CCM, SEED-GCM/CCM, ARIA/Camellia-CCM, AES-CBC-PKCS5 |
| `ind_cpa.rs` | wycheproof | AES/ARIA-CBC-PKCS5, AES-XTS |
| `hmac.rs`, `hkdf.rs` | wycheproof | HMAC (SHA-1/2/3, SHA-512/224, SHA-512/256, SM3), HKDF |
| `mac.rs` | wycheproof + pyca | CMAC (AES/ARIA/Camellia, truncated tags), GMAC, KMAC128/256, SipHash-2-4/-x, HMAC extras, CMAC SP 800-38B (AES/3DES), Poly1305 |
| `rsa.rs` | wycheproof + pyca | RSA PKCS#1 v1.5 verify *and* sign, PSS verify, OAEP decrypt, PKCS#1 decrypt; Ed25519 verify, sign and key derivation |
| `pyca_kdf.rs` | pyca | HKDF (RFC 5869), PBKDF2 (RFC 6070), scrypt (RFC 7914), Argon2id (RFC 9106), ANS X9.63 |
| `pyca_modes.rs` | pyca | AES-XTS (CAVS), AES-SIV, ECB (AES/3DES/SM4), RC4 (incl. offsets) |
| `pyca_block.rs`, `pyca_stream.rs`, `pyca_aead.rs` | pyca | CBC (NIST CAVS), CTR/CFB128/OFB, GCM/OCB3/ChaCha20-Poly1305 seal *and* open, CAVS negative cases |
| `hash.rs` | pyca | MD5, SHA-1/2/3, SHAKE (incl. variable output), SM3, BLAKE2b/2s, HMAC-RIPEMD-160 |
| `pki.rs` | pyca + openssl fixtures | X.509 roots (RSA MD2/SHA-1/SHA-256, ECDSA, Ed25519, Ed448) and a real chain, CSRs (ECDSA/RSA/DSA/MD4, negative case), 100+ PKITS CRLs with 5+ validated against issuers, PKCS#7 (DER/BER/pem certs-only), PKCS#12 (PBES2 AES-256, legacy RC2/3DES, no-password) |

Not covered because crown has no implementation to test against those
vectors: ML-KEM/ML-DSA, AEGIS. DSA/ECDSA/ECDH are now implemented
and pinned by in-module RFC 6979 / RFC 5903 KATs (X448/Ed448/Ed448ph
likewise have RFC 7748/8032 in-module vectors). HOTP/TOTP, PBES2 and FF1
are now implemented with RFC 4226/6238, PKCS#5 and SP 800-38G vectors.
AES-GCM-SIV, Ascon-AEAD128 and
KW/KWP are now implemented and covered by in-module RFC/KAT vectors
rather than the vendored vector trees. The KBKDF
CAVS files are not consumed either: their counter-placement variants
(`CTRLOCATION`, `RLEN`) are not expressible through `kbkdf::FixedInput`,
which the unit tests pin against OpenSSL's EVP vectors instead.

### Bugs these vectors found

- `hash/sm3`: `block_size()` returned 256 instead of 64, corrupting HMAC-SM3.
- `bn`: the Knuth division estimate was corrected against the wrong low half
  (`qhat*b` instead of `b*rhat`), which made ~6% of divisions return
  `q*v > u` — RSA panicked in debug builds or decrypted to garbage in
  release.
- `rsa`: `emsa_pss_verify` skipped RFC 8017 9.1.2 step 8, accepting
  signatures whose maskedDB had nonzero unused leading bits.
- The pyca block/stream/AEAD harnesses matched only one spelling of each
  field name (`keys` vs `KEY`, `plaintext` vs `PLAINTEXT1`, `PT` vs
  `Plaintext`), so almost every vector had been skipped; the wycheproof HMAC
  builder had no SHA-1 arm, skipping that whole file.

## 2. Asymmetric / elliptic-curve status (feat/asymmetric)

| Algorithm | Module | Status |
|---|---|---|
| Short-Weierstrass Jacobian EC (P-256/P-384/P-521) | `crown/src/ec` | done — FIPS 186-4 D.1.2.3/4/5 params (secp256r1/secp384r1/secp521r1); group laws for all three curves; RFC 5903 §8.2/§8.3 scalar-mult KATs |
| ECDH (P-256/P-384/P-521) | `crown/src/ecdh` | done — `generate`/`agree` take a `CurveId`; shared secret is x left-padded to 32/48/66 bytes; RFC 5903 §8.1/§8.2/§8.3 KATs |
| ECDSA (P-256/384/521, SHA-256/384/512) | `crown/src/ecdsa` | done — `sign`/`verify` with explicit `CurveId` + `DigestId`; `sign_sha256`/`verify_sha256` kept as P-256 wrappers; RFC 6979 A.2.5 (P-256/SHA-256), A.2.6 (P-384/SHA-384), A.2.7 (P-521/SHA-512) |
| DSA (FIPS 186-4, 2048/256) | `crown/src/dsa` | done — `dsa_2048_256()` parameter set (RFC 6979 A.2.2 / NIST), `generate`, `sign_sha256`, `verify_sha256`; g^q ≡ 1 mod p sanity + RFC 6979 A.2.2 SHA-256 sample/test KATs |
| DH MODP 2048 (RFC 3526) | `crown/src/dh` | done — modp2048() + generate/agree with y-range checks |
| DH ffdhe groups (RFC 7919) | `crown/src/dh` | done — `ffdhe(bits)` for 2048/3072/4096/6144/8192, constants cross-checked against OpenSSL |
| DSA parameter generation (FIPS 186-4 A.1.2.1.2) | `crown/src/dsa` | done — `generate_params(L, N)` for (2048,224), (2048,256), (3072,256); generated groups validated by the OpenSSL CLI |
| SM2 signature (GM/T 0003.2) | `crown/src/sm2` | done — GM/T sample (d, M="message digest") r/s match |
| SM2 encryption (GB/T 32918.4-2016) | `crown/src/sm2/crypt` | done — raw C1C3C2 and OpenSSL-compatible DER forms; GB/T 32918.1 annex A worked example (fixed k) + OpenSSL CLI interop both directions |
| SM2 key exchange (GB/T 32918.3-2016) | `crown/src/sm2/kap` | done — shared key and S1/S2 confirmation tags; GB/T 32918.3 appendix A vector |
| SM3 x86_64 asm dispatch | `crown/src/hash/sm3` | live — SM2 ZA/KDF/tags ride the ported asm under `feature="asm"` |

## 3. DRBG / OTP / PBES2 status (feat/rand-otp)

| Algorithm | Module | Status |
|---|---|---|
| HMAC_DRBG (SP 800-90A §10.1.2, SHA-256) | `crown/src/drbg` | done — HMAC_DRBG_Update per spec; tests: determinism, reseed/additional change output, distinct entropy |
| Hash_DRBG (SP 800-90A §10.1.1, SHA-256, seedlen 440) | `crown/src/drbg` | done — Hash_df/Hashgen + V update; tests: determinism, reseed/additional change output |
| HOTP (RFC 4226) | `crown/src/otp` | done — dynamic truncation; tests: RFC 4226 Appendix D counters 0..9 |
| TOTP (RFC 6238) | `crown/src/otp` | done — step/t0 parameters; tests: RFC 6238 Appendix B SHA-1 8-digit times 59..20000000000 |
| PBES2 (PKCS #5 v2.1 / RFC 8018 §6.2) | `crown/src/password_hash/pbes2` | done — PBKDF2+AES-128/256-CBC + 3DES-EDE-CBC, IV from KDF output prepended to CT; tests: roundtrips, wrong-password reject, PBKDF2 split KAT. HKDF variant returns `InvalidParameterStr` (not implemented). |

Notes:
- `HMAC::new(hash_fn, key)` + `CoreWrite::write_all` + `Hash::sum` is the
  one-shot MAC pattern; PBES2 IV = `dk[key_len..key_len+block_size]` and is
  prepended to the CBC of PKCS#7-padded plaintext (output = `iv || ct`).
- Crown CBC decrypters follow the Go `BlockMode` convention: the processing
  entry point is `encrypt()`; `decrypt()` is `unreachable!()`.

## 5. PKI round 2: name matching, lossless extensions, issuance and OCSP request signing — 2026-10-06

| area | crown status |
|---|---|
| name matching (`X509_check_*`) | `x509::matching`: `Certificate::check_host`/`check_email`/`check_ip`/`check_ip_asc`. OpenSSL semantics pinned with the CLI: case-insensitive DNS with trailing-dot tolerance, wildcards only in the leftmost label (partial wildcards and empty star matches included), one-label wildcard reach, CN fallback only when the SAN has no dNSName entries, email local-part case-sensitive + domain case-insensitive, IPv4-mapped IPv6 equivalence, literal IPv4/IPv6 parsing. Fixtures + expectations in `crown/tests/matching.rs`, cross-checked with `openssl verify -verify_hostname/-verify_email/-verify_ip` |
| `partial_chain` | `VerifyFlags::partial_chain` mirrors `X509_V_FLAG_PARTIAL_CHAIN`: a trusted non-self-signed chain element terminates the chain (trusted intermediate, or the leaf itself pinned as anchor). Without the flag a trusted non-self-signed element is only a link, so the build continues towards a self-signed anchor; the depth-zero/depth-n error mapping now matches OpenSSL (20 at depth 0, 2 above) |
| lossless extensions | `certificatePolicies` keeps `PolicyInformation` with CPS-URI and userNotice qualifiers (DisplayText retains its string tag so re-encoding is byte-exact); `crlDistributionPoints`/`freshestCRL` keep full `DistributionPoint` (fullName, nameRelativeToCRLIssuer, ReasonFlags with DER-minimal unused bits, cRLIssuer); `authorityInfoAccess` keeps every `AccessDescription` (arbitrary accessMethod and GeneralName) with `ocsp_uris()`/`ca_issuers_uris()` conveniences; `subjectDirectoryAttributes` is decoded as attribute sets. CRL scope matching in `verify` compares full distribution point names (RFC 5280 6.3.3) instead of URI text |
| certificate fetch helpers | `Certificate::ocsp_urls()`/`ca_issuer_urls()` (AIA) and `crl_urls()`/`freshest_crl_urls()` (CRL DP) extract the URLs applications need |
| CSR `extensionRequest` | `attribute::extension_request`/`parse_extension_request`, `CertificationRequest::extensions()`, `CertificateBuilder::request_extensions()`; the OpenSSL-generated `extreq.csr` fixture parses, re-encodes byte-exactly and its requested SAN/KU/EKU are carried into an issued certificate |
| OCSP request signing | `OcspRequest::sign` (signature over the TBSRequest, `requestorName` set to the signer subject like OpenSSL's `OCSP_request_sign`, certificates attached) and `OcspRequest::verify_signature` (explicit signer or attached certificates; a key-type mismatch is a non-match, not an error). `requestorName` is preserved on parse so OpenSSL-signed requests re-encode byte-exactly and verify |
| HTTP fetch (std only) | `x509::http`: `get`/`post` with redirects (301/302/303/307/308), chunked decoding, body/header caps and timeouts; plain `http://` only (`https` fails explicitly — PKI payloads are caller-verifiable). `OcspRequest::post_to` posts a request to a responder URL and parses the reply. Tests drive a local `TcpListener`, no external network |
| `DisplayText`/`VisibleString` | `asn1::der` gained VisibleString (`0x1a`) decoding; `x509::DisplayText` (tag + octets) keeps notice text byte-exact, as OpenSSL emits VisibleString |
