# Algorithm & asm porting status

Snapshot as of 2026-09-27. Reference trees: `crown-ref/openssl` (Apache-2.0)
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
| `crypto/camellia/asm/cmll-x86_64.pl` | `crown/src/block/camellia/x86_64.ts` |
| `crypto/chacha/asm/chacha-x86_64.pl` | `crown/src/stream/chacha20/x86_64.ts` |
| `boringSSL crypto/cipher/asm/chacha20_poly1305_x86_64.pl` | `crown/src/aead/chacha20poly1305/x86_64.ts` (`_CET_ENDBR` expanded, SSE4.1+AVX2 dispatch in Rust) |
| `crypto/ec/asm/x25519-x86_64.pl` | `crown/src/ed25519/x86_64.ts` (fe51 for ed25519, fe64 for x25519; `$addx=1` pin) |
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
| `crypto/whrlpool/asm/wp-x86_64.pl` | — (no crown whirlpool module yet) |

### Remaining, by bucket

- **hash bucket: complete.** Everything with a crown-side consumer is translated.
  Re-generated each perl and compared exported symbols against the `.ts` files;
  all match.
- **aead-related:** `aesni-gcm` and `chacha20_poly1305` are ported;
  `aesni-sha1-x86_64.pl`, `aesni-sha256-x86_64.pl`, `sha1-mb-x86_64.pl`,
  `sha256-mb-x86_64.pl` remain. Note: `sha{1,256}-multi_block` in this OpenSSL
  version are only consumed by the TLS CBC-HMAC-SHA stitched ciphers
  (`cipher_aes_cbc_hmac_sha{1,256}_hw.c`), so they belong to the aead round.
- **no crown consumer:** `wp-x86_64.pl` (whirlpool),
  `keccak1600x4-avx512vl.pl` (4-way SHA3; crown sha3 is single-stream;
  `keccak1600-avx2/avx512/avx512vl.pl` are not even referenced by this
  OpenSSL's `build.info`).
- **not yet visited buckets:** `bn/` (`rsaz-*`, `gf2m` — mont and mont5 are
  done), `ec/` (`ecp_nistz256`; x25519 is done), `ml_dsa/` (`ml_dsa_ntt`).

### Wiring status of the newly ported asm

Compiled and unit-tested against the portable implementations, dispatch not
yet switched:

All of the previously "dispatch pending" asm is now wired: `bn_mul_mont`
and the mont5 `bn_power5`/gather5 family drive `Montgomery::pow_consttime`
(RSA private-key paths); fe51/fe64 feed ed25519 and x25519; the
chacha20-poly1305 and aesni-gcm stitches back their AEADs; ghash's
`gcm_ghash_avx` is live; vpaes/bsaes sit in the AES block/CBC/XTS dispatch;
rc4 and aes-ctr32 are live.

## 2. Algorithm coverage: crown vs OpenSSL (default provider)

### crown gaps — hash (4) — ALL CLOSED 2026-09-26

| algorithm | openssl source | crown status |
|---|---|---|
| RIPEMD-160 | `crypto/ripemd` (no x86_64 asm upstream) | implemented (`hash/ripemd160`), RFC 2289 vectors |
| Whirlpool | `crypto/whrlpool` + `wp-x86_64.pl` | implemented (`hash/whirlpool`), ISO/IEC 10118-3 vectors verified against a locally compiled OpenSSL reference; asm port now unblocked |
| MDC-2 | `crypto/mdc2` (DES-based) | implemented (`hash/mdc2`), both pad types (PAD_1/PAD_2) with OpenSSL vectors |
| MD5-SHA1 | `md5_sha1_prov.c` (TLS composite) | implemented (`hash/md5_sha1`) |

All four are registered in `envelope::EvpHash` (`new_ripemd160`, `new_whirlpool`,
`new_mdc2`, `new_md5_sha1`).

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
| AES-GCM-SIV | `cipher_aes_gcm_siv*.c` | not started (POLYVAL-based, separate construction) |
| ASCON-AEAD128 | `ascon` | not started |
| Key Wrap (KW/KWP) | `crypto/modes/wrap128.c` | not started |
| CTS | `crypto/modes/cts128.c` | not started (XTS stealing is unrelated) |
| DES-X(EX) | `cipher_desx.c` | not started |

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
| Ed448 | `crypto/ec/curve448/` | implemented (`ed448` + shared `curve448::fe`): untwisted Edwards edwards448 (a=1, d=-39081) in extended coordinates, RFC 8032 §5.2.4 complete add/dbl, dom4/SHAKE256 sign-verify with required context; RFC 8032 §7.4 vectors (blank, 1/11/12/13/64/256/1023 octets, 1 octet with context) |
| RSA | `crypto/rsa` + `crypto/bn` | implemented (`rsa` on `bn`): raw/PKCS#1 v1.5/OAEP encryption, PKCS#1 v1.5/PSS signatures, CRT private path, key generation (top-two-bit primes, small-prime sieve, 64 MR rounds, FIPS 186-4 distance), PKCS#1 DER + PKCS#8 parse; all directions cross-checked against the OpenSSL 3.5.8 CLI |
| RSA-PSS/other digests | | PSS and PKCS#1 v1.5 accept md5/sha1/sha224/sha256/sha384/sha512 (DigestInfo table) |
| X25519 | `crypto/ec/curve25519.c` | implemented (`x25519`): Montgomery ladder over radix-2^64 field ops, fe64 asm (`x25519_fe64_*`) wired in when `asm` is on; RFC 7748 §5.2/§6.1 vectors |
| X448 | `crypto/ec/curve448/` | implemented (`x448` + shared `curve448::fe`): Montgomery ladder over radix-2^56 (8×56-bit limbs) field ops for p = 2^448-2^224-1, software only; RFC 7748 §5.2 vectors 1-2, §5.2 iterative (1 iter), §6.2 Diffie-Hellman |
| DSA/ECDSA/SM2 | | not started |
| ML-KEM/ML-DSA/SLH-DSA/LMS | | not started |
| RAND | `crypto/rand` | not started; randomized RSA operations take a caller-supplied `Rng` instead |

### crown gaps — other buckets (not started)

- ARIA/SM4/Camellia GCM/CCM need only marker wiring — `aead/gcm` and
  `aead/ccm` are already generic.

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
  where available.
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

Not covered because crown has no implementation to test against those
vectors: X448/Ed448, DSA/ECDSA/ECDH, ML-KEM/ML-DSA, AEGIS, FF1, PBES2,
PKCS#7/PKCS#12/X.509 and HOTP/TOTP. AES-GCM-SIV, Ascon-AEAD128 and
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
| Short-Weierstrass Jacobian EC (P-256) | `crown/src/ec` | done — FIPS 186-4 D.1.2.3 params; tests: n*G=O, G*1=G, 2G=G+G |
| ECDH (P-256) | `crown/src/ecdh` | done — RFC 5903 §8.1 P-256 KAT + generate/agree roundtrip |
| ECDSA (P-256/SHA-256) | `crown/src/ecdsa` | done — RFC 6979 A.2.5 P-256/SHA-256 vectors |
| DH MODP 2048 (RFC 3526) | `crown/src/dh` | done — modp2048() + generate/agree with y-range checks |
| SM2 signature (GM/T 0003.2) | `crown/src/sm2` | done — GM/T sample (d, M="message digest") r/s match |
