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
| `crypto/modes/asm/aesni-gcm-x86_64.pl` | `crown/src/aead/gcm/x86_64.ts` (stitch; compile+CTR/GHASH/round-trip tested, AEAD dispatch pending) |
| `crypto/modes/asm/ghash-x86_64.pl` | `crown/src/block/aes/gcm/x86_64.ts` (dispatch live in `block::aes::gcm::ghash`; `gcm_init_avx` ported for the stitch, gmult/ghash AVX entry points still stubs) |
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

- `bn::{x86_64,mont5_x86_64}` — `bn_mul_mont` vs `bn::Montgomery`
  (variable path, 8-limb mul4x path, Montgomery-form conversion).
- `ed25519/x86_64.ts` — fe51 mul/sqr/mul121666 vs `ed25519::fe`, fe64
  ops vs bigint arithmetic mod 2^255-19.
- `aead/chacha20poly1305/x86_64.ts` — seal/open vs the BoringSSL
  `chacha20_poly1305_tests.txt` vectors.
- `aead/gcm/x86_64.ts` (stitch) — CTR keystream vs software AES-CTR and
  round-trip; consumes the AES-NI `aesni_set_encrypt_key` schedule format
  (not the C big-endian-word format — mixing them up was the long-standing
  "first 96 bytes untransformed" bug). The `ctx.xi` contract is asserted as
  well: the stitch leaves the GHASH state over the ciphertext it consumed,
  which needs the *AVX* Htable (`gcm_init_avx`, ported into
  `block/aes/gcm/x86_64.ts`); the shorter clmul table zeroes H^5/H^6 and
  corrupted `ctx.xi` — that, not a pipeline subtlety, was the mismatch. Both
  the ciphertext and the resulting Xi match the perl-generated reference asm
  byte for byte. AEAD dispatch is still pending.

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

### crown gaps — asymmetric — partially closed 2026-09-27 (software)

| algorithm | openssl source | crown status |
|---|---|---|
| Ed25519 | `crypto/ec/curve25519.c` | implemented (`ed25519`): 51-bit-limb field arithmetic, ref10 invert/pow22523 chains, extended-coordinate group ops, constant-time 4-bit-window scalar mult; RFC 8032 section 7.1 vectors, CLI cross-checked |
| RSA | `crypto/rsa` + `crypto/bn` | implemented (`rsa` on `bn`): raw/PKCS#1 v1.5/OAEP encryption, PKCS#1 v1.5/PSS signatures, CRT private path, key generation (top-two-bit primes, small-prime sieve, 64 MR rounds, FIPS 186-4 distance), PKCS#1 DER + PKCS#8 parse; all directions cross-checked against the OpenSSL 3.5.8 CLI |
| RSA-PSS/other digests | | PSS and PKCS#1 v1.5 accept md5/sha1/sha224/sha256/sha384/sha512 (DigestInfo table) |
| X25519 | `crypto/ec/curve25519.c` | not started (the ed25519 field arithmetic is reusable) |
| DSA/ECDSA/SM2 | | not started |
| ML-KEM/ML-DSA/SLH-DSA/LMS | | not started |
| RAND | `crypto/rand` | not started; randomized RSA operations take a caller-supplied `Rng` instead |

### crown gaps — other buckets (not started)

- AEAD/modes: AES-GCM-SIV, ASCON-AEAD128, Key Wrap (KW/KWP), CTS, DES-X(EX).
  ARIA/SM4/Camellia GCM/CCM need only marker wiring — `aead/gcm` and
  `aead/ccm` are already generic.

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
vectors: X25519/X448 (no public agreement API; the fe64/fe51 asm is tested
internally), DSA/ECDSA/ECDH/Ed448, ML-KEM/ML-DSA, AES-GCM-SIV, AEGIS/ASCON,
KW/KWP key wrap, FF1, PBES2, PKCS#7/PKCS#12/X.509 and HOTP/TOTP. The KBKDF
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
