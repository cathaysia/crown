# Algorithm & asm porting status

Snapshot as of 2026-09-26. Reference tree: `crown-ref/openssl` (Apache-2.0).

## 1. x86_64 perlasm → jsasm porting status

### Done (wired into crown, symbol parity with perl re-verified)

| OpenSSL script | crown file |
|---|---|
| `crypto/aes/asm/aes-x86_64.pl` | `crown/src/block/aes/ttable.ts` |
| `crypto/aes/asm/aesni-x86_64.pl` | `crown/src/block/aes/aesni/x86_64.ts` (+ NOTES.md) |
| `crypto/aes/asm/bsaes-x86_64.pl` | `crown/src/block/aes/bsaes/x86_64.ts` (+ NOTES.md) |
| `crypto/aes/asm/vpaes-x86_64.pl` | `crown/src/block/aes/vpaes/x86_64.ts` |
| `crypto/camellia/asm/cmll-x86_64.pl` | `crown/src/block/camellia/x86_64.ts` |
| `crypto/chacha/asm/chacha-x86_64.pl` | `crown/src/stream/chacha20/x86_64.ts` |
| `crypto/md5/asm/md5-x86_64.pl` | `crown/src/hash/md5/block/x86_64.ts` |
| `crypto/modes/asm/aesni-gcm-x86_64.pl` | `crown/src/aead/gcm/x86_64.ts` |
| `crypto/poly1305/asm/poly1305-x86_64.pl` | `crown/src/mac/poly1305/x86_64.ts` |
| `crypto/rc4/asm/rc4-x86_64.pl` | `crown/src/stream/rc4/xor_key_stream/x86_64.ts` |
| `crypto/rc4/asm/rc4-md5-x86_64.pl` | `crown/src/stream/rc4/md5_enc/x86_64.ts` (+ NOTES.md) |
| `crypto/sha/asm/sha1-x86_64.pl` | `crown/src/hash/sha1/block/x86_64.ts` |
| `crypto/sha/asm/sha512-x86_64.pl` | `crown/src/hash/sha256/block/x86_64.ts` + `sha512/block/x86_64.ts` |
| `crypto/sha/asm/keccak1600-x86_64.pl` | `crown/src/hash/sha3/x86_64.ts` |
| `crypto/sm3/asm/sm3-x86_64.pl` | `crown/src/hash/sm3/x86_64.ts` |
| `crypto/sm4/asm/sm4-x86_64.pl` | `crown/src/block/sm4/x86_64.ts` |
| `crypto/whrlpool/asm/wp-x86_64.pl` | — (no crown whirlpool module yet) |
| `crypto/modes/asm/ghash-x86_64.pl` | — (aead round, deferred) |

### Remaining, by bucket

- **hash bucket: complete.** Everything with a crown-side consumer is translated.
  Re-generated each perl and compared exported symbols against the `.ts` files;
  all match.
- **aead-related (deferred by design):** `ghash-x86_64.pl`,
  `aesni-gcm` (done, listed above), `aesni-sha1-x86_64.pl`,
  `aesni-sha256-x86_64.pl`, `sha1-mb-x86_64.pl`, `sha256-mb-x86_64.pl`.
  Note: `sha{1,256}-multi_block` in this OpenSSL version are only consumed by
  the TLS CBC-HMAC-SHA stitched ciphers
  (`cipher_aes_cbc_hmac_sha{1,256}_hw.c`), so they belong to the aead round.
- **no crown consumer:** `wp-x86_64.pl` (whirlpool),
  `keccak1600x4-avx512vl.pl` (4-way SHA3; crown sha3 is single-stream;
  `keccak1600-avx2/avx512/avx512vl.pl` are not even referenced by this
  OpenSSL's `build.info`).
- **not yet visited buckets:** `bn/` (x86_64-mont, mont5, rsaz, gf2m),
  `ec/` (ecp_nistz256, x25519), `ml_dsa/` (ml_dsa_ntt).

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

### crown gaps — other buckets (not started)

- AEAD/modes: AES/SM4 XTS, AES-SIV, AES-GCM-SIV, ASCON-AEAD128, Key Wrap
  (KW/KWP), CTS, DES-X(EX). ARIA/SM4/Camellia GCM/CCM need only marker
  wiring — `aead/gcm` and `aead/ccm` are already generic.
- KDF: TLS1-PRF, KBKDF, SSKDF, X963KDF, X942KDF, SSHKDF, KRB5KDF,
  PKCS12KDF, PBKDF1, SRTP-KDF, IKEv2-KDF.
- Asymmetric: RSA/DSA/ECDSA/EdDSA/X25519/DH/ECDH/SM2/ML-KEM/ML-DSA/
  SLH-DSA/LMS — likely outside crown's symmetric-primitives scope.
- RAND: CTR/HMAC/HASH-DRBG, RDRAND, JITTER.

### crown extras (OpenSSL has none)

Anubis, Kasumi, Khazad, MULTI2, Noekeon, RC6, Safer, Skipjack, TEA/XTEA,
Twofish, Salsa20, Rabbit, SOSEMANUK, SOBER128, EAX, bcrypt.

## 3. Test-vector sources for this round

- OpenSSL 3.5.8 system CLI (`openssl dgst` / `openssl mac`) where available.
- `crown-ref/openssl/test/recipes/30-test_evp_data/`:
  `evpmd_mdc2.txt`, `evpmd_whirlpool.txt` (ISO/IEC 10118-3 set),
  `evpmac_siphash.txt`, `evpmac_cmac_des.txt`, `cmactest.c` (RFC 4493),
  `evpkdf_kbkdf_kmac.txt`.
- RFC 2289 (RIPEMD-160), RFC 4493 (AES-CMAC), McGrew/Viega GCM test case 4
  (GMAC), NIST SP 800-185 (KMAC samples).
