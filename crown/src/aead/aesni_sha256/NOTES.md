# aesni-sha256-x86_64 (aesni_cbc_sha256_enc) — jsasm translation notes

Source: OpenSSL `crypto/aes/asm/aesni-sha256-x86_64.pl`
(Andy Polyakov; CRYPTOGAMS + Apache-2.0).
Port: `crown/src/aead/aesni_sha256/x86_64.ts`.
Rust wiring: `crown/src/aead/aesni_sha256/mod.rs`.

## Status

The AVX stitched body is a static translation of the perl output
(`CC=gcc perl aesni-sha256-x86_64.pl elf`), with `aesenc`/`sha256*` mnemonics
encoded as `.byte` and data labels prefixed `aesni_sha256_`. It is wired
via `global_asm!` and passes the software-oracle tests.

shaext / xop / avx2 tiers are **not** ported; the dispatcher routes
unconditionally to the AVX body.

## Config pins (for the eventual asm path)

| pin | value | reason |
|---|---|---|
| `$win64` | `0` | unix SysV ABI |
| `$avx` | `2` | avx + avx2 bodies emitted |
| `$shaext` | `2` | shaext body emitted |

Reproduce the reference with `CC=gcc perl crypto/aes/asm/aesni-sha256-x86_64.pl elf`.

## Exported global symbols (perl)

- `aesni_cbc_sha256_enc` — dispatcher
- `aesni_cbc_sha256_enc_xop` / `_avx` / `_avx2` / `_shaext`
- data label `K256` (renamed `aesni_sha256_K256` in the jsasm port)

## C signature

```c
void aesni_cbc_sha256_enc(const void *inp, void *out, size_t blocks,
                          AES_KEY *key, unsigned char iv[16],
                          SHA256_CTX *ctx, const void *in0);
```

## Remaining work

1. Debug the AVX body (likely register/stack offset or AES-block interleaving).
2. Port shaext / avx2 / xop tiers.
3. Re-enable `global_asm!` + extern and drop the software path.
