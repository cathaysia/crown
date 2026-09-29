# aesni-sha256-x86_64 (aesni_cbc_sha256_enc) — jsasm translation notes

Source: OpenSSL `crypto/aes/asm/aesni-sha256-x86_64.pl`
(Andy Polyakov; CRYPTOGAMS + Apache-2.0).
Port: `crown/src/aead/aesni_sha256/x86_64.ts`.
Rust wiring: `crown/src/aead/aesni_sha256/mod.rs`.

## Status

The jsasm translation of the AVX body is present in `x86_64.ts` but **not
wired into the call path** — the stitched body currently faults (SIGSEGV)
and needs further verification against the perl output. The public API in
`mod.rs` therefore runs a correct software path (AES-NI CBC + portable
SHA-256 compression of the plaintext) that matches the stitched semantics.
Tests pin both outputs against independent oracles.

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
