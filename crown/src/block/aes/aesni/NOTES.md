# aesni-x86_64.pl — jsasm translation notes

Source: OpenSSL `crypto/aes/asm/aesni-x86_64.pl`
Port: `staging/aesni/x86_64.ts`
Config pin: `$win64=0` (unix SysV ABI). Win64 SEH / stack-offload blocks are dropped.
`$PREFIX` left at default `aesni` (not the `AES` drop-in for `aes-x86_64.pl`).
No `$avx` probe exists in this script; no avx pin was required.

## Exported global symbols

- `aesni_encrypt`
- `aesni_decrypt`
- `aesni_ecb_encrypt`
- `aesni_ccm64_encrypt_blocks`
- `aesni_ccm64_decrypt_blocks`
- `aesni_ctr32_encrypt_blocks`
- `aesni_xts_encrypt`
- `aesni_xts_decrypt`
- `aesni_ocb_encrypt`
- `aesni_ocb_decrypt`
- `aesni_cbc_encrypt`
- `aesni_set_decrypt_key`
- `aesni_set_encrypt_key`

Internal (non-`.globl`) label used by `aesni_set_decrypt_key`:

- `__aesni_set_encrypt_key` (alias of `aesni_set_encrypt_key` entry)

External reference:

- `OPENSSL_ia32cap_P` (`.extern`; capability words consulted for AES-NI / PCLMULQDQ-ish paths)

## C signatures (from perl comments)

```c
void aesni_encrypt(const void *inp, void *out, const AES_KEY *key);
void aesni_decrypt(const void *inp, void *out, const AES_KEY *key);

void aesni_ecb_encrypt(const void *in, void *out,
                       size_t length, const AES_KEY *key,
                       int enc);

void aesni_ccm64_encrypt_blocks(const void *in, void *out,
                                size_t blocks, const AES_KEY *key,
                                const char *ivec, char *cmac);
void aesni_ccm64_decrypt_blocks(const void *in, void *out,
                                size_t blocks, const AES_KEY *key,
                                const char *ivec, char *cmac);
/* complete 64-bit-counter blocks only; does not update *ivec nor finalize CMAC */

void aesni_ctr32_encrypt_blocks(const void *in, void *out,
                                size_t blocks, const AES_KEY *key,
                                const char *ivec);
/* complete blocks only; 32-bit counter; does not update *ivec */

void aesni_xts_encrypt(const char *inp, char *out, size_t len,
                       const AES_KEY *key1, const AES_KEY *key2,
                       const unsigned char iv[16]);
void aesni_xts_decrypt(const char *inp, char *out, size_t len,
                       const AES_KEY *key1, const AES_KEY *key2,
                       const unsigned char iv[16]);

void aesni_ocb_encrypt(const char *inp, char *out, size_t blocks,
                       const AES_KEY *key, unsigned int start_block_num,
                       unsigned char offset_i[16], const unsigned char L_[][16],
                       unsigned char checksum[16]);
void aesni_ocb_decrypt(const char *inp, char *out, size_t blocks,
                       const AES_KEY *key, unsigned int start_block_num,
                       unsigned char offset_i[16], const unsigned char L_[][16],
                       unsigned char checksum[16]);

void aesni_cbc_encrypt(const void *inp, void *out,
                       size_t length, const AES_KEY *key,
                       unsigned char *ivp, const int enc);

int aesni_set_decrypt_key(const unsigned char *inp, int bits, AES_KEY *key);
int aesni_set_encrypt_key(const unsigned char *inp, int bits, AES_KEY * const key);
```

ABI notes (unix SysV, `$win64=0`):

- 1–6 integer args in `%rdi %rsi %rdx %rcx %r8 %r9`.
- `aesni_ecb_encrypt` 5th arg `enc` tested via `%r8d`.
- `aesni_cbc_encrypt` 6th arg `enc` tested via `%r9d`.
- `aesni_ccm64_*_blocks` 6th arg `cmac` lives in `%r9`.
- `aesni_ocb_*` 7th/8th args (`L_`, `checksum`) are stack-passed at `8(%rsp)` / `16(%rsp)` after the call frame (the asm reads `seventh_arg = 8`).
- `aesni_xts_*` uses `%r11` as frame pointer (CFA register swap).
- `aesni_set_encrypt_key` is frame-less / `@abi-omnipotent`; also sets `%eax` = 0 on success, -1/-2 on failure, and leaves `bits` = rounds-1 plus `key` advanced for `aesni_set_decrypt_key`.

## AES_KEY layout notes

Matches OpenSSL `struct aes_key_st` (`crypto/aes/aes.h`, non-`AES_LONG`):

```c
# define AES_MAXNR 14
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)]; /* 60 * 4 = 240 bytes */
    int rounds;                               /* offset 240 */
};
```

Asm access patterns in this script:

- `240(%key)` → `key->rounds` (loaded into `%eax` / `%r10d`; mutated by the private `aesni_[en|de]cryptN` helpers).
- `(%key)` / `16(%key)` / `32(%key)` → successive 16-byte round keys (`movups`).
- After `shl $4, %rounds` and `lea 32(%key,%rounds), %key` the pointer walks round keys at 16-byte stride; the first two round keys are consumed before the loop and the rest are streamed.
- Decrypt schedule is the inverse-MixColumns form (`aesimc` applied while swapping end-to-end in `aesni_set_decrypt_key`).
- Single-block `aesni_encrypt`/`aesni_decrypt` accept any of 128/192/256-bit schedules; `rounds` = 10 / 12 / 14.

crown `BlockExpanded.enc` / `.dec` limbs are already a standard FIPS-197 schedule (see `block/aes/asm.rs`), so an `AES_KEY` shim is just `{ rd_key: u32[60], rounds: i32 }` overlaying those limbs plus the round count — same pattern as `block/aes/vpaes` note about plain aes/aesni consuming the standard schedule.

## CPUID feature needed

**AES-NI** = CPUID leaf 1, ECX bit 25 (mask `0x0200_0000`).

In OpenSSL this is `OPENSSL_ia32cap_P[1]` (the second 32-bit word = leaf-1 ECX). The script also peeks that word inside `aesni_ctr32_encrypt_blocks` and `aesni_cbc_encrypt` (and ANDs it in the key-setup tail) for related ECX feature bits (e.g. PCLMULQDQ-style helpers on some paths); the hard requirement to enter these routines is still AES-NI.

crown probe already present:

```rust
// crown/src/block/aes/asm.rs
pub fn aesni_supported() -> bool {
    ia32cap(1) & (1 << 25) != 0
}
```

## Wiring suggestion for `crown/src/block/aes/`

1. Drop the generated file at `crown/src/block/aes/aesni/x86_64.ts` (sibling of `vpaes/x86_64.ts`).
2. In `block/aes/asm.rs`, mirror the vpaes `global_asm!(crown_derive::jsasm_file!(...))` include behind `#[cfg(all(feature = "asm", target_arch = "x86_64"))]`.
3. Add `extern "C"` declarations for the 13 globals above (SysV). Keep `aesni_set_encrypt_key` / `aesni_set_decrypt_key` as the key-expansion entry points: call them from `Aes` key setup when `aesni_supported()`, storing the 240-byte `rd_key` + `rounds` next to `BlockExpanded`.
4. Dispatch single-block `aesni_encrypt` / `aesni_decrypt` from the block trait impl when AES-NI is present (they consume the standard FIPS-197 schedule directly — unlike vpaes, no transformed-domain conversion).
5. Mode accelerators, if desired later: `aesni_cbc_encrypt`, `aesni_ctr32_encrypt_blocks`, `aesni_ecb_encrypt`, `aesni_xts_*`, `aesni_ocb_*`, `aesni_ccm64_*_blocks` can back `modes::{cbc,ctr,xts,ocb3}` and the AEAD paths. CFB/OFB stay on the generic `CRYPTO_[c|o]fb128_encrypt`-style single-block loop (this script does not export dedicated CFB/OFB routines).
6. Register the CPUID gate once in the block dispatch (already sketched as `aesni_supported()`); fall back to `vpaes` / `generic` when AES-NI is absent.

## Verification

Pre-xlate body was produced by patching a private copy of the perl (`$xlate="cat"; open OUT, "| cat"`) and running `perl /tmp/gen-aesni-pre.pl elf`. Reference post-xlate is `CC=clang perl crypto/aes/asm/aesni-x86_64.pl elf`. Confirmed `BYTE_IDENTICAL` against `crown-jsasm` `dump` of this file.
