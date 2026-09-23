# bsaes-x86_64 (bit-sliced AES) — port notes

Source: OpenSSL `crypto/aes/asm/bsaes-x86_64.pl`
(Emilia Käsper / Peter Schwabe / Andy Polyakov; public-domain bit-sliced AES
originally for Core 2, transliterated to perlasm September 2011.)

## Config pins

| pin | value | reason |
|---|---|---|
| `$win64` | `0` | unix SysV ABI; Win64 SEH blocks (`.pdata`/`.xdata`/`se_handler`) dropped |
| `$ecb` | `0` | the perl default — suppresses unreferenced `bsaes_ecb_*_blocks` helpers |
| `$avx` | n/a | this script has no AVX probe |

### Encoding pin (`.asciz` credit string)

`translateAssembly` converts `.asciz` to `.byte` via `charCodeAt` (Latin-1),
while perl `x86_64-xlate.pl` emits UTF-8 bytes. The credit string contains
U+00E4 (`K\u00e4sper`). In `x86_64.ts` that character is written as the two
code units U+00C3 U+00A4 so the emitted `.byte` list is `...,75,195,164,115,...`
(UTF-8 pair) and matches the perl reference. Without this the TS side would
emit `...,75,228,115,...` (Latin-1) and `diff` would show one line.

Argument registers used with `$win64=0`:
`$arg1..$arg6` = `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9` (`%r9d` for the
32-bit `enc` flag of CBC).

## Exported global symbols

- `ossl_bsaes_cbc_encrypt`
- `ossl_bsaes_ctr32_encrypt_blocks`
- `ossl_bsaes_xts_encrypt`
- `ossl_bsaes_xts_decrypt`

The following four symbols exist in the perl but are compiled out
(`if (0 && !$win64)` — "unsupported interface used for benchmarking"):
`bsaes_enc_key_convert`, `bsaes_encrypt_128`, `bsaes_dec_key_convert`,
`bsaes_decrypt_128`. The ECB entry points `bsaes_ecb_encrypt_blocks` /
`bsaes_ecb_decrypt_blocks` are also compiled out (`$ecb=0`).

## Internal (non-global) symbols

- `_bsaes_encrypt8` — encrypt 8 blocks in parallel (bit-sliced). Clobbers
  `%rax`, `%r10d`, `%r11`, `%xmm0`–`%xmm15`.
- `_bsaes_decrypt8` — decrypt 8 blocks in parallel (bit-sliced).
- `_bsaes_key_convert` — convert a conventional AES key schedule to the
  bit-sliced representation (see below).
- `_bsaes_const` — `.rodata` constants table (`.LM0ISR`, `.LISRM0`, `.LISR`,
  `.LBS0`–`.LBS2`, `.LSR`, `.LSRM0`, `.LM0SR`, `.LSWPUP`, `.LSWPUPM0SR`,
  `.LADD1`–`.LADD8`, `.Lxts_magic`, `.Lmasks`, `.LM0`, `.L63`) plus the
  `.asciz` credit string.

External references (must be provided by the surrounding crate):

- `asm_AES_encrypt`
- `asm_AES_decrypt`
- `asm_AES_cbc_encrypt`  (fallback for CBC encrypt direction / short inputs)

## C signatures (from `include/crypto/aes_platform.h` and the perl comments)

```c
void ossl_bsaes_cbc_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char ivec[16], int enc);

void ossl_bsaes_ctr32_encrypt_blocks(const unsigned char *in,
    unsigned char *out, size_t len,
    const AES_KEY *key,
    const unsigned char ivec[16]);

void ossl_bsaes_xts_encrypt(const unsigned char *inp, unsigned char *out,
    size_t len, const AES_KEY *key1,
    const AES_KEY *key2, const unsigned char iv[16]);

void ossl_bsaes_xts_decrypt(const unsigned char *inp, unsigned char *out,
    size_t len, const AES_KEY *key1,
    const AES_KEY *key2, const unsigned char iv[16]);
```

Perl comment for XTS (equivalent):

```c
void bsaes_xts_[en|de]crypt(const char *inp, char *out, size_t len,
    const AES_KEY *key1, const AES_KEY *key2,
    const unsigned char iv[16]);
```

`ossl_bsaes_cbc_encrypt` only takes the fast bit-sliced path when `enc == 0`
(CBC decryption) and `length >= 128`; otherwise it tails to
`asm_AES_cbc_encrypt`. CTR32 processes 8 blocks at a time and tails to
`asm_AES_encrypt` for the remainder. XTS key1 is the data key, key2 is the
tweak key.

## AES_KEY / key-conversion notes

`AES_KEY` is the standard OpenSSL structure:

```c
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)]; /* AES_MAXNR == 14 -> 240 bytes */
    int rounds;                               /* offset 240 */
};
```

All entry points read `rounds` from `240(%reg)` and pass the *conventional*
`rd_key` schedule to `_bsaes_key_convert`. There is **no** bit-sliced key setup
of its own — this module relies on conversion of the schedule produced by
`AES_set_encrypt_key` (128/192/256-bit keys all supported).

### `_bsaes_key_convert`

Register interface (unix SysV, as used by the call sites):

| reg | meaning |
|---|---|
| `%rax` | `$out` — destination bit-sliced key schedule |
| `%rcx` | `$inp` — source conventional `rd_key` (round keys, 16 bytes each) |
| `%r10d` | `$rounds` — `AES_KEY.rounds` (10 / 12 / 14) |
| `%r11`  | `$const` — clobbered; loaded with `.Lmasks(%rip)` |

Behaviour:

1. Loads round-0 key into `%xmm7` and stores it **unconverted** at `($out)`.
   First and last round keys are treated differently (no ShiftRows on them),
   which skips one `shiftrows()` and speeds conversion up by ~22%.
2. For each middle round key: `pshufb` with `.LM0`, then a bit-sliced
   transposition (the `swapmove2x` network) producing 8 × 16-byte bit-sliced
   round-key words at `0x00..0x70($out)`.
3. Does **not** write the last round key (`#movdqa %xmm6, ($out)` is commented
   out). Callers fix up the last/first key themselves:
   - encrypt path: `pxor %xmm6,%xmm7` then store `%xmm7` (so the last round
     key is pre-xored with the previous one);
   - decrypt path: `pxor ($out),%xmm7`, store `%xmm6` at `(%rax)` and `%xmm7`
     at `($out)`.
4. Leaves `%xmm6` = last conventional round key, `%xmm7` = `.L63`
   (`0x63…63` broadcast) for the caller.

Conversion cost is ~180–240 cycles (Core 2 / Nehalem) per invocation, paid on
every call — OpenSSL uses per-invocation on-the-fly conversion rather than a
cached bit-sliced schedule.

## CPUID / ISA requirements

- **SSSE3** is mandatory (`pshufb`, `palignr`-class byte permutes; the header
  comment says "requires support of SSE extensions up to SSSE3").
- Also uses plain SSE2 integer ops (`movdqa`/`movdqu`/`pxor`/`pand`/`pcmpeqb`/
  `psllq`/`psrlq`/`pslld`/`psrld`/`punpck*`/`pshufd`) — implied by SSSE3 on
  x86_64.
- `endbranch` is emitted at the public entry points (IBT / CET). The xlate
  layer also appends a `.note.gnu.property` IBT note.
- No AES-NI, no AVX/AVX2/AVX-512. This path is the non-AES-NI bitsliced
  fallback (historically Core 2 / Atom / Silvermont / Goldmont).

Suggested gate: `cpuid_ssse3()` (and treat as the non-AES-NI backend).

## Wiring suggestion for `crown/src/block/aes/`

Place the generator at `crown/src/block/aes/bsaes/x86_64.ts` (this file, once
promoted out of `staging/bsaes/`) and expose it next to the existing
`vpaes/` backend:

1. **Module** `crown/src/block/aes/bsaes/mod.rs` (or fold into
   `block/aes/x86_64.rs`):
   - `global_asm!(include_str!("bsaes/x86_64.ts"))` via the usual jsasm
     loader, **or** the `translateAssembly` default export consumed the same
     way `vpaes` / `gcm` / `camellia` are.
   - `extern "C"` block for the four `ossl_bsaes_*` symbols plus the three
     `asm_AES_*` externs (those three should resolve to the crate’s existing
     AES-NI / ttable `AES_encrypt` / `AES_decrypt` / `AES_cbc_encrypt`
     shims — same convention as `ossl_bsaes_cbc_encrypt`’s `.extern`).
2. **Dispatch** (in `block/aes/` `x86_64.rs` / `mod.rs`):
   - Prefer AES-NI (`aesni` / `aes-x86_64`) when `cpuid_aesni()`.
   - Else if `cpuid_ssse3()`, use **bsaes** for:
     - CBC decrypt (`ossl_bsaes_cbc_encrypt`, `enc=0`) when `len >= 128`;
     - CTR (`ossl_bsaes_ctr32_encrypt_blocks`) when `len >= 128` (8-block
       granularity; shorter buffers stay on the generic/ttable path);
     - XTS (`ossl_bsaes_xts_encrypt` / `ossl_bsaes_xts_decrypt`) for
       `len >= 80` (perl notes <80-byte XTS is suboptimal).
   - Else fall back to `vpaes` (SSSE3) or ttable.
3. **Key schedule**: keep using the conventional `AES_set_encrypt_key`
   schedule (`rd_key` + `rounds` at offset 240). Do **not** persist the
   bit-sliced schedule — convert per invocation via the internal
   `_bsaes_key_convert` already inlined into each entry point (each public
   function calls it itself; no separate export needed).
4. **Tests**: ECB/KAT vectors can go through the existing
   `block/aes/tests.rs`; CBC-CTR-XTS multi-block tests should exercise the
   ≥128-byte and non-multiple-of-8 tails so the `asm_AES_*` fallbacks run.

## Files in this staging dir

- `x86_64.ts` — jsasm generator (pre-xlate body + `translateAssembly`).
- `NOTES.md` — this file.

Verification: `cargo run -q -p crown-jsasm --example dump -- staging/bsaes/x86_64.ts`
is byte-identical to `CC=clang perl crypto/aes/asm/bsaes-x86_64.pl elf`.
