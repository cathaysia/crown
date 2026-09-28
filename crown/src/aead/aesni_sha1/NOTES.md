# aesni-sha1-x86_64 (aesni_cbc_sha1_enc) — jsasm translation notes

Source: OpenSSL `crypto/aes/asm/aesni-sha1-x86_64.pl`
(Andy Polyakov; CRYPTOGAMS + Apache-2.0).
Port: `crown/src/aead/aesni_sha1/x86_64.ts`.
Rust wiring: `crown/src/aead/aesni_sha1/mod.rs`.

## Config pins

| pin | value | reason |
|---|---|---|
| `$win64` | `0` | unix SysV ABI; Win64 SEH blocks and the xmm6-15 spill dropped |
| `$avx` | `1` | `CC=gcc` probe succeeds; the `aesni_cbc_sha1_enc_avx` body is emitted |
| `$shaext` | `1` | hardcoded; the `aesni_cbc_sha1_enc_shaext` body is emitted |
| `$stitched_decrypt` | `0` | upstream default; `aesni256_cbc_sha1_dec` family omitted |

Reproduce the reference with `CC=gcc perl crypto/aes/asm/aesni-sha1-x86_64.pl elf`
(`$avx` comes from `$ENV{CC} -Wa,-v`; without `CC` only the SSSE3 body
and the stub dispatcher are emitted).

## Exported global symbols

- `aesni_cbc_sha1_enc` — dispatcher (SHA-NI bit 61 → shaext, AVX+Intel
  bits → avx, else ssse3)

Internal (non-global) bodies:

- `aesni_cbc_sha1_enc_ssse3` (`.type ..., @function, 6`)
- `aesni_cbc_sha1_enc_avx`
- `aesni_cbc_sha1_enc_shaext`
- `K_XX_XX` — `.rodata align=64`: K_00_19..K_60_79 (4 dwords each) +
  pbswap mask + a 16-byte reverse table
- `.Laesenclast1`..`.Laesenclast8` — AES-128/192/256 last-round epilogues
  (the `$sn` counter is file-scope in the perl and runs across the ssse3
  **and** avx bodies — do **not** reset it per path)
- `.Loop_ssse3`/`.Ldone_ssse3`, `.Loop_avx`/`.Ldone_avx`,
  `.Loop_shaext`, `.Lepilogue_*`

## C signature

```c
void aesni_cbc_sha1_enc(const void *inp, void *out, size_t blocks,
                        const AES_KEY *key, unsigned char iv[16],
                        SHA_CTX *ctx, const void *in0);
```

`blocks` counts 64-byte chunks. Only `ctx->h[0..4]` is updated (the
OpenSSL TLS caller adds the length counters itself). `in0` is the base
for relative output addressing; pass `in0 == inp` when `out` is a plain
destination buffer.

## Translation notes (jsasm-specific)

- The perl software-pipelines AES rounds through the SHA-1 round schedule
  via `@body_00_19`/`@body_20_39`/`@body_40_59` instruction-string arrays
  and the `Xupdate_ssse3_16_31`/`_32_79`/`Xuplast`/`Xloop`/`Xtail`
  evaluators. The port mirrors this with `Insn` thunks: each body block
  returns 8–11 thunks (the perl `.` concatenations — assign+first op and
  the trailing `$j++`/`unshift(@V,pop(@V))` — stay one thunk), and the
  Xupdate schedules call them interleaved with the SSE ops.
- `$aesenc` is injected by appending `'&$aesenc();'` to one thunk slot
  (`@r[$k%$n]`) chosen by integer division on `$jj` — the slot index and
  the `use integer` truncation must match exactly or the interleave
  drifts. `$sn` (`.Laesenclast$sn`) is **not** reset between the ssse3
  and avx bodies.
- Register rotations are `unshift(@V,pop(@V))` (rotate **right**), while
  `@X`/`@Tx` use `push(shift)` (rotate left). The two directions are easy
  to swap and will silently scramble the IALU registers.
- The final perl pass encodes `sha1rnds4`/`sha1nexte`/`sha1msg1`/`sha1msg2`
  and bare `aesenc`/`aesenclast` as `.byte` rows (the JS xlate has
  `pshufb`/`movq`/`pclmulqdq` hardcoded but **not** the SHA1/AES-NI
  mnemonics); `postProcess()` in the .ts does the same. VEX `vaesenc`
  stays a mnemonic (the perl `\b(aes` guard skips `vaes*`).
- Perl numeric literals like `0xee` in `pshufd` are bare integers (238);
  the port emits decimal `$238` to match the xlate immediate.
- `0(%r13,%reg)` EA operands flip base/index (perl treats label `0` as
  falsy). `crown-jsasm/preload/x86_64-xlate.ts` now mirrors that.

## Re-verify

```
cd ~/crown-ref/openssl && CC=gcc perl crypto/aes/asm/aesni-sha1-x86_64.pl elf > /tmp/aesni_sha1_ref.s
cd ~/crown-second && cargo run -p crown-jsasm --example dump -- crown/src/aead/aesni_sha1/x86_64.ts > /tmp/aesni_sha1_ts.s
diff -u /tmp/aesni_sha1_ref.s /tmp/aesni_sha1_ts.s
cargo test -p crown --lib --features asm aesni_sha1
```

Verified 2026-09-28: **byte-identical** (0 diff lines, including the
`.note.gnu.property` section — this script's `$gnuas` probe picks the
`".note.gnu.property", "a"` spelling on this host, same as
`translateAssembly`).

## Wiring status

Translated, byte-identical and unit-tested: `crate::aead::aesni_sha1`
exports `cbc_sha1_enc` and the tests cross-check CBC output against
`aesni::cbc_encrypt` and the SHA-1 chaining value against a portable
FIPS 180-4 compression oracle. Full TLS `AES-CBC-HMAC-SHA1` AEAD
integration (the `e_aes_cbc_hmac_sha1.c` stitched cipher) is **not**
wired — that needs the HMAC outer hash, the TLS record framing and the
`sha1_multi_block` edge handling, which belong to the aead/TLS round.
