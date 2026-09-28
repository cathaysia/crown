# ecp_nistz256-x86_64.pl — porting notes

## Source

- Perl: `crypto/ec/asm/ecp_nistz256-x86_64.pl` (OpenSSL, Apache-2.0 / CRYPTOGAMS)
- C consumer: `crypto/ec/ecp_nistz256.c`
- Table data: `crypto/ec/ecp_nistz256_table.c` (expanded into `.rodata` by the perl)

## Config pins

| pin | value | effect |
|---|---|---|
| `$win64` | 0 | unix SysV ABI only; all Win64 SEH / `.LSEH_*` / `.xdata` blocks dropped |
| flavour | `elf` | AT&T / GAS output |
| `$addx` | 1 | ADX+BMI2 (MULX/ADCX) paths are present and dispatched at runtime on `OPENSSL_ia32cap_P` bit `0x80100` (leaf 7 EBX bits 8+19) |
| `$avx` | ≤ 1 | AVX2 gather bodies are **not** emitted. `ecp_nistz256_avx2_gather_w5` is absent. `ecp_nistz256_avx2_gather_w7` is the `ud2` stub (the `else` branch of the `$avx>1` probe). `gather_w5` / `gather_w7` do not dispatch to AVX2. |

`OPENSSL_ia32cap_P` is the shared CPUID word defined by
`crown/src/utils/cpuid/x86_64.ts` and filled at load time.

## Exported symbols (`.globl` in the elf output)

| symbol | kind | C signature |
|---|---|---|
| `ecp_nistz256_precomputed` | rodata object | `const PRECOMP256_ROW ecp_nistz256_precomputed[37]` |
| `ecp_nistz256_mul_by_2` | function | `void (uint64_t res[4], const uint64_t a[4])` |
| `ecp_nistz256_div_by_2` | function | `void (uint64_t res[4], const uint64_t a[4])` |
| `ecp_nistz256_mul_by_3` | function | `void (uint64_t res[4], const uint64_t a[4])` |
| `ecp_nistz256_add` | function | `void (uint64_t res[4], const uint64_t a[4], const uint64_t b[4])` |
| `ecp_nistz256_sub` | function | `void (uint64_t res[4], const uint64_t a[4], const uint64_t b[4])` |
| `ecp_nistz256_neg` | function | `void (uint64_t res[4], const uint64_t a[4])` |
| `ecp_nistz256_ord_mul_mont` | function | `void (uint64_t res[4], const uint64_t a[4], const uint64_t b[4])` |
| `ecp_nistz256_ord_sqr_mont` | function | `void (uint64_t res[4], const uint64_t a[4], uint64_t rep)` |
| `ecp_nistz256_to_mont` | function | `void (uint64_t res[4], const uint64_t in[4])` |
| `ecp_nistz256_mul_mont` | function | `void (uint64_t res[4], const uint64_t a[4], const uint64_t b[4])` |
| `ecp_nistz256_sqr_mont` | function | `void (uint64_t res[4], const uint64_t a[4])` |
| `ecp_nistz256_from_mont` | function | `void (uint64_t res[4], const uint64_t in[4])` |
| `ecp_nistz256_scatter_w5` | function | `void (void *val, const void *in_t, int index)` |
| `ecp_nistz256_gather_w5` | function | `void (void *val, const void *in_t, int index)` |
| `ecp_nistz256_scatter_w7` | function | `void (void *val, const void *in_t, int index)` |
| `ecp_nistz256_gather_w7` | function | `void (void *val, const void *in_t, int index)` |
| `ecp_nistz256_avx2_gather_w7` | function | `void (void *val, const void *in_t, int index)` — `ud2` stub |
| `ecp_nistz256_point_double` | function | `void (P256_POINT *r, const P256_POINT *a)` |
| `ecp_nistz256_point_add` | function | `void (P256_POINT *r, const P256_POINT *a, const P256_POINT *b)` |
| `ecp_nistz256_point_add_affine` | function | `void (P256_POINT *r, const P256_POINT *a, const P256_POINT_AFFINE *b)` |

Internal (`.type` but not `.globl`):
`__ecp_nistz256_mul_montq`, `__ecp_nistz256_sqr_montq`,
`__ecp_nistz256_add_toq`, `__ecp_nistz256_sub_fromq`,
`__ecp_nistz256_subq`, `__ecp_nistz256_mul_by_2q`.

## Register / field layout

- **Field element**: 256-bit integer as **4 × u64 little-endian limbs** in
  memory (limb 0 at the lowest address).  This matches `Bn`'s internal
  `Vec<u64>` limb order.
- **Jacobian point** (`P256_POINT`): three field elements `X[4], Y[4], Z[4]`
  = **12 × u64 / 96 bytes**, contiguous.
- **Affine point** (`P256_POINT_AFFINE`): `X[4], Y[4]` = **8 × u64 / 64 bytes**.
- **Montgomery domain**: `R = 2^256 mod p` for the field ops
  (`to_mont` / `mul_mont` / `sqr_mont` / `from_mont`); `R = 2^256 mod n`
  for the order ops (`ord_mul_mont` / `ord_sqr_mont`).
  `to_mont(x) = x·R mod p`, `from_mont(x) = x·R⁻¹ mod p`.
- **Point ops expect coordinates already in the Montgomery form.** The
  internal `mul_mont` / `sqr_mont` calls confirm this; linear ops
  (`add` / `sub` / `mul_by_2`) preserve the form.
- **w5 table** (`P256_POINT[16]`): scatter/gather index is **1-based**
  (1..=16).  Slot 0 is implicitly infinity and is never stored.  Storage
  stride is 96 bytes; scatter offset = `96 * (index - 1)`.
- **w7 table** (`P256_POINT_AFFINE[64]`): scatter index is **0-based**
  (0..=63), gather index is **1-based** (1..=64) — the zero entry is
  implicitly infinity so gather skips it.  Storage stride is 64 bytes;
  scatter offset = `64 * index`, gather reads `64 * (index - 1)`.
  Round-trip: `scatter_w7(.., k)` then `gather_w7(.., k + 1)`.
- **`ecp_nistz256_precomputed`**: 4096-byte-aligned rodata,
  `PRECOMP256_ROW[37]` where `PRECOMP256_ROW = P256_POINT_AFFINE[64]`.
  Total 37 × 64 × 64 = 151 552 bytes.  Contents are the affine windowed
  generator multiples in the Montgomery domain (built from
  `ecp_nistz256_table.c`).

## Byte-identity vs perl

Re-verify:

```bash
ssh loongtao@10.4.15.134 'cd /home/loongtao/crown-ref/openssl && \
  perl crypto/ec/asm/ecp_nistz256-x86_64.pl elf > /tmp/nistz256_ref.s'
ssh loongtao@10.4.15.134 'cd /home/loongtao/crown-wt-ecp256 && \
  export PATH="$HOME/.cargo/bin:$PATH" && \
  cargo run -p crown-jsasm --example dump -- crown/src/ec/nistz256/x86_64.ts \
    > /tmp/nistz256_ts.s'
diff -u /tmp/nistz256_ref.s /tmp/nistz256_ts.s
```

**Result (2026-09-28):** 5313 lines on both sides.  Instruction mnemonics
and operands match exactly.  The only delta is one directive:

| line | perl (`x86_64-xlate.pl`, `$gnuas=0` default) | jsasm `translateAssembly` (`gnuas=true`) |
|---|---|---|
| last `.section` | `.section .note.gnu.property, #alloc` | `.section ".note.gnu.property", "a"` |

This is the GNU-as quoted-section-flags form that LLVM `global_asm!`
requires (see `crown-jsasm/preload/x86_64-xlate.ts` `initConfig`:
`gnuas = true`).  Semantic equivalent; the assembler accepts both.

Note: the `code` string embeds the **pre-xlate** perl text (short `mov`,
`ret` mnemonics).  `translateAssembly` applies the same normalisations
`perlasm/x86_64-xlate.pl` does (`ret` → `.byte 0xf3,0xc3`, `mov` →
`movq`/`movl`, `.section` flags).  Embedding the post-xlate text instead
causes double-sizing (`orq` → `orqq`) — do not do that.

## Wiring status

**Translated, not yet dispatched.**  The asm is compiled and unit-tested
(`crown/src/ec/nistz256/tests.rs`, gated on `feature = "asm"` +
`target_arch = "x86_64"`) against the software Jacobian path in
`crown/src/ec` and against RFC 5903 §8.1 P-256 KATs.  It is **not**
routed into `crate::ec::point_mul` / `Point::mul_with` yet: crown's
software path uses generic `Bn` arithmetic in plain (non-Montgomery)
domain, while this asm expects fixed 4-limb Montgomery-form buffers.
Bridging that would require a Montgomery-aware P-256 field context in
`crown/src/ec`; left for a follow-up.

## Re-run tests

```bash
ssh loongtao@10.4.15.134 'cd /home/loongtao/crown-wt-ecp256 && \
  export PATH="$HOME/.cargo/bin:$PATH" && \
  cargo test -p crown --lib --features asm'
```
