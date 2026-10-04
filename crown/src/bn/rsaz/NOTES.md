# rsaz-x86_64.pl / rsaz-avx2.pl — jsasm translation notes

Sources: OpenSSL `crypto/bn/asm/rsaz-x86_64.pl` and
`crypto/bn/asm/rsaz-avx2.pl` (CRYPTOGAMS, Apache-2.0).
Ports: `crown/src/bn/rsaz_x86_64.ts`, `crown/src/bn/rsaz_avx2_x86_64.ts`.
Rust wiring: `crown/src/bn/rsaz.rs`.

## Config pins

Both scripts are pinned to `$win64=0` (unix SysV argument registers; the
Win64 SEH / stack-offload blocks and `.xdata`/`.pdata` are dropped).

`$addx` and `$avx` come from `$ENV{CC} -Wa,-v` (GNU as version probe). The
reference configuration is the probe **succeeding**:

| script | probe | pin | effect |
|---|---|---|---|
| `rsaz-x86_64.pl` | GNU as >= 2.23 | `$addx=1` | MULX/ADOX `__rsaz_512_mulx`, `__rsaz_512_reducex`, `.Loop_sqrx`, `.Lmulx` paths present; runtime dispatch via `OPENSSL_ia32cap_P+8` bit 0x80100 |
| `rsaz-avx2.pl` | GNU as >= 2.22 and >= 2.23 | `$avx>1`, `$addx=1` | full `if ($avx>1)` body emitted (else the stub is just `ud2`); `$addx` block at the end of `rsaz_1024_mul_avx2` emitted |

Reproduce the reference with `CC=gcc` (or any compiler whose `as` is
2.42-ish). Without `CC` set the avx2 script emits only the `rsaz_avx2_eligible`
stub + `ud2` aliases.

## Exported global symbols

`rsaz-x86_64.pl` (7):

- `rsaz_512_sqr`
- `rsaz_512_mul`
- `rsaz_512_mul_gather4`
- `rsaz_512_mul_scatter4`
- `rsaz_512_mul_by_one`
- `rsaz_512_scatter4`
- `rsaz_512_gather4`

Internal (not `.globl`) continuations shared by the above:
`__rsaz_512_reduce`, `__rsaz_512_reducex`, `__rsaz_512_subtract`,
`__rsaz_512_mul`, `__rsaz_512_mulx`.

`rsaz-avx2.pl` (7):

- `rsaz_1024_sqr_avx2`
- `rsaz_1024_mul_avx2`
- `rsaz_1024_red2norm_avx2`
- `rsaz_1024_norm2red_avx2`
- `rsaz_1024_scatter5_avx2`
- `rsaz_1024_gather5_avx2`
- `rsaz_avx2_eligible`

External reference: `OPENSSL_ia32cap_P` (`.extern`; supplied by
`utils/cpuid`, same as the mont/mont5 ports). `rsaz_512_sqr`,
`rsaz_512_mul`, `rsaz_512_mul_gather4`, `rsaz_512_mul_scatter4` and
`rsaz_avx2_eligible` read `+8(%rip)` for the MULX/ADOX/AVX2 bits.

## C signatures (from `crypto/bn/rsaz_exp.c`)

```c
void rsaz_512_mul(void *ret, const void *a, const void *b, const void *n,
                  BN_ULONG k);
void rsaz_512_mul_scatter4(void *ret, const void *a, const void *n,
                           BN_ULONG k, const void *tbl, unsigned int power);
void rsaz_512_mul_gather4(void *ret, const void *a, const void *tbl,
                          const void *n, BN_ULONG k, unsigned int power);
void rsaz_512_mul_by_one(void *ret, const void *a, const void *n, BN_ULONG k);
void rsaz_512_sqr(void *ret, const void *a, const void *n, BN_ULONG k,
                  int cnt);
void rsaz_512_scatter4(void *tbl, const BN_ULONG *val, int power);
void rsaz_512_gather4(BN_ULONG *val, const void *tbl, int power);

void rsaz_1024_norm2red_avx2(void *red, const void *norm);
void rsaz_1024_mul_avx2(void *ret, const void *a, const void *b,
                        const void *n, BN_ULONG k);
void rsaz_1024_sqr_avx2(void *ret, const void *a, const void *n, BN_ULONG k,
                        int cnt);
void rsaz_1024_scatter5_avx2(void *tbl, const void *val, int i);
void rsaz_1024_gather5_avx2(void *val, const void *tbl, int i);
void rsaz_1024_red2norm_avx2(void *norm, const void *red);

int rsaz_avx2_eligible(void);
```

`k` / `n0` is always `-n^-1 mod 2^64` (`BN_MONT_CTX::n0[0]`).

## Operand conventions

**512-bit family** — 8 little-endian u64 limbs, ordinary Montgomery
arithmetic with R = 2^512. `rsaz_512_sqr` performs `cnt` successive
Montgomery squares (`out = in^2 * R^-1 mod n`, then feeds `out` back).
`rsaz_512_mul_by_one` is the reduction-by-1 (`out = a * R^-1 mod n`) used
to leave Montgomery form. Scatter/gather4 tables are structure-of-arrays:
limb `i` of entry `power` sits at `tbl[power + i * 16]` (128-byte limb
stride, 16 slots, 1024-byte table).

**1024-bit AVX2 family** — values live in a 29-bit-digit redundant form:
36 digits (ceil(1024/29)), 4 digits per ymm lane, spilled as 40 u64 words
(320 bytes; last 4 words are zero pad). `norm2red` / `red2norm` convert
to and from the ordinary 16-limb little-endian form. AMM Montgomery
R = 2^(29*36) = 2^1044 — note this is **not** 2^1024; OpenSSL's
`RSAZ_1024_mod_exp_avx2` bridges the gap by multiplying with a `two80`
constant (= 2^80 in redundant form) after squaring `mont->RR`.
Scatter5/gather5 tables hold 32 entries in SoA form: 9 digit-groups, each
512 bytes apart (`tbl + i*16` within a group), total 4608 bytes. Only the
36 data digits travel: scatter5 stores 288 bytes per entry, gather5
returns those 288 bytes and then zeros the 4 pad words. The table buffer
must be **32-byte aligned** — `rsaz_1024_gather5_avx2` loads it with
`vmovdqa` (OpenSSL 64-byte-aligns its storage for exactly this reason).

## Re-verification

Generate the reference (pins above must hold: `CC` set, GNU as 2.42-ish):

```bash
cd crown-ref/openssl
CC=gcc perl crypto/bn/asm/rsaz-x86_64.pl elf > /tmp/rsaz_ref.s
CC=gcc perl crypto/bn/asm/rsaz-avx2.pl elf  > /tmp/rsaz_avx2_ref.s
```

Dump the jsasm ports and diff:

```bash
cd crown-wt-rsaz
cargo run -p crown-jsasm --example dump -- crown/src/bn/rsaz_x86_64.ts \
    > /tmp/rsaz_ts.s
cargo run -p crown-jsasm --example dump -- crown/src/bn/rsaz_avx2_x86_64.ts \
    > /tmp/rsaz_avx2_ts.s
diff -u /tmp/rsaz_ref.s /tmp/rsaz_ts.s
diff -u /tmp/rsaz_avx2_ref.s /tmp/rsaz_avx2_ts.s
```

Known deltas (mnemonics and operands match; only leading whitespace on
`.byte` lines differs):

- Every `rep ret` encoded as `\t.byte\t0xf3,0xc3` in the perl output is
  re-emitted at column 0 by `translateAssembly` (12 occurrences in the
  512-bit file, 7 in the AVX2 file). Same class of delta as the other
  jsasm ports.
- `.note.gnu.property` is **not** embedded in the `code` body;
  `translateAssembly` appends it, so the dump carries exactly one copy
  and it matches the perl tail byte-for-byte.

Line counts match exactly (2038 / 1767 with the 2.42 pins above).

Unit tests (`cargo test -p crown --lib --features asm`) exercise
`rsaz_512_mul` / `rsaz_512_sqr` / `rsaz_512_mul_by_one` against `Bn`
Montgomery arithmetic, scatter/gather roundtrips, and the AVX2
`norm2red`/`red2norm` plus `mul_avx2`/`sqr_avx2` through those converters.

## Wiring status

**Dispatched.** `rsaz::mod_exp` ports `RSAZ_512_mod_exp` and
`RSAZ_1024_mod_exp_avx2` from `crypto/bn/rsaz_exp.c`:

- the 512-bit driver uses a 16-entry scatter4/gather4 table (64-byte
  stride) with 4-bit windows over the exponent bytes;
- the 1024-bit driver uses the redundant 29-bit-digit form with the
  32-entry scatter5 table (32-byte aligned, 4608 bytes), the `two80`
  bridge constant and 5-bit windows.

`Montgomery::pow_consttime` calls the driver for 8- and 16-limb moduli
(RSA-1024/2048 CRT halves) when `avx2_eligible()` holds (1024-bit only)
and falls back to the mont5 stack on any mismatch — the mont5 table
layout is untouched.

Tests: `pow_consttime_matches_windowed` / `..._1024` and
`rsaz_mod_exp_driver_matches_windowed` cross-check the drivers against
the 4-bit windowed `Montgomery::pow` for random bases and exponents.
