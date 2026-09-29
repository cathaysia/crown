# sha256-mb-x86_64 (sha256_multi_block) — jsasm translation notes

Source: OpenSSL `crypto/sha/asm/sha256-mb-x86_64.pl`
(Andy Polyakov; CRYPTOGAMS + Apache-2.0).
Port: `crown/src/hash/sha256/mb/x86_64.ts`.
Rust wiring: `crown/src/hash/sha256/mb/mod.rs`.

## Config pins

| pin | value | reason |
|---|---|---|
| `$win64` | `0` | unix SysV ABI; Win64 SEH blocks dropped |
| `$avx` | `0` (implicit) | AVX/AVX2 bodies **deferred** |
| shaext body | **deferred** | `sha256_multi_block_shaext` not translated |

## Exported global symbols

- `sha256_multi_block` — SSSE3 4-way multi-block body.

### Deferred (not emitted)

- `sha256_multi_block_shaext` (SHA-NI tier, ~500 lines)
- `sha256_multi_block_avx` (AVX tier, ~2270 lines)
- `sha256_multi_block_avx2` (AVX2 tier, ~2420 lines)

## Data labels

- `sha256mb_K256` — `.rodata align=256`: 64 SHA-256 K constants, each
  broadcast 8× (two `.long` rows of 4 per constant). The code addresses
  them as `32*(i%8)-128(%rbp)` with `%rbp = K256+128`; every 8 rounds
  `%rbp += 256`.
- `sha256mb_L_pbswap` — byte-swap mask (two `.long` rows).
- `sha256mb_K256_shaext` — 64 K constants as single `.long` rows (hex),
  for the deferred shaext tier.

Local labels prefixed `.Lsha256mb_*`.

## C signature

```c
void sha256_multi_block(
    struct { unsigned int A[8]; B[8]; C[8]; D[8]; E[8]; F[8]; G[8]; H[8]; } *ctx,
    struct { void *ptr; int blocks; } inp[8],
    int num);
```

`ctx` is pre-offset by `0x80` inside the asm (`lea 0x80(ctx),ctx` as a
size optimization); all state accesses use `X-0x80(ctx)`.

## Translation notes

- 8 state registers `@V=(A..H)=xmm8..15`, rotated **right** each round.
  8 temporaries `(t1,t2,t3,axb,bxc,Xi,Xn,sigma)=xmm0..7`.
- `($axb,$bxc)` are **swapped** at the end of each `ROUND_00_15`.
  `($Xi,$Xn)` are **swapped** at the end of each `ROUND_16_XX`.
- `bxc` is pre-seeded per block: `movdqa C,bxc; pxor B,bxc` ("magic seed"
  for Maj).
- The pshufb byte-swap of loaded message words is emitted for rounds
  0–15 only (even rounds after `sigma=e`, odd rounds after `t3=e`).
  The `prefetcht0` hints fire only at round 15.
- The empty pshufb/prefetch slots keep their leading whitespace from the
  perl heredoc: pshufb slots are `\t`, prefetch slots are `\t `.
- `.Loop_16_xx` runs rounds 16–31, then `dec/jnz` runs it twice more for
  32–47 and 48–63 (`mov $3,%ecx` counter).
- `pshufb` is `.byte`-encoded by the xlate; `rep ret` → `.byte 0xf3,0xc3`.

## Re-verify

```sh
cd ~/crown-ref/openssl && CC=gcc perl crypto/sha/asm/sha256-mb-x86_64.pl elf > /tmp/sha256_mb_ref.s
cd ~/crown-second && cargo run -p crown-jsasm --example dump -- crown/src/hash/sha256/mb/x86_64.ts > /tmp/sha256_mb_ts.s
cargo test -p crown --lib --features asm sha256::mb
```

Verified 2026-09-29: SSSE3 body **byte-identical** to the reference
(only the 5 feature-dispatch lines at the top differ). Data section
matches after label renaming.

## Remaining symbols

| symbol | tier | status |
|---|---|---|
| `sha256_multi_block_shaext` | SHA-NI | deferred |
| `sha256_multi_block_avx` | AVX | deferred |
| `sha256_multi_block_avx2` | AVX2 | deferred |
| dispatcher feature checks | — | deferred |
