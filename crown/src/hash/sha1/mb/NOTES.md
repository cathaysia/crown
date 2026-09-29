# sha1-mb-x86_64 (sha1_multi_block) — jsasm translation notes

Source: OpenSSL `crypto/sha/asm/sha1-mb-x86_64.pl`
(Andy Polyakov; CRYPTOGAMS + Apache-2.0).
Port: `crown/src/hash/sha1/mb/x86_64.ts`.
Rust wiring: `crown/src/hash/sha1/mb/mod.rs`.

## Config pins

| pin | value | reason |
|---|---|---|
| `$win64` | `0` | unix SysV ABI; Win64 SEH blocks and xmm6-15 spill dropped |
| `$avx` | `0` (implicit) | AVX/AVX2 bodies **deferred** — only the SSSE3 path is emitted |
| shaext body | **deferred** | `sha1_multi_block_shaext` not translated in this pass |

Reproduce the reference with `CC=gcc perl crypto/sha/asm/sha1-mb-x86_64.pl elf`
(`$avx` comes from `$ENV{CC} -Wa,-v`; on this host it resolves to 2, so the
reference also contains the avx/avx2 bodies). The SSSE3 body is independent
of `$avx` and `$win64`.

## Exported global symbols

- `sha1_multi_block` — SSSE3 4-way multi-block body.

### Deferred (not emitted)

- `sha1_multi_block_shaext` (SHA-NI tier)
- `sha1_multi_block_avx` (AVX tier, 4-way)
- `sha1_multi_block_avx2` (AVX2 tier, 8-way)

These are internal (non-`.globl`) in the reference and only reachable
through the dispatcher at the top of `sha1_multi_block`. Because they are
deferred, the dispatcher's `bt $61` / `test $1<<28` feature checks are also
omitted; `sha1_multi_block` always uses the SSSE3 path.

## Data labels

- `sha1mb_K_XX_XX` — `.rodata align=256`:
  - 2×4 dwords K_00_19 (**before** the label — the code addresses them as `-0x20(%rbp)`)
  - 2×4 dwords K_20_39 (at the label)
  - 2×4 dwords K_40_59
  - 2×4 dwords K_60_79
  - 2×4 dwords pbswap mask
  - 16-byte reverse byte table
  - `.asciz` credit string

Local labels are prefixed `.Lsha1mb_*` to avoid clashes with other
`global_asm!` blocks in the crate.

## C signature

```c
void sha1_multi_block(
    struct { unsigned int A[8]; B[8]; C[8]; D[8]; E[8]; } *ctx,
    struct { void *ptr; int blocks; } inp[8],
    int num);
```

- `ctx` holds 8 lanes of 5-word SHA-1 state. Each XMM register packs 4
  lanes: `A` is `movdqu 0x00(ctx)`, `B` is `0x20(ctx)`, etc.
- `inp[i]` is `{void *ptr; int blocks}` (16 bytes). `ptr` points to
  contiguous 64-byte blocks; `blocks` is the count. Lanes with
  `blocks <= 0` are cancelled (pointer redirected to the K table) and
  their state is preserved.
- `num` is the number of 4-lane groups: `1` processes lanes 0–3,
  `2` processes lanes 0–3 then 4–7.

## Translation notes (jsasm-specific)

- The perl software-pipelines the message schedule via `@Xi` (5-register
  sliding window, rotated **left** each round) and the SHA-1 state via
  `@V` (rotated **right** each round: `unshift(@V,pop(@V))`).  After 80
  rounds both arrays return to their initial ordering.
- `@Xi[-2]` and `@Xi[3]` are the **same** slot in a 5-element array. The
  Xupdate sequence reads it as `"X[13]"`, then overwrites it with
  `"X[2]"` from the spill buffer, then XORs the new value — the emit
  order must match exactly.
- `Xi_off(n)` = `(n % 16) * 16 - 128(%rax)` (the `(%rbx)` branch is
  unreachable because of the `% 16`).
- The dual-issue scheduling (leading space on alternate instructions) is
  preserved verbatim from the perl heredocs.
- The post-round counter mask uses `pcmpgtd` + `paddd` to decrement only
  active lanes; the state merge is `pand mask, state; paddd ctx, state`.
- `pshufb` is encoded as `.byte` rows by the JS xlate (mirroring the perl
  xlate). `rep ret` becomes `.byte 0xf3,0xc3`.

## Re-verify

```sh
cd ~/crown-ref/openssl && CC=gcc perl crypto/sha/asm/sha1-mb-x86_64.pl elf > /tmp/sha1_mb_ref.s
cd ~/crown-second && cargo run -p crown-jsasm --example dump -- crown/src/hash/sha1/mb/x86_64.ts > /tmp/sha1_mb_ts.s
# Compare the SSSE3 body + data section (feature-dispatch lines are deferred):
diff -u <(awk '/^sha1_multi_block:/,/^\.size.sha1_multi_block/' /tmp/sha1_mb_ref.s) \
        <(awk '/^sha1_multi_block:/,/^\.size.sha1_multi_block/' /tmp/sha1_mb_ts.s)
cargo test -p crown --lib --features asm sha1_mb
```

Verified 2026-09-29: SSSE3 body **byte-identical** to the reference
(only the 5 feature-dispatch lines at the top differ — those reference
the deferred `_shaext_shortcut` / `_avx_shortcut` labels). Data section
byte-identical after label renaming (`K_XX_XX` → `sha1mb_K_XX_XX`).

## Wiring status

Translated and unit-tested: `crate::hash::sha1::mb` exports
`multi_block` (raw 8-lane API) and `multi_block_single` (single-stream
convenience). Tests cross-check against a portable FIPS 180-4
compression oracle for single-stream, 4-lane uniform, mixed block-count,
and inactive-lane cases.

## Remaining symbols to port

| symbol | tier | lines (ref) | status |
|---|---|---|---|
| `sha1_multi_block_shaext` | SHA-NI | ~375 | deferred |
| `sha1_multi_block_avx` | AVX | ~2090 | deferred |
| `sha1_multi_block_avx2` | AVX2 | ~2250 | deferred |
| dispatcher feature checks | — | 5 | deferred |
