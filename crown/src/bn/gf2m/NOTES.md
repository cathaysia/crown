# x86_64-gf2m (bn_GF2m_mul_2x2) — jsasm translation notes

Source: OpenSSL `crypto/bn/asm/x86_64-gf2m.pl`
(Andy Polyakov, May 2011; CRYPTOGAMS + Apache-2.0).
Port: `crown/src/bn/gf2m_x86_64.ts`.
Rust wiring: `crown/src/bn/gf2m.rs`.

## Config pins

| pin | value | reason |
|---|---|---|
| `$win64` | `0` | unix SysV ABI; Win64 SEH blocks (`se_handler`, `.pdata`/`.xdata`) and the 5th-argument stack spill dropped |
| `$avx`/`$addx` | n/a | no assembler probes; the PCLMULQDQ path is selected at **runtime** via `OPENSSL_ia32cap_P` bit 33 (`bt $33,%r10`) |

Reproduce the reference with `perl crypto/bn/asm/x86_64-gf2m.pl elf`
(no `CC` needed).

## Exported global symbols

- `bn_GF2m_mul_2x2`

Internal (non-global):

- `_mul_1x1` — `.type ...,@abi-omnipotent`; 64x64 -> 128 carry-less
  product in `$lo`/`$hi` (%rax/%rdx) using a 16-entry x4-slice table on
  the stack plus SSE2 `movq`/`pslldq` accumulation.
- `.Lvanilla_mul_2x2`, `.Lbody_mul_2x2`, `.Lepilogue_mul_2x2`,
  `.Lend_mul_2x2`, `.Lend_mul_1x1` — control-flow / CFI boundaries.

External reference: `OPENSSL_ia32cap_P` (`.extern`, swallowed by the
xlate for gas; supplied by `utils/cpuid`, same as the mont/rsaz ports).

## C signature

```c
void bn_GF2m_mul_2x2(BN_ULONG r[4], BN_ULONG a1, BN_ULONG a0,
                     BN_ULONG b1, BN_ULONG b0);
```

Computes `(a1·x^64 + a0)·(b1·x^64 + b0)` over GF(2)[x], storing the
256-bit result as 4 little-endian 64-bit limbs.

## Encoding notes

`translateAssembly` (like the perl `x86_64-xlate.pl`) encodes the
following as raw `.byte` rows:

- inter-register `movq` GPR <-> XMM ("elderly gas can't handle" note) —
  the four `movq $a1/%xmm*` argument loads and the two `movq $R,$i*`
  table-drain stores.
- `pclmulqdq` (three sites in the PCLMUL path).
- `ret` -> `.byte 0xf3,0xc3` (rep ret).
- `.asciz` signature string -> `.byte` char codes.

## Re-verify

```
cd ~/crown-ref/openssl && perl crypto/bn/asm/x86_64-gf2m.pl elf > /tmp/gf2m_ref.s
cd ~/crown-second && cargo run -p crown-jsasm --example dump -- crown/src/bn/gf2m_x86_64.ts > /tmp/gf2m_ts.s
diff -u /tmp/gf2m_ref.s /tmp/gf2m_ts.s
cargo test -p crown --lib --features asm gf2m
```

Verified 2026-09-28: identical except the one-line `.note.gnu.property`
spelling (`".note.gnu.property", "a"` from `translateAssembly` vs
`.note.gnu.property, #alloc` from the host's `$gnuas=false` perl xlate) —
the known, documented CET-note delta. Instruction bytes, labels, CFI
directives, and the `.byte` signature row are byte-identical.

## Wiring status

Translated and unit-tested; **not dispatched** into any crown consumer
(crown EC is prime-field only, so `bn_gf2m.c`'s binary-curve callers have
no counterpart). `crate::bn::gf2m::mul_2x2` exports the primitive and the
tests cross-check it against a portable shift-and-xor polynomial
reference (`gf2m::poly_mul2x2`). Folding into a future binary-curve
implementation is a pure caller-side task.
