# RC4-MD5 x86_64 — translation notes

TypeScript port of `crypto/rc4/asm/rc4-md5-x86_64.pl` (CRYPTOGAMS, Andy Polyakov).
Generator: `staging/rc4-md5/x86_64.ts` (pre-xlate body wrapped in `translateAssembly`).

## Config pins

| pin | value | notes |
|---|---|---|
| `$win64` | `0` | unix SysV; Win64 SEH / `.pdata` / `.xdata` blocks dropped |
| `$rc4` | `1` | script default `my ($rc4,$md5)=(1,1)` |
| `$md5` | `1` | stitches MD5 into the RC4 path (not the dummy-MD5 `$D` mode) |
| `$D` | undef | `$D="#" if (!$md5)` is inactive because `$md5=1` |
| `$MOD` | `32` | script default (16/32/64 also legal in the .pl) |
| `$avx` | n/a | this script has **no** AVX/CPUID probe |

With `$rc4=$md5=1` the script emits only the stitched subroutine (standalone
`RC4` / `ossl_md5_block_asm_data_order` are alternative `$rc4`/`$md5` one-hot
configs, not additional symbols here).

## Exported global symbols

```
rc4_md5_enc
```

(plus the standard `.note.gnu.property` CET note appended by `x86_64-xlate`,
i.e. by `translateAssembly`, not present in the pre-xlate body).

## C signature (from the perl comments)

```c
void rc4_md5_enc(
        RC4_KEY *key,           /* %rdi */
        const void *in0,        /* %rsi  RC4 input  */
        void *out,              /* %rdx  RC4 output */
        MD5_CTX *ctx,           /* %rcx */
        const void *inp,        /* %r8   MD5 input  */
        size_t len);            /* %r9   number of 64-byte blocks */
```

- `len` is a count of **64-byte blocks** (the asm does `shl $6,len` to form an
  end pointer). Both the RC4 stream (`in0`/`out`) and the MD5 stream (`inp`)
  must cover `len * 64` bytes; the residual-byte loop is **not** generated in
  this combined config, so lengths must be multiples of 64.
- Early-out `ret` when `len == 0`.
- Callee-saved used: `rbx`, `rbp`, `r12`–`r15` (88-byte frame: 6 pushes + `sub $40,%rsp`).

## Key / IV state layout

### RC4_KEY (`key` / `%rdi`) — matches OpenSSL `RC4_KEY` and crown `Rc4State` in
`crown/src/stream/rc4/xor_key_stream/asm.rs`

```
offset  0: x   (RC4_INT / u32; only the low byte is used and written back)
offset  4: y   (RC4_INT / u32; only the low byte is used and written back)
offset  8: s[256]  (RC4_INT / u32 S-box; accessed as (%rdi + 8 + i*4) after
                    `lea 8(%rdi),%rdi`, so index base is `s[0]`)
```

Load: `movb -8(%rdi),%bpl` (x), `movb -4(%rdi),%cl` (y) after the `lea`.
Store: `movl %ebp,-8(%rdi)`, `movl %ecx,-4(%rdi)` (full 32-bit writes of the
zero-extended byte).

### MD5_CTX (`ctx` / `%rcx`) — data-order block state only

```
offset  0: A  (u32, MD5_CTX->A / V[0] / %r8d)
offset  4: B  (u32, MD5_CTX->B / V[1] / %r9d)
offset  8: C  (u32, MD5_CTX->C / V[2] / %r10d)
offset 12: D  (u32, MD5_CTX->D / V[3] / %r11d)
```

Only these four words are read and written (`ossl_md5_block_asm_data_order`
semantics). `Nl`/`Nh`/`num`/partial buffer are the caller’s responsibility.
crown’s `hash::md5::Md5 { s: [u32; 4], x: [u8; 64], nx, len }` matches this:
pass `&mut md5.s` (or a dedicated `#[repr(C)] struct Md5BlockState([u32; 4])`)
as `ctx`; the asm will not touch `x`/`nx`/`len`.

### Stack frame (88 bytes)

| slot | use |
|---|---|
| `0(%rsp)` | spill of A |
| `4(%rsp)` | spill of B |
| `8(%rsp)` | spill of C |
| `12(%rsp)` | spill of D |
| `16(%rsp)` | end pointer (`inp + len*64`) |
| `24(%rsp)` | saved `MD5_CTX *` |
| `32(%rsp)` | saved original `len` (only in non-stitched / `$D` configs) |
| `40..80(%rsp)` | saved `r15,r14,r13,r12,rbp,rbx` |

## CPUID / ISA needs

- **None.** Plain x86_64 SSE2 baseline. No `OPENSSL_ia32cap_P`, no `cpuid`, no
  AVX/XOP branches. Uses GP registers plus `movdqu`/`pxor`/`punpck*`/`psll*`/
  `psr*`/`pand` (SSE2) for the RC4 keystream weave.
- CET `endbranch` is **not** present in this module. The trailing
  `.note.gnu.property` (GNU_PROPERTY_X86_FEATURE_1_AND = IBT|SHSTK) is added by
  `x86_64-xlate.pl` / `translateAssembly`, not by the generator body.

## Wiring suggestion for `crown/src/stream/rc4/`

Mirror `xor_key_stream/`:

```
crown/src/stream/rc4/md5_enc/
  mod.rs          // pub mod asm; pub mod generic; feature-gated dispatch
  generic.rs      // reference stitch for non-x86_64 / non-asm
  asm.rs          // global_asm!(crown_derive::jsasm_file!("crown/src/stream/rc4/md5_enc/x86_64.ts"))
  x86_64.ts       // this generator, moved out of staging/
```

`asm.rs` sketch (same pattern as `xor_key_stream/asm.rs`):

```rust
#![cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/stream/rc4/md5_enc/x86_64.ts"),
    options(att_syntax)
);
extern "C" {
    fn rc4_md5_enc(
        key: *const Rc4State,
        in0: *const u8,
        out: *mut u8,
        ctx: *mut Md5BlockState,
        inp: *const u8,
        len: usize, // 64-byte blocks
    );
}
```

Reuse `Rc4State` from `xor_key_stream/asm.rs` (already OpenSSL `RC4_KEY`-
compatible). Add `#[repr(C)] struct Md5BlockState { a: u32, b: u32, c: u32, d: u32 }`
or pass `md5.s` as `*mut [u32; 4]`. Caller must ensure `len % 64 == 0` input
sizes and that RC4 `in0`/`out` buffers are `len*64` bytes (the classic
RC4-MD5 TLS stitch: one RC4 keystream byte per MD5 round, 64 per block).
