# wp-x86_64 (Whirlpool compression) — port notes

Source: OpenSSL `crypto/whrlpool/asm/wp-x86_64.pl`
(Andy Polyakov; whirlpool_block for x86_64, ~2500 cycles per 64-byte block on
AMD64 at the time of writing — identical to the 32-bit MMX version.)

## Config pins

| pin | value | reason |
|---|---|---|
| `$win64` | `0` | unix SysV ABI; Win64 SEH blocks (`se_handler`, `.pdata`/`.xdata`) dropped |
| `$avx`/`$addx` | n/a | this script has no assembler/CPUID probes |

### Output dialect note (CET property)

`translateAssembly` appends the Intel CET `.note.gnu.property` section using
the clang/`$gnuas` spelling:

```
	.section ".note.gnu.property", "a"
```

The reference `perl crypto/whrlpool/asm/wp-x86_64.pl elf` on this host (gcc
`$gnuas` false) emits:

```
	.section .note.gnu.property, #alloc
```

This is the **only** line-level difference between the dump and the perl
output (verified `diff -u`: one hunk, one line). Instruction mnemonics,
operands, labels, `.byte` table rows, and CFI directives are byte-identical.
When re-verifying, either diff around that line or compare the sections
above `.note.gnu.property`.

## Exported global symbols

- `whirlpool_block`

Internal (non-global) symbols:

- `.Ltable` — `.rodata` T-table + round constants (`.align 64`)
  - bytes `0x000..0xFFF`: 256 rows × 16 bytes. Each row is one S-box/circulant
    8-byte value stored **twice**, so an unaligned 8-byte load at `+1..+7`
    inside the row yields the byte-rotated form the round mixes.
  - bytes `0x1000..0x104F`: `rc[0..9]`, 8 bytes each (Whirlpool round
    constants).
- `.Lprologue`, `.Louterloop`, `.Lround`, `.Lroundsdone`, `.Lalldone`,
  `.Lepilogue` — control-flow labels (CFI boundaries use `.Lprologue` /
  `.Lepilogue`).

## C signatures

Perl comment header names the entry `whirlpool_block`. Argument registers
(`$win64=0` SysV) and the frame save/restore show the prototype:

```c
void whirlpool_block(u64 *state, const void *inp, size_t n);
```

- `state` (`%rdi`): 8 little-endian 64-bit lanes `H[0..7]` — the leading
  `union { ... H[8] ... }` of OpenSSL `WIRLPOOL_CTX`, or crown's
  `h: &mut [u64; 8]`.
- `inp` (`%rsi`): pointer to `n` consecutive 64-byte message blocks.
- `n` (`%rdx`): block count, a full 64-bit `size_t` (saved/restored across the
  outer loop and decremented with `sub $1,%rax`).

crown wiring (`crown/src/hash/whirlpool/asm.rs`) matches this exactly:
`whirlpool_block(state: *mut u64, data: *const u8, num_blocks: usize)`.

## Register map

| reg | role |
|---|---|
| `%rdi` | `state` on entry; reloaded from the parameter block each outer iteration |
| `%rsi` | `inp` on entry; also the round counter / `lea (%rcx,%rcx),%rsi` table index scratch |
| `%rdx` | `n` on entry; also `movz %ah,%edx` byte scratch |
| `%rax` | saved entry `%rsp`; then `movz`/`shr` byte halves of `eax`; `n` countdown |
| `%rbx` | parameter-block pointer (`lea 128(%rsp),%rbx`); then `mov`/`shr` of `ebx` |
| `%rcx` | `xor %rcx,%rcx` then zero-extended byte indices |
| `%rbp` | `.Ltable(%rip)` pointer |
| `%r8`–`%r15` | the 8 message-lane words; the substitution loops rotate the `@mm` list so each register plays every column role |
| `%rsp` | 64-byte-aligned frame: `0..63` = K (round key), `64..127` = S (state), `128..` = parameter block (`0`=`state*`, `8`=`inp*`, `16`=`n`, `24`=round counter, `32`=saved `%rsp`) |

Callee-saved: `%rbx`, `%rbp`, `%r12`–`%r15` (pushed in the prologue, restored
from the saved-`%rsp` frame in `.Lalldone`). CFI: `cfi_push`/`cfi_restore`
pairs and a `cfi_cfa_expression` for the parameter block.

## Round structure (for diffing)

Per 64-byte block (`.Louterloop`):

1. Save `H` to K, `S = K ^ M` to the state slot.
2. Ten rounds (`.Lround`, counter at `24(%rbx)`):
   - theta-pi-gamma on K into `%r8-%r15` (first 8 substitution iterations,
     `mov` on iteration 0 else `xor`), store as new K.
   - theta-pi-gamma on S into `%r8-%r15` (next 8 iterations, always `xor`),
     keyed with the new K.
   - the two loops rotate the `@mm` register list each iteration (perl
     `push(@mm,shift(@mm))`); after 8 iterations the list is back in order.
3. `H ^= S ^ M` and store back to `state`; advance `inp += 64`, `n--`, loop.

## Re-verify against perl

```bash
# reference (OpenSSL tree)
cd /home/loongtao/crown-ref/openssl
perl crypto/whrlpool/asm/wp-x86_64.pl elf > /tmp/wp_ref.s

# jsasm dump (crown worktree)
cd /home/loongtao/crown-wt-whirlpool
cargo run -q -p crown-jsasm --example dump -- crown/src/hash/whirlpool/x86_64.ts > /tmp/wp_ts.s

# expect a single CET-note hunk (see "Output dialect note" above)
diff -u /tmp/wp_ref.s /tmp/wp_ts.s
```

To compare only the whirlpool body (instructions + table), stop before the
note:

```bash
diff -u <(sed -n '1,/^\.byte\t202,45,191/p' /tmp/wp_ref.s) \
        <(sed -n '1,/^\.byte\t202,45,191/p' /tmp/wp_ts.s)
```

Unit tests (`cargo test -p crown --lib --features asm whirlpool` and the
`--no-default-features --features std` software-only run) cross-check the
asm path against `block_soft` and the ISO/IEC 10118-3 vectors already in
`tests.rs`.
