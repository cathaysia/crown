/**
 * sha256_block_data_order for x86_64.
 *
 * TypeScript port of the $SZ==4 branch of OpenSSL
 * crypto/sha/asm/sha512-x86_64.pl (selected by an output name without
 * "512").
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $shaext=1, $avx=0 (the perl
 * script auto-detects the assembler; without $ENV{CC} it emits the ialu,
 * shaext and ssse3 code paths for SHA-256).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

const func = 'sha256_block_data_order';
const TABLE = 'K256';
const SZ = 4;
const ROT = ['%eax', '%ebx', '%ecx', '%edx', '%r8d', '%r9d', '%r10d', '%r11d'];
const [A, B, C, D, E, F, G, H] = ROT;
const T1 = '%r12d';
const a0 = '%r13d';
let a1 = '%r14d';
let a2 = '%r15d';
let a3 = '%edi';
const Sigma0 = [2, 13, 22];
const Sigma1 = [6, 11, 25];
const sigma0 = [7, 18, 3];
const sigma1 = [17, 19, 10];
const rounds = 64;

const ctx = '%rdi'; // 1st arg, zapped by a3
const inp = '%rsi'; // 2nd arg
const Tbl = '%rbp';

const _ctx = `${16 * SZ}+0*8(%rsp)`;
const _inp = `${16 * SZ}+1*8(%rsp)`;
const _end = `${16 * SZ}+2*8(%rsp)`;
const _rsp = `${16 * SZ + 3 * 8}(%rsp)`;
const framesz = `${16 * SZ}+4*8`;

function ROUND_00_15(
  i: number,
  a: string,
  b: string,
  c: string,
  d: string,
  e: string,
  f: string,
  g: string,
  h: string,
): void {
  let STRIDE = SZ;
  if (i % (16 / SZ) === 16 / SZ - 1) {
    STRIDE += 16;
  }

  code += `	ror	$${Sigma1[2] - Sigma1[1]},${a0}
	mov	${f},${a2}

	xor	${e},${a0}
	ror	$${Sigma0[2] - Sigma0[1]},${a1}
	xor	${g},${a2}			# f^g

	mov	${T1},${SZ * (i & 0xf)}(%rsp)
	xor	${a},${a1}
	and	${e},${a2}			# (f^g)&e

	ror	$${Sigma1[1] - Sigma1[0]},${a0}
	add	${h},${T1}			# T1+=h
	xor	${g},${a2}			# Ch(e,f,g)=((f^g)&e)^g

	ror	$${Sigma0[1] - Sigma0[0]},${a1}
	xor	${e},${a0}
	add	${a2},${T1}			# T1+=Ch(e,f,g)

	mov	${a},${a2}
	add	(${Tbl}),${T1}		# T1+=K[round]
	xor	${a},${a1}

	xor	${b},${a2}			# a^b, b^c in next round
	ror	$${Sigma1[0]},${a0}	# Sigma1(e)
	mov	${b},${h}

	and	${a2},${a3}
	ror	$${Sigma0[0]},${a1}	# Sigma0(a)
	add	${a0},${T1}			# T1+=Sigma1(e)

	xor	${a3},${h}			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	${T1},${d}			# d+=T1
	add	${T1},${h}			# h+=T1

	lea	${STRIDE}(${Tbl}),${Tbl}	# round++
`;
  if (i < 15) {
    code += `	add	${a1},${h}			# h+=Sigma0(a)
`;
  }
  [a2, a3] = [a3, a2];
}

function ROUND_16_XX(
  i: number,
  a: string,
  b: string,
  c: string,
  d: string,
  e: string,
  f: string,
  g: string,
  h: string,
): void {
  code += `	mov	${SZ * ((i + 1) & 0xf)}(%rsp),${a0}
	mov	${SZ * ((i + 14) & 0xf)}(%rsp),${a2}

	mov	${a0},${T1}
	ror	$${sigma0[1] - sigma0[0]},${a0}
	add	${a1},${a}			# modulo-scheduled h+=Sigma0(a)
	mov	${a2},${a1}
	ror	$${sigma1[1] - sigma1[0]},${a2}

	xor	${T1},${a0}
	shr	$${sigma0[2]},${T1}
	ror	$${sigma0[0]},${a0}
	xor	${a1},${a2}
	shr	$${sigma1[2]},${a1}

	ror	$${sigma1[0]},${a2}
	xor	${a0},${T1}			# sigma0(X[(i+1)&0xf])
	xor	${a1},${a2}			# sigma1(X[(i+14)&0xf])
	add	${SZ * ((i + 9) & 0xf)}(%rsp),${T1}

	add	${SZ * (i & 0xf)}(%rsp),${T1}
	mov	${e},${a0}
	add	${a2},${T1}
	mov	${a},${a1}
`;
  ROUND_00_15(i, a, b, c, d, e, f, g, h);
}

function genIalu(): void {
  code += `.text

.extern	OPENSSL_ia32cap_P
.globl	${func}
.type	${func},@function,3
.align	16
${func}:
.cfi_startproc
    lea OPENSSL_ia32cap_P(%rip),%r10
    mov 0(%r10),%r9
    mov 8(%r10),%r11d
    test $${1 << 29},%r11d            # check for SHA
    jnz  _shaext_shortcut
    bt $41,%r9                     # mask SSSE3
    jc .Lssse3_shortcut
	mov	%rsp,%rax		# copy %rsp
.cfi_def_cfa_register	%rax
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	shl	$4,%rdx		# num*16
	sub	$${framesz},%rsp
	lea	(${inp},%rdx,${SZ}),%rdx	# inp+num*16*${SZ}
	and	$-64,%rsp		# align stack frame
	mov	${ctx},${_ctx}		# save ctx, 1st arg
	mov	${inp},${_inp}		# save inp, 2nd arh
	mov	%rdx,${_end}		# save end pointer, "3rd" arg
	mov	%rax,${_rsp}		# save copy of %rsp
.cfi_cfa_expression	${_rsp},deref,+8
.Lprologue:

	mov	${SZ * 0}(${ctx}),${A}
	mov	${SZ * 1}(${ctx}),${B}
	mov	${SZ * 2}(${ctx}),${C}
	mov	${SZ * 3}(${ctx}),${D}
	mov	${SZ * 4}(${ctx}),${E}
	mov	${SZ * 5}(${ctx}),${F}
	mov	${SZ * 6}(${ctx}),${G}
	mov	${SZ * 7}(${ctx}),${H}
	jmp	.Lloop

.align	16
.Lloop:
	mov	${B},${a3}
	lea	${TABLE}(%rip),${Tbl}
	xor	${C},${a3}			# magic
`;
  let i: number;
  for (i = 0; i < 16; i++) {
    code += `	mov	${SZ * i}(${inp}),${T1}\n`;
    code += `	mov	${ROT[4]},${a0}\n`;
    code += `	mov	${ROT[0]},${a1}\n`;
    code += `	bswap	${T1}\n`;
    ROUND_00_15(
      i,
      ROT[0],
      ROT[1],
      ROT[2],
      ROT[3],
      ROT[4],
      ROT[5],
      ROT[6],
      ROT[7],
    );
    ROT.unshift(ROT.pop() as string);
  }
  code += `	jmp	.Lrounds_16_xx
.align	16
.Lrounds_16_xx:
`;
  for (; i < 32; i++) {
    ROUND_16_XX(
      i,
      ROT[0],
      ROT[1],
      ROT[2],
      ROT[3],
      ROT[4],
      ROT[5],
      ROT[6],
      ROT[7],
    );
    ROT.unshift(ROT.pop() as string);
  }

  code += `	cmpb	$0,${SZ - 1}(${Tbl})
	jnz	.Lrounds_16_xx

	mov	${_ctx},${ctx}
	add	${a1},${A}			# modulo-scheduled h+=Sigma0(a)
	lea	${16 * SZ}(${inp}),${inp}

	add	${SZ * 0}(${ctx}),${A}
	add	${SZ * 1}(${ctx}),${B}
	add	${SZ * 2}(${ctx}),${C}
	add	${SZ * 3}(${ctx}),${D}
	add	${SZ * 4}(${ctx}),${E}
	add	${SZ * 5}(${ctx}),${F}
	add	${SZ * 6}(${ctx}),${G}
	add	${SZ * 7}(${ctx}),${H}

	cmp	${_end},${inp}

	mov	${A},${SZ * 0}(${ctx})
	mov	${B},${SZ * 1}(${ctx})
	mov	${C},${SZ * 2}(${ctx})
	mov	${D},${SZ * 3}(${ctx})
	mov	${E},${SZ * 4}(${ctx})
	mov	${F},${SZ * 5}(${ctx})
	mov	${G},${SZ * 6}(${ctx})
	mov	${H},${SZ * 7}(${ctx})
	jb	.Lloop

	mov	${_rsp},%rsi
.cfi_def_cfa	%rsi,8
	mov	-48(%rsi),%r15
.cfi_restore	%r15
	mov	-40(%rsi),%r14
.cfi_restore	%r14
	mov	-32(%rsi),%r13
.cfi_restore	%r13
	mov	-24(%rsi),%r12
.cfi_restore	%r12
	mov	-16(%rsi),%rbp
.cfi_restore	%rbp
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lepilogue:
	ret
.cfi_endproc
.size	${func},.-${func}
`;
}

function genTable(): void {
  code += `.section .rodata align=64
.align	64
.type	${TABLE},@object
${TABLE}:
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f
	.long	0x03020100,0x0b0a0908,0xffffffff,0xffffffff
	.long	0x03020100,0x0b0a0908,0xffffffff,0xffffffff
	.long	0xffffffff,0xffffffff,0x03020100,0x0b0a0908
	.long	0xffffffff,0xffffffff,0x03020100,0x0b0a0908
	.asciz	"SHA256 block transform for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.previous
`;
}

function genShaext(): void {
  const seCtx = '%rdi';
  const seInp = '%rsi';
  const seNum = '%rdx';
  const seTbl = '%rcx';

  const Wi = '%xmm0';
  const ABEF = '%xmm1';
  const CDGH = '%xmm2';
  const TMP = '%xmm7';
  const BSWAP = '%xmm8';
  const ABEF_SAVE = '%xmm9';
  const CDGH_SAVE = '%xmm10';
  const MSG = ['%xmm3', '%xmm4', '%xmm5', '%xmm6'];

  code += `.type	sha256_block_data_order_shaext,@function,3
.align	64
sha256_block_data_order_shaext:
_shaext_shortcut:
.cfi_startproc
	lea		K256+0x80(%rip),${seTbl}
	movdqu		(${seCtx}),${ABEF}		# DCBA
	movdqu		16(${seCtx}),${CDGH}		# HGFE
	movdqa		0x200-0x80(${seTbl}),${TMP}	# byte swap mask

	pshufd		$0x1b,${ABEF},${Wi}	# ABCD
	pshufd		$0xb1,${ABEF},${ABEF}	# CDAB
	pshufd		$0x1b,${CDGH},${CDGH}	# EFGH
	movdqa		${TMP},${BSWAP}		# offload
	palignr		$8,${CDGH},${ABEF}		# ABEF
	punpcklqdq	${Wi},${CDGH}		# CDGH
	jmp		.Loop_shaext

.align	16
.Loop_shaext:
	movdqu		(${seInp}),${MSG[0]}
	movdqu		0x10(${seInp}),${MSG[1]}
	movdqu		0x20(${seInp}),${MSG[2]}
	pshufb		${TMP},${MSG[0]}
	movdqu		0x30(${seInp}),${MSG[3]}

	movdqa		0*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[0]},${Wi}
	pshufb		${TMP},${MSG[1]}
	movdqa		${CDGH},${CDGH_SAVE}	# offload
	sha256rnds2	${ABEF},${CDGH}		# 0-3
	pshufd		$0x0e,${Wi},${Wi}
	nop
	movdqa		${ABEF},${ABEF_SAVE}	# offload
	sha256rnds2	${CDGH},${ABEF}

	movdqa		1*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[1]},${Wi}
	pshufb		${TMP},${MSG[2]}
	sha256rnds2	${ABEF},${CDGH}		# 4-7
	pshufd		$0x0e,${Wi},${Wi}
	lea		0x40(${seInp}),${seInp}
	sha256msg1	${MSG[1]},${MSG[0]}
	sha256rnds2	${CDGH},${ABEF}

	movdqa		2*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[2]},${Wi}
	pshufb		${TMP},${MSG[3]}
	sha256rnds2	${ABEF},${CDGH}		# 8-11
	pshufd		$0x0e,${Wi},${Wi}
	movdqa		${MSG[3]},${TMP}
	palignr		$4,${MSG[2]},${TMP}
	nop
	paddd		${TMP},${MSG[0]}
	sha256msg1	${MSG[2]},${MSG[1]}
	sha256rnds2	${CDGH},${ABEF}

	movdqa		3*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[3]},${Wi}
	sha256msg2	${MSG[3]},${MSG[0]}
	sha256rnds2	${ABEF},${CDGH}		# 12-15
	pshufd		$0x0e,${Wi},${Wi}
	movdqa		${MSG[0]},${TMP}
	palignr		$4,${MSG[3]},${TMP}
	nop
	paddd		${TMP},${MSG[1]}
	sha256msg1	${MSG[3]},${MSG[2]}
	sha256rnds2	${CDGH},${ABEF}
`;
  for (let i = 4; i < 16 - 3; i++) {
    code += `	movdqa		${i}*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[0]},${Wi}
	sha256msg2	${MSG[0]},${MSG[1]}
	sha256rnds2	${ABEF},${CDGH}		# 16-19...
	pshufd		$0x0e,${Wi},${Wi}
	movdqa		${MSG[1]},${TMP}
	palignr		$4,${MSG[0]},${TMP}
	nop
	paddd		${TMP},${MSG[2]}
	sha256msg1	${MSG[0]},${MSG[3]}
	sha256rnds2	${CDGH},${ABEF}
`;
    MSG.push(MSG.shift() as string);
  }
  code += `	movdqa		13*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[0]},${Wi}
	sha256msg2	${MSG[0]},${MSG[1]}
	sha256rnds2	${ABEF},${CDGH}		# 52-55
	pshufd		$0x0e,${Wi},${Wi}
	movdqa		${MSG[1]},${TMP}
	palignr		$4,${MSG[0]},${TMP}
	sha256rnds2	${CDGH},${ABEF}
	paddd		${TMP},${MSG[2]}

	movdqa		14*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[1]},${Wi}
	sha256rnds2	${ABEF},${CDGH}		# 56-59
	pshufd		$0x0e,${Wi},${Wi}
	sha256msg2	${MSG[1]},${MSG[2]}
	movdqa		${BSWAP},${TMP}
	sha256rnds2	${CDGH},${ABEF}

	movdqa		15*32-0x80(${seTbl}),${Wi}
	paddd		${MSG[2]},${Wi}
	nop
	sha256rnds2	${ABEF},${CDGH}		# 60-63
	pshufd		$0x0e,${Wi},${Wi}
	dec		${seNum}
	nop
	sha256rnds2	${CDGH},${ABEF}

	paddd		${CDGH_SAVE},${CDGH}
	paddd		${ABEF_SAVE},${ABEF}
	jnz		.Loop_shaext

	pshufd		$0xb1,${CDGH},${CDGH}	# DCHG
	pshufd		$0x1b,${ABEF},${TMP}	# FEBA
	pshufd		$0xb1,${ABEF},${ABEF}	# BAFE
	punpckhqdq	${CDGH},${ABEF}		# DCBA
	palignr		$8,${TMP},${CDGH}		# HGFE

	movdqu	${ABEF},(${seCtx})
	movdqu	${CDGH},16(${seCtx})
	ret
.cfi_endproc
.size	sha256_block_data_order_shaext,.-sha256_block_data_order_shaext
`;
}

// ---------------------------------------------------------------------------
// ssse3 implementation
// ---------------------------------------------------------------------------
interface Insn {
  text: string;
  run: () => void;
}

function insn(text: string, run: () => void): Insn {
  return { text, run };
}

function AUTOLOAD(opcode: string, ...args: string[]): void {
  let arg = args.pop() as string;
  if (/^[0-9]+$/.test(arg)) {
    arg = '$' + arg;
  }
  const rest = [...args].reverse();
  code += `\t${opcode}\t${[arg, ...rest].join(',')}\n`;
}

const a4 = T1;

function body_00_15(): Insn[] {
  let a = '';
  let b = '';
  let c = '';
  let d = '';
  let e = '';
  let f = '';
  let g = '';
  let h = '';
  return [
    insn('($a,...$h)=@ROT;&ror($a0,$Sigma1[2]-$Sigma1[1])', () => {
      [a, b, c, d, e, f, g, h] = ROT;
      AUTOLOAD('ror', a0, (Sigma1[2] - Sigma1[1]).toString());
    }),
    insn('&mov($a,$a1)', () => {
      AUTOLOAD('mov', a, a1);
    }),
    insn('&mov($a4,$f)', () => {
      AUTOLOAD('mov', a4, f);
    }),
    insn('&ror($a1,$Sigma0[2]-$Sigma0[1])', () => {
      AUTOLOAD('ror', a1, (Sigma0[2] - Sigma0[1]).toString());
    }),
    insn('&xor($a0,$e)', () => {
      AUTOLOAD('xor', a0, e);
    }),
    insn('&xor($a4,$g)', () => {
      AUTOLOAD('xor', a4, g); // f^g
    }),
    insn('&ror($a0,$Sigma1[1]-$Sigma1[0])', () => {
      AUTOLOAD('ror', a0, (Sigma1[1] - Sigma1[0]).toString());
    }),
    insn('&xor($a1,$a)', () => {
      AUTOLOAD('xor', a1, a);
    }),
    insn('&and($a4,$e)', () => {
      AUTOLOAD('and', a4, e); // (f^g)&e
    }),
    insn('&xor($a0,$e)', () => {
      AUTOLOAD('xor', a0, e);
    }),
    insn('&add($h,X[i]+K[i])', () => {
      AUTOLOAD('add', h, (SZ * (i & 15)).toString() + '(%rsp)'); // h+=X[i]+K[i]
    }),
    insn('&mov($a2,$a)', () => {
      AUTOLOAD('mov', a2, a);
    }),
    insn('&xor($a4,$g)', () => {
      AUTOLOAD('xor', a4, g); // Ch(e,f,g)=((f^g)&e)^g
    }),
    insn('&ror($a1,$Sigma0[1]-$Sigma0[0])', () => {
      AUTOLOAD('ror', a1, (Sigma0[1] - Sigma0[0]).toString());
    }),
    insn('&xor($a2,$b)', () => {
      AUTOLOAD('xor', a2, b); // a^b, b^c in next round
    }),
    insn('&add($h,$a4)', () => {
      AUTOLOAD('add', h, a4); // h+=Ch(e,f,g)
    }),
    insn('&ror($a0,$Sigma1[0])', () => {
      AUTOLOAD('ror', a0, Sigma1[0].toString()); // Sigma1(e)
    }),
    insn('&and($a3,$a2)', () => {
      AUTOLOAD('and', a3, a2); // (b^c)&(a^b)
    }),
    insn('&xor($a1,$a)', () => {
      AUTOLOAD('xor', a1, a);
    }),
    insn('&add($h,$a0)', () => {
      AUTOLOAD('add', h, a0); // h+=Sigma1(e)
    }),
    insn('&xor($a3,$b)', () => {
      AUTOLOAD('xor', a3, b); // Maj(a,b,c)=Ch(a^b,c,b)
    }),
    insn('&ror($a1,$Sigma0[0])', () => {
      AUTOLOAD('ror', a1, Sigma0[0].toString()); // Sigma0(a)
    }),
    insn('&add($d,$h)', () => {
      AUTOLOAD('add', d, h); // d+=h
    }),
    insn('&add($h,$a3)', () => {
      AUTOLOAD('add', h, a3); // h+=Maj(a,b,c)
    }),
    insn('&mov($a0,$d)', () => {
      AUTOLOAD('mov', a0, d);
    }),
    insn(
      '&add($a1,$h);($a2,$a3)=($a3,$a2);unshift(@ROT,pop(@ROT));$i++;',
      () => {
        AUTOLOAD('add', a1, h); // h+=Sigma0(a)
        [a2, a3] = [a3, a2];
        ROT.unshift(ROT.pop() as string);
        i++;
      },
    ),
  ];
}

// ssse3 local registers
const X = ['%xmm0', '%xmm1', '%xmm2', '%xmm3'];
const t0 = '%xmm4';
const t1 = '%xmm5';
const t2 = '%xmm6';
const t3 = '%xmm7';
const t4 = '%xmm8';
const t5 = '%xmm9';

let i = 0;

function SSSE3_256_00_47(j: number, body: () => Insn[], Xarg: string[]): void {
  const insns = [...body(), ...body(), ...body(), ...body()]; // 104 instructions
  const ev = (): void => {
    const s = insns.shift();
    if (s) {
      s.run();
    }
  };
  const X = Xarg;

  ev(); //@
  AUTOLOAD('movdqa', t0, X[1]);
  ev();
  ev();
  AUTOLOAD('movdqa', t3, X[3]);
  ev(); //@
  ev();
  ev();
  ev(); //@
  ev();
  AUTOLOAD('palignr', t0, X[0], SZ.toString()); // X[1..4]
  ev();
  ev();
  AUTOLOAD('palignr', t3, X[2], SZ.toString()); // X[9..12]
  ev();
  ev();
  ev();
  ev(); //@
  AUTOLOAD('movdqa', t1, t0);
  ev();
  ev();
  AUTOLOAD('movdqa', t2, t0);
  ev(); //@
  ev();
  AUTOLOAD('psrld', t0, sigma0[2].toString());
  ev();
  ev();
  ev();
  AUTOLOAD('paddd', X[0], t3); // X[0..3] += X[9..12]
  ev(); //@
  ev();
  AUTOLOAD('psrld', t2, sigma0[0].toString());
  ev();
  ev();
  AUTOLOAD('pshufd', t3, X[3], '250'); // X[4..15]
  ev();
  ev(); //@
  AUTOLOAD('pslld', t1, (8 * SZ - sigma0[1]).toString());
  ev();
  ev();
  AUTOLOAD('pxor', t0, t2);
  ev(); //@
  ev();
  ev();
  ev(); //@
  AUTOLOAD('psrld', t2, (sigma0[1] - sigma0[0]).toString());
  ev();
  AUTOLOAD('pxor', t0, t1);
  ev();
  ev();
  AUTOLOAD('pslld', t1, (sigma0[1] - sigma0[0]).toString());
  ev();
  ev();
  AUTOLOAD('pxor', t0, t2);
  ev();
  ev(); //@
  AUTOLOAD('movdqa', t2, t3);
  ev();
  ev();
  AUTOLOAD('pxor', t0, t1); // sigma0(X[1..4])
  ev(); //@
  ev();
  ev();
  AUTOLOAD('psrld', t3, sigma1[2].toString());
  ev();
  ev();
  AUTOLOAD('paddd', X[0], t0); // X[0..3] += sigma0(X[1..4])
  ev(); //@
  ev();
  AUTOLOAD('psrlq', t2, sigma1[0].toString());
  ev();
  ev();
  ev();
  AUTOLOAD('pxor', t3, t2);
  ev(); //@
  ev();
  ev();
  ev(); //@
  AUTOLOAD('psrlq', t2, (sigma1[1] - sigma1[0]).toString());
  ev();
  ev();
  AUTOLOAD('pxor', t3, t2);
  ev(); //@
  ev();
  ev();
  // &pshufb ($t3,$t4) is commented out in perl
  AUTOLOAD('pshufd', t3, t3, '128');
  ev();
  ev();
  ev();
  AUTOLOAD('psrldq', t3, '8');
  ev();
  ev(); //@
  ev();
  ev();
  ev(); //@
  AUTOLOAD('paddd', X[0], t3); // X[0..1] += sigma1(X[14..15])
  ev();
  ev();
  ev();
  AUTOLOAD('pshufd', t3, X[0], '80'); // X[16..17]
  ev();
  ev(); //@
  ev();
  AUTOLOAD('movdqa', t2, t3);
  ev();
  ev();
  AUTOLOAD('psrld', t3, sigma1[2].toString());
  ev();
  ev(); //@
  AUTOLOAD('psrlq', t2, sigma1[0].toString());
  ev();
  ev();
  AUTOLOAD('pxor', t3, t2);
  ev(); //@
  ev();
  ev();
  ev(); //@
  ev();
  AUTOLOAD('psrlq', t2, (sigma1[1] - sigma1[0]).toString());
  ev();
  ev();
  ev();
  AUTOLOAD('pxor', t3, t2);
  ev();
  ev();
  ev(); //@
  // &pshufb ($t3,$t5) is commented out in perl
  AUTOLOAD('pshufd', t3, t3, '8');
  ev();
  ev();
  AUTOLOAD('movdqa', t2, (16 * 2 * j).toString() + `(${Tbl})`);
  ev(); //@
  ev();
  AUTOLOAD('pslldq', t3, '8');
  ev();
  ev();
  ev();
  AUTOLOAD('paddd', X[0], t3); // X[2..3] += sigma1(X[16..17])
  ev(); //@
  ev();
  ev();

  AUTOLOAD('paddd', t2, X[0]);
  for (const s of insns) {
    s.run();
  } // remaining instructions
  AUTOLOAD('movdqa', (16 * j).toString() + '(%rsp)', t2);
}

function genSsse3(): void {
  code += `.type	${func}_ssse3,@function,3
.align	64
${func}_ssse3:
.cfi_startproc
.Lssse3_shortcut:
	mov	%rsp,%rax		# copy %rsp
.cfi_def_cfa_register	%rax
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	shl	$4,%rdx		# num*16
	sub	$${64 + 32 + 0 * 16 * 4},%rsp
	lea	(${inp},%rdx,${SZ}),%rdx	# inp+num*16*${SZ}
	and	$-64,%rsp		# align stack frame
	mov	${ctx},${_ctx}		# save ctx, 1st arg
	mov	${inp},${_inp}		# save inp, 2nd arh
	mov	%rdx,${_end}		# save end pointer, "3rd" arg
	mov	%rax,${_rsp}		# save copy of %rsp
.cfi_cfa_expression	${_rsp},deref,+8
.Lprologue_ssse3:

	mov	${SZ * 0}(${ctx}),${A}
	mov	${SZ * 1}(${ctx}),${B}
	mov	${SZ * 2}(${ctx}),${C}
	mov	${SZ * 3}(${ctx}),${D}
	mov	${SZ * 4}(${ctx}),${E}
	mov	${SZ * 5}(${ctx}),${F}
	mov	${SZ * 6}(${ctx}),${G}
	mov	${SZ * 7}(${ctx}),${H}
	#movdqa	${TABLE}+${SZ * 2 * rounds}+32(%rip),${t4}
	#movdqa	${TABLE}+${SZ * 2 * rounds}+64(%rip),${t5}
	jmp	.Lloop_ssse3
.align	16
.Lloop_ssse3:
	movdqa	${TABLE}+${SZ * 2 * rounds}(%rip),${t3}
	movdqu	0x00(${inp}),${X[0]}
	movdqu	0x10(${inp}),${X[1]}
	movdqu	0x20(${inp}),${X[2]}
	pshufb	${t3},${X[0]}
	movdqu	0x30(${inp}),${X[3]}
	lea	${TABLE}(%rip),${Tbl}
	pshufb	${t3},${X[1]}
	movdqa	0x00(${Tbl}),${t0}
	movdqa	0x20(${Tbl}),${t1}
	pshufb	${t3},${X[2]}
	paddd	${X[0]},${t0}
	movdqa	0x40(${Tbl}),${t2}
	pshufb	${t3},${X[3]}
	movdqa	0x60(${Tbl}),${t3}
	paddd	${X[1]},${t1}
	paddd	${X[2]},${t2}
	paddd	${X[3]},${t3}
	movdqa	${t0},0x00(%rsp)
	mov	${A},${a1}
	movdqa	${t1},0x10(%rsp)
	mov	${B},${a3}
	movdqa	${t2},0x20(%rsp)
	xor	${C},${a3}			# magic
	movdqa	${t3},0x30(%rsp)
	mov	${E},${a0}
	jmp	.Lssse3_00_47

.align	16
.Lssse3_00_47:
	sub	$${-16 * 2 * SZ},${Tbl}	# size optimization
`;
  let j: number;
  for (i = 0, j = 0; j < 4; j++) {
    SSSE3_256_00_47(j, body_00_15, [...X]);
    X.push(X.shift() as string); // rotate(@X)
  }
  AUTOLOAD('cmpb', `${SZ - 1 + 16 * 2 * SZ}(${Tbl})`, '0');
  AUTOLOAD('jne', '.Lssse3_00_47');

  for (i = 0; i < 16; ) {
    for (const s of body_00_15()) {
      s.run();
    }
  }
  code += `	mov	${_ctx},${ctx}
	mov	${a1},${A}

	add	${SZ * 0}(${ctx}),${A}
	lea	${16 * SZ}(${inp}),${inp}
	add	${SZ * 1}(${ctx}),${B}
	add	${SZ * 2}(${ctx}),${C}
	add	${SZ * 3}(${ctx}),${D}
	add	${SZ * 4}(${ctx}),${E}
	add	${SZ * 5}(${ctx}),${F}
	add	${SZ * 6}(${ctx}),${G}
	add	${SZ * 7}(${ctx}),${H}

	cmp	${_end},${inp}

	mov	${A},${SZ * 0}(${ctx})
	mov	${B},${SZ * 1}(${ctx})
	mov	${C},${SZ * 2}(${ctx})
	mov	${D},${SZ * 3}(${ctx})
	mov	${E},${SZ * 4}(${ctx})
	mov	${F},${SZ * 5}(${ctx})
	mov	${G},${SZ * 6}(${ctx})
	mov	${H},${SZ * 7}(${ctx})
	jb	.Lloop_ssse3

	mov	${_rsp},%rsi
.cfi_def_cfa	%rsi,8
	mov	-48(%rsi),%r15
.cfi_restore	%r15
	mov	-40(%rsi),%r14
.cfi_restore	%r14
	mov	-32(%rsi),%r13
.cfi_restore	%r13
	mov	-24(%rsi),%r12
.cfi_restore	%r12
	mov	-16(%rsi),%rbp
.cfi_restore	%rbp
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lepilogue_ssse3:
	ret
.cfi_endproc
.size	${func}_ssse3,.-${func}_ssse3
`;
}

function sha256op38(instr: string, args: string): string {
  const opcodelet: Record<string, number> = {
    sha256rnds2: 0xcb,
    sha256msg1: 0xcc,
    sha256msg2: 0xcd,
  };

  const m = args.match(/%xmm([0-7]),\s*%xmm([0-7])/);
  if (opcodelet[instr] !== undefined && m) {
    const opcodes = [0x0f, 0x38];
    opcodes.push(opcodelet[instr]);
    opcodes.push(0xc0 | (parseInt(m[1]) & 7) | ((parseInt(m[2]) & 7) << 3)); // ModR/M
    return '.byte\t' + opcodes.join(',');
  }
  return instr + '\t' + args;
}

function postProcess(): void {
  code = code
    .split('\n')
    .map(line => {
      const m = line.match(/\b(sha256[^\s]*)\s+(.*)/);
      if (m) {
        return line.slice(0, m.index) + sha256op38(m[1], m[2]);
      }
      return line;
    })
    .join('\n');
}

genIalu();
genTable();
genShaext();
genSsse3();
postProcess();

export default translateAssembly(code);
