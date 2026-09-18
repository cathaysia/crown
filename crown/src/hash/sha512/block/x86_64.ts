/**
 * sha512_block_data_order for x86_64.
 *
 * TypeScript port of the $SZ==8 branch of OpenSSL
 * crypto/sha/asm/sha512-x86_64.pl (selected by an output name containing
 * "512").
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $shaext=1, $avx=0 (the perl
 * script auto-detects the assembler; without $ENV{CC} it emits only the
 * ialu code path for SHA-512).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

const func = 'sha512_block_data_order';
const TABLE = 'K512';
const SZ = 8;
const ROT = ['%rax', '%rbx', '%rcx', '%rdx', '%r8', '%r9', '%r10', '%r11'];
const [A, B, C, D, E, F, G, H] = ROT;
const T1 = '%r12';
const a0 = '%r13';
let a1 = '%r14';
let a2 = '%r15';
let a3 = '%rdi';
const Sigma0 = [28, 34, 39];
const Sigma1 = [14, 18, 41];
const sigma0 = [1, 8, 7];
const sigma1 = [19, 61, 6];
const rounds = 80;

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

code += `.text

.extern	OPENSSL_ia32cap_P
.globl	${func}
.type	${func},@function,3
.align	16
${func}:
.cfi_startproc
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
  ROUND_00_15(i, ROT[0], ROT[1], ROT[2], ROT[3], ROT[4], ROT[5], ROT[6], ROT[7]);
  ROT.unshift(ROT.pop() as string);
}
code += `	jmp	.Lrounds_16_xx
.align	16
.Lrounds_16_xx:
`;
for (; i < 32; i++) {
  ROUND_16_XX(i, ROT[0], ROT[1], ROT[2], ROT[3], ROT[4], ROT[5], ROT[6], ROT[7]);
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

code += `.section .rodata align=64
.align	64
.type	${TABLE},@object
${TABLE}:
	.quad	0x428a2f98d728ae22,0x7137449123ef65cd
	.quad	0x428a2f98d728ae22,0x7137449123ef65cd
	.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	.quad	0x3956c25bf348b538,0x59f111f1b605d019
	.quad	0x3956c25bf348b538,0x59f111f1b605d019
	.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
	.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
	.quad	0xd807aa98a3030242,0x12835b0145706fbe
	.quad	0xd807aa98a3030242,0x12835b0145706fbe
	.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
	.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
	.quad	0x9bdc06a725c71235,0xc19bf174cf692694
	.quad	0x9bdc06a725c71235,0xc19bf174cf692694
	.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
	.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
	.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
	.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
	.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	.quad	0x983e5152ee66dfab,0xa831c66d2db43210
	.quad	0x983e5152ee66dfab,0xa831c66d2db43210
	.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
	.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
	.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
	.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
	.quad	0x06ca6351e003826f,0x142929670a0e6e70
	.quad	0x06ca6351e003826f,0x142929670a0e6e70
	.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
	.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
	.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
	.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
	.quad	0x81c2c92e47edaee6,0x92722c851482353b
	.quad	0x81c2c92e47edaee6,0x92722c851482353b
	.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
	.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
	.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
	.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
	.quad	0xd192e819d6ef5218,0xd69906245565a910
	.quad	0xd192e819d6ef5218,0xd69906245565a910
	.quad	0xf40e35855771202a,0x106aa07032bbd1b8
	.quad	0xf40e35855771202a,0x106aa07032bbd1b8
	.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
	.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
	.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
	.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
	.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
	.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
	.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
	.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
	.quad	0x90befffa23631e28,0xa4506cebde82bde9
	.quad	0x90befffa23631e28,0xa4506cebde82bde9
	.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
	.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
	.quad	0xca273eceea26619c,0xd186b8c721c0c207
	.quad	0xca273eceea26619c,0xd186b8c721c0c207
	.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
	.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
	.quad	0x113f9804bef90dae,0x1b710b35131c471b
	.quad	0x113f9804bef90dae,0x1b710b35131c471b
	.quad	0x28db77f523047d84,0x32caab7b40c72493
	.quad	0x28db77f523047d84,0x32caab7b40c72493
	.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
	.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
	.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
	.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817

	.quad	0x0001020304050607,0x08090a0b0c0d0e0f
	.quad	0x0001020304050607,0x08090a0b0c0d0e0f
	.asciz	"SHA512 block transform for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.previous
`;

export default translateAssembly(code);
