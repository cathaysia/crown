/**
 * Poly1305 for x86_64.
 *
 * TypeScript port of the scalar branch of OpenSSL
 * crypto/poly1305/asm/poly1305-x86_64.pl.
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $avx=0 (the avx/avx2/avx512 code
 * paths and their dispatch stubs are omitted).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

const ctx = '%rdi';
const inp = '%rsi';
const len = '%rdx';
const padbit = '%rcx';
const mac = inp; // *_emit arguments
const nonce = len;

const d1 = '%r8';
const d2 = '%r9';
const d3 = '%r10';
const r0 = '%r11';
const r1 = '%r12';
const s1 = '%r13';
const h0 = '%r14';
const h1 = '%rbx';
const h2 = '%rbp';

function poly1305_iteration(): void {
  // input: copy of r1 in %rax, h0-h2, r0-r1
  // output: h0-h2 *= r0-r1
  code += `	mulq	${h0}			# h0*r1
	mov	%rax,${d2}
	 mov	${r0},%rax
	mov	%rdx,${d3}

	mulq	${h0}			# h0*r0
	mov	%rax,${h0}		# future ${h0}
	 mov	${r0},%rax
	mov	%rdx,${d1}

	mulq	${h1}			# h1*r0
	add	%rax,${d2}
	 mov	${s1},%rax
	adc	%rdx,${d3}

	mulq	${h1}			# h1*s1
	 mov	${h2},${h1}			# borrow ${h1}
	add	%rax,${h0}
	adc	%rdx,${d1}

	imulq	${s1},${h1}			# h2*s1
	add	${h1},${d2}
	 mov	${d1},${h1}
	adc	$0,${d3}

	imulq	${r0},${h2}			# h2*r0
	add	${d2},${h1}
	mov	$-4,%rax		# mask value
	adc	${h2},${d3}

	and	${d3},%rax		# last reduction step
	mov	${d3},${h2}
	shr	$2,${d3}
	and	$3,${h2}
	add	${d3},%rax
	add	%rax,${h0}
	adc	$0,${h1}
	adc	$0,${h2}
`;
}

function genScalar(): void {
  code += `.text

.extern	OPENSSL_ia32cap_P

.globl	poly1305_init
.hidden	poly1305_init
.globl	poly1305_blocks
.hidden	poly1305_blocks
.globl	poly1305_emit
.hidden	poly1305_emit

.type	poly1305_init,@function,3
.align	32
poly1305_init:
.cfi_startproc
	xor	%rax,%rax
	mov	%rax,0(${ctx})		# initialize hash value
	mov	%rax,8(${ctx})
	mov	%rax,16(${ctx})

	cmp	$0,${inp}
	je	.Lno_key

	lea	poly1305_blocks(%rip),%r10
	lea	poly1305_emit(%rip),%r11
	mov	$0x0ffffffc0fffffff,%rax
	mov	$0x0ffffffc0ffffffc,%rcx
	and	0(${inp}),%rax
	and	8(${inp}),%rcx
	mov	%rax,24(${ctx})
	mov	%rcx,32(${ctx})
	mov	%r10,0(%rdx)
	mov	%r11,8(%rdx)
	mov	$1,%eax
.Lno_key:
	ret
.cfi_endproc
.size	poly1305_init,.-poly1305_init

.type	poly1305_blocks,@function,4
.align	32
poly1305_blocks:
.cfi_startproc
	endbranch
.Lblocks:
	shr	$4,${len}
	jz	.Lno_data		# too short

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
.Lblocks_body:

	mov	${len},%r15		# reassign ${len}

	mov	24(${ctx}),${r0}		# load r
	mov	32(${ctx}),${s1}

	mov	0(${ctx}),${h0}		# load hash value
	mov	8(${ctx}),${h1}
	mov	16(${ctx}),${h2}

	mov	${s1},${r1}
	shr	$2,${s1}
	mov	${r1},%rax
	add	${r1},${s1}			# s1 = r1 + (r1 >> 2)
	jmp	.Loop

.align	32
.Loop:
	add	0(${inp}),${h0}		# accumulate input
	adc	8(${inp}),${h1}
	lea	16(${inp}),${inp}
	adc	${padbit},${h2}
`;
  poly1305_iteration();
  code += `	mov	${r1},%rax
	dec	%r15			# len-=16
	jnz	.Loop

	mov	${h0},0(${ctx})		# store hash value
	mov	${h1},8(${ctx})
	mov	${h2},16(${ctx})

	mov	0(%rsp),%r15
.cfi_restore	%r15
	mov	8(%rsp),%r14
.cfi_restore	%r14
	mov	16(%rsp),%r13
.cfi_restore	%r13
	mov	24(%rsp),%r12
.cfi_restore	%r12
	mov	32(%rsp),%rbp
.cfi_restore	%rbp
	mov	40(%rsp),%rbx
.cfi_restore	%rbx
	lea	48(%rsp),%rsp
.cfi_adjust_cfa_offset	-48
.Lno_data:
.Lblocks_epilogue:
	ret
.cfi_endproc
.size	poly1305_blocks,.-poly1305_blocks

.type	poly1305_emit,@function,3
.align	32
poly1305_emit:
.cfi_startproc
	endbranch
.Lemit:
	mov	0(${ctx}),%r8	# load hash value
	mov	8(${ctx}),%r9
	mov	16(${ctx}),%r10

	mov	%r8,%rax
	add	$5,%r8		# compare to modulus
	mov	%r9,%rcx
	adc	$0,%r9
	adc	$0,%r10
	shr	$2,%r10	# did 130-bit value overflow?
	cmovnz	%r8,%rax
	cmovnz	%r9,%rcx

	add	0(${nonce}),%rax	# accumulate nonce
	adc	8(${nonce}),%rcx
	mov	%rax,0(${mac})	# write result
	mov	%rcx,8(${mac})

	ret
.cfi_endproc
.size	poly1305_emit,.-poly1305_emit
`;
}

function genXor128(): void {
  const out = '%rdi';
  const xin = '%rsi';
  const otp = '%rdx';
  const xlen = '%rcx';

  code += `.globl	xor128_encrypt_n_pad
.type	xor128_encrypt_n_pad,@abi-omnipotent
.align	16
xor128_encrypt_n_pad:
.cfi_startproc
	sub	${otp},${xin}
	sub	${otp},${out}
	mov	${xlen},%r10		# put len aside
	shr	$4,${xlen}		# len / 16
	jz	.Ltail_enc
	nop
.Loop_enc_xmm:
	movdqu	(${xin},${otp}),%xmm0
	pxor	(${otp}),%xmm0
	movdqu	%xmm0,(${out},${otp})
	movdqa	%xmm0,(${otp})
	lea	16(${otp}),${otp}
	dec	${xlen}
	jnz	.Loop_enc_xmm

	and	$15,%r10		# len % 16
	jz	.Ldone_enc

.Ltail_enc:
	mov	$16,${xlen}
	sub	%r10,${xlen}
	xor	%eax,%eax
.Loop_enc_byte:
	mov	(${xin},${otp}),%al
	xor	(${otp}),%al
	mov	%al,(${out},${otp})
	mov	%al,(${otp})
	lea	1(${otp}),${otp}
	dec	%r10
	jnz	.Loop_enc_byte

	xor	%eax,%eax
.Loop_enc_pad:
	mov	%al,(${otp})
	lea	1(${otp}),${otp}
	dec	${xlen}
	jnz	.Loop_enc_pad

.Ldone_enc:
	mov	${otp},%rax
	ret
.cfi_endproc
.size	xor128_encrypt_n_pad,.-xor128_encrypt_n_pad

.globl	xor128_decrypt_n_pad
.type	xor128_decrypt_n_pad,@abi-omnipotent
.align	16
xor128_decrypt_n_pad:
.cfi_startproc
	sub	${otp},${xin}
	sub	${otp},${out}
	mov	${xlen},%r10		# put len aside
	shr	$4,${xlen}		# len / 16
	jz	.Ltail_dec
	nop
.Loop_dec_xmm:
	movdqu	(${xin},${otp}),%xmm0
	movdqa	(${otp}),%xmm1
	pxor	%xmm0,%xmm1
	movdqu	%xmm1,(${out},${otp})
	movdqa	%xmm0,(${otp})
	lea	16(${otp}),${otp}
	dec	${xlen}
	jnz	.Loop_dec_xmm

	pxor	%xmm1,%xmm1
	and	$15,%r10		# len % 16
	jz	.Ldone_dec

.Ltail_dec:
	mov	$16,${xlen}
	sub	%r10,${xlen}
	xor	%eax,%eax
	xor	%r11,%r11
.Loop_dec_byte:
	mov	(${xin},${otp}),%r11b
	mov	(${otp}),%al
	xor	%r11b,%al
	mov	%al,(${out},${otp})
	mov	%r11b,(${otp})
	lea	1(${otp}),${otp}
	dec	%r10
	jnz	.Loop_dec_byte

	xor	%eax,%eax
.Loop_dec_pad:
	mov	%al,(${otp})
	lea	1(${otp}),${otp}
	dec	${xlen}
	jnz	.Loop_dec_pad

.Ldone_dec:
	mov	${otp},%rax
	ret
.cfi_endproc
.size	xor128_decrypt_n_pad,.-xor128_decrypt_n_pad
`;
}

genScalar();
genXor128();

code += `.asciz	"Poly1305 for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.align	16
`;

export default translateAssembly(code);
