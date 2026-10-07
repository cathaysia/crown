/**
 * Poly1305 for x86_64.
 *
 * TypeScript port of OpenSSL crypto/poly1305/asm/poly1305-x86_64.pl.
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the full x86_64 configuration of a stock OpenSSL build: with
 * GNU as >= 2.26 the perl emits the IALU, AVX, AVX2 and AVX512F+VL+BW
 * bodies (the latter with the VPMADD52 precomputed powers). `poly1305_init`
 * fills the caller supplied function table with the best available
 * blocks/emit pair and returns 1; on a CPU without AVX it returns 0 and the
 * caller keeps the IALU entry points, matching crypto/poly1305/poly1305.c.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text

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
	mov	%rax,0(%rdi)		# initialize hash value
	mov	%rax,8(%rdi)
	mov	%rax,16(%rdi)

	cmp	$0,%rsi
	je	.Lno_key

	lea	poly1305_blocks(%rip),%r10
	lea	poly1305_emit(%rip),%r11
	mov	OPENSSL_ia32cap_P+4(%rip),%r9
	lea	poly1305_blocks_avx(%rip),%rax
	lea	poly1305_emit_avx(%rip),%rcx
	bt	$28,%r9		# AVX?
	cmovc	%rax,%r10
	cmovc	%rcx,%r11
	lea	poly1305_blocks_avx2(%rip),%rax
	bt	$37,%r9		# AVX2?
	cmovc	%rax,%r10
	mov	$2149646336,%rax
	shr	$32,%r9
	and	%rax,%r9
	cmp	%rax,%r9
	je	.Linit_base2_44
	mov	$0x0ffffffc0fffffff,%rax
	mov	$0x0ffffffc0ffffffc,%rcx
	and	0(%rsi),%rax
	and	8(%rsi),%rcx
	mov	%rax,24(%rdi)
	mov	%rcx,32(%rdi)
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
	shr	$4,%rdx
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

	mov	%rdx,%r15		# reassign %rdx

	mov	24(%rdi),%r11		# load r
	mov	32(%rdi),%r13

	mov	0(%rdi),%r14		# load hash value
	mov	8(%rdi),%rbx
	mov	16(%rdi),%rbp

	mov	%r13,%r12
	shr	$2,%r13
	mov	%r12,%rax
	add	%r12,%r13			# s1 = r1 + (r1 >> 2)
	jmp	.Loop

.align	32
.Loop:
	add	0(%rsi),%r14		# accumulate input
	adc	8(%rsi),%rbx
	lea	16(%rsi),%rsi
	adc	%rcx,%rbp
	mulq	%r14			# h0*r1
	mov	%rax,%r9
	 mov	%r11,%rax
	mov	%rdx,%r10

	mulq	%r14			# h0*r0
	mov	%rax,%r14		# future %r14
	 mov	%r11,%rax
	mov	%rdx,%r8

	mulq	%rbx			# h1*r0
	add	%rax,%r9
	 mov	%r13,%rax
	adc	%rdx,%r10

	mulq	%rbx			# h1*s1
	 mov	%rbp,%rbx			# borrow %rbx
	add	%rax,%r14
	adc	%rdx,%r8

	imulq	%r13,%rbx			# h2*s1
	add	%rbx,%r9
	 mov	%r8,%rbx
	adc	$0,%r10

	imulq	%r11,%rbp			# h2*r0
	add	%r9,%rbx
	mov	$-4,%rax		# mask value
	adc	%rbp,%r10

	and	%r10,%rax		# last reduction step
	mov	%r10,%rbp
	shr	$2,%r10
	and	$3,%rbp
	add	%r10,%rax
	add	%rax,%r14
	adc	$0,%rbx
	adc	$0,%rbp
	mov	%r12,%rax
	dec	%r15			# len-=16
	jnz	.Loop

	mov	%r14,0(%rdi)		# store hash value
	mov	%rbx,8(%rdi)
	mov	%rbp,16(%rdi)

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
	mov	0(%rdi),%r8	# load hash value
	mov	8(%rdi),%r9
	mov	16(%rdi),%r10

	mov	%r8,%rax
	add	$5,%r8		# compare to modulus
	mov	%r9,%rcx
	adc	$0,%r9
	adc	$0,%r10
	shr	$2,%r10	# did 130-bit value overflow?
	cmovnz	%r8,%rax
	cmovnz	%r9,%rcx

	add	0(%rdx),%rax	# accumulate nonce
	adc	8(%rdx),%rcx
	mov	%rax,0(%rsi)	# write result
	mov	%rcx,8(%rsi)

	ret
.cfi_endproc
.size	poly1305_emit,.-poly1305_emit
.type	__poly1305_block,@abi-omnipotent
.align	32
__poly1305_block:
.cfi_startproc
	mulq	%r14			# h0*r1
	mov	%rax,%r9
	 mov	%r11,%rax
	mov	%rdx,%r10

	mulq	%r14			# h0*r0
	mov	%rax,%r14		# future %r14
	 mov	%r11,%rax
	mov	%rdx,%r8

	mulq	%rbx			# h1*r0
	add	%rax,%r9
	 mov	%r13,%rax
	adc	%rdx,%r10

	mulq	%rbx			# h1*s1
	 mov	%rbp,%rbx			# borrow %rbx
	add	%rax,%r14
	adc	%rdx,%r8

	imulq	%r13,%rbx			# h2*s1
	add	%rbx,%r9
	 mov	%r8,%rbx
	adc	$0,%r10

	imulq	%r11,%rbp			# h2*r0
	add	%r9,%rbx
	mov	$-4,%rax		# mask value
	adc	%rbp,%r10

	and	%r10,%rax		# last reduction step
	mov	%r10,%rbp
	shr	$2,%r10
	and	$3,%rbp
	add	%r10,%rax
	add	%rax,%r14
	adc	$0,%rbx
	adc	$0,%rbp
	ret
.cfi_endproc
.size	__poly1305_block,.-__poly1305_block

.type	__poly1305_init_avx,@abi-omnipotent
.align	32
__poly1305_init_avx:
.cfi_startproc
	mov	%r11,%r14
	mov	%r12,%rbx
	xor	%rbp,%rbp

	lea	48+64(%rdi),%rdi	# size optimization

	mov	%r12,%rax
	call	__poly1305_block	# r^2

	mov	$0x3ffffff,%eax	# save interleaved r^2 and r base 2^26
	mov	$0x3ffffff,%edx
	mov	%r14,%r8
	and	%r14d,%eax
	mov	%r11,%r9
	and	%r11d,%edx
	mov	%eax,-64(%rdi)
	shr	$26,%r8
	mov	%edx,-60(%rdi)
	shr	$26,%r9

	mov	$0x3ffffff,%eax
	mov	$0x3ffffff,%edx
	and	%r8d,%eax
	and	%r9d,%edx
	mov	%eax,-48(%rdi)
	lea	(%rax,%rax,4),%eax	# *5
	mov	%edx,-44(%rdi)
	lea	(%rdx,%rdx,4),%edx	# *5
	mov	%eax,-32(%rdi)
	shr	$26,%r8
	mov	%edx,-28(%rdi)
	shr	$26,%r9

	mov	%rbx,%rax
	mov	%r12,%rdx
	shl	$12,%rax
	shl	$12,%rdx
	or	%r8,%rax
	or	%r9,%rdx
	and	$0x3ffffff,%eax
	and	$0x3ffffff,%edx
	mov	%eax,-16(%rdi)
	lea	(%rax,%rax,4),%eax	# *5
	mov	%edx,-12(%rdi)
	lea	(%rdx,%rdx,4),%edx	# *5
	mov	%eax,0(%rdi)
	mov	%rbx,%r8
	mov	%edx,4(%rdi)
	mov	%r12,%r9

	mov	$0x3ffffff,%eax
	mov	$0x3ffffff,%edx
	shr	$14,%r8
	shr	$14,%r9
	and	%r8d,%eax
	and	%r9d,%edx
	mov	%eax,16(%rdi)
	lea	(%rax,%rax,4),%eax	# *5
	mov	%edx,20(%rdi)
	lea	(%rdx,%rdx,4),%edx	# *5
	mov	%eax,32(%rdi)
	shr	$26,%r8
	mov	%edx,36(%rdi)
	shr	$26,%r9

	mov	%rbp,%rax
	shl	$24,%rax
	or	%rax,%r8
	mov	%r8d,48(%rdi)
	lea	(%r8,%r8,4),%r8		# *5
	mov	%r9d,52(%rdi)
	lea	(%r9,%r9,4),%r9		# *5
	mov	%r8d,64(%rdi)
	mov	%r9d,68(%rdi)

	mov	%r12,%rax
	call	__poly1305_block	# r^3

	mov	$0x3ffffff,%eax	# save r^3 base 2^26
	mov	%r14,%r8
	and	%r14d,%eax
	shr	$26,%r8
	mov	%eax,-52(%rdi)

	mov	$0x3ffffff,%edx
	and	%r8d,%edx
	mov	%edx,-36(%rdi)
	lea	(%rdx,%rdx,4),%edx	# *5
	shr	$26,%r8
	mov	%edx,-20(%rdi)

	mov	%rbx,%rax
	shl	$12,%rax
	or	%r8,%rax
	and	$0x3ffffff,%eax
	mov	%eax,-4(%rdi)
	lea	(%rax,%rax,4),%eax	# *5
	mov	%rbx,%r8
	mov	%eax,12(%rdi)

	mov	$0x3ffffff,%edx
	shr	$14,%r8
	and	%r8d,%edx
	mov	%edx,28(%rdi)
	lea	(%rdx,%rdx,4),%edx	# *5
	shr	$26,%r8
	mov	%edx,44(%rdi)

	mov	%rbp,%rax
	shl	$24,%rax
	or	%rax,%r8
	mov	%r8d,60(%rdi)
	lea	(%r8,%r8,4),%r8		# *5
	mov	%r8d,76(%rdi)

	mov	%r12,%rax
	call	__poly1305_block	# r^4

	mov	$0x3ffffff,%eax	# save r^4 base 2^26
	mov	%r14,%r8
	and	%r14d,%eax
	shr	$26,%r8
	mov	%eax,-56(%rdi)

	mov	$0x3ffffff,%edx
	and	%r8d,%edx
	mov	%edx,-40(%rdi)
	lea	(%rdx,%rdx,4),%edx	# *5
	shr	$26,%r8
	mov	%edx,-24(%rdi)

	mov	%rbx,%rax
	shl	$12,%rax
	or	%r8,%rax
	and	$0x3ffffff,%eax
	mov	%eax,-8(%rdi)
	lea	(%rax,%rax,4),%eax	# *5
	mov	%rbx,%r8
	mov	%eax,8(%rdi)

	mov	$0x3ffffff,%edx
	shr	$14,%r8
	and	%r8d,%edx
	mov	%edx,24(%rdi)
	lea	(%rdx,%rdx,4),%edx	# *5
	shr	$26,%r8
	mov	%edx,40(%rdi)

	mov	%rbp,%rax
	shl	$24,%rax
	or	%rax,%r8
	mov	%r8d,56(%rdi)
	lea	(%r8,%r8,4),%r8		# *5
	mov	%r8d,72(%rdi)

	lea	-48-64(%rdi),%rdi	# size [de-]optimization
	ret
.cfi_endproc
.size	__poly1305_init_avx,.-__poly1305_init_avx

.type	poly1305_blocks_avx,@function,4
.align	32
poly1305_blocks_avx:
.cfi_startproc
	endbranch
	mov	20(%rdi),%r8d		# is_base2_26
	cmp	$128,%rdx
	jae	.Lblocks_avx
	test	%r8d,%r8d
	jz	.Lblocks

.Lblocks_avx:
	and	$-16,%rdx
	jz	.Lno_data_avx

	vzeroupper

	test	%r8d,%r8d
	jz	.Lbase2_64_avx

	test	$31,%rdx
	jz	.Leven_avx

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
.Lblocks_avx_body:

	mov	%rdx,%r15		# reassign %rdx

	mov	0(%rdi),%r8		# load hash value
	mov	8(%rdi),%r9
	mov	16(%rdi),%ebp

	mov	24(%rdi),%r11		# load r
	mov	32(%rdi),%r13

	################################# base 2^26 -> base 2^64
	mov	%r8d,%r14d
	and	$-2147483648,%r8
	mov	%r9,%r12			# borrow %r12
	mov	%r9d,%ebx
	and	$-2147483648,%r9

	shr	$6,%r8
	shl	$52,%r12
	add	%r8,%r14
	shr	$12,%rbx
	shr	$18,%r9
	add	%r12,%r14
	adc	%r9,%rbx

	mov	%rbp,%r8
	shl	$40,%r8
	shr	$24,%rbp
	add	%r8,%rbx
	adc	$0,%rbp			# can be partially reduced...

	mov	$-4,%r9		# ... so reduce
	mov	%rbp,%r8
	and	%rbp,%r9
	shr	$2,%r8
	and	$3,%rbp
	add	%r9,%r8			# =*5
	add	%r8,%r14
	adc	$0,%rbx
	adc	$0,%rbp

	mov	%r13,%r12
	mov	%r13,%rax
	shr	$2,%r13
	add	%r12,%r13			# s1 = r1 + (r1 >> 2)

	add	0(%rsi),%r14		# accumulate input
	adc	8(%rsi),%rbx
	lea	16(%rsi),%rsi
	adc	%rcx,%rbp

	call	__poly1305_block

	test	%rcx,%rcx		# if %rcx is zero,
	jz	.Lstore_base2_64_avx	# store hash in base 2^64 format

	################################# base 2^64 -> base 2^26
	mov	%r14,%rax
	mov	%r14,%rdx
	shr	$52,%r14
	mov	%rbx,%r11
	mov	%rbx,%r12
	shr	$26,%rdx
	and	$0x3ffffff,%rax	# h[0]
	shl	$12,%r11
	and	$0x3ffffff,%rdx	# h[1]
	shr	$14,%rbx
	or	%r11,%r14
	shl	$24,%rbp
	and	$0x3ffffff,%r14		# h[2]
	shr	$40,%r12
	and	$0x3ffffff,%rbx		# h[3]
	or	%r12,%rbp			# h[4]

	sub	$16,%r15
	jz	.Lstore_base2_26_avx

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4
	jmp	.Lproceed_avx

.align	32
.Lstore_base2_64_avx:
	mov	%r14,0(%rdi)
	mov	%rbx,8(%rdi)
	mov	%rbp,16(%rdi)		# note that is_base2_26 is zeroed
	jmp	.Ldone_avx

.align	16
.Lstore_base2_26_avx:
	mov	%eax,0(%rdi)		# store hash value base 2^26
	mov	%edx,4(%rdi)
	mov	%r14d,8(%rdi)
	mov	%ebx,12(%rdi)
	mov	%ebp,16(%rdi)
.align	16
.Ldone_avx:
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
.Lno_data_avx:
.Lblocks_avx_epilogue:
	ret
.cfi_endproc

.align	32
.Lbase2_64_avx:
.cfi_startproc
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
.Lbase2_64_avx_body:

	mov	%rdx,%r15		# reassign %rdx

	mov	24(%rdi),%r11		# load r
	mov	32(%rdi),%r13

	mov	0(%rdi),%r14		# load hash value
	mov	8(%rdi),%rbx
	mov	16(%rdi),%ebp

	mov	%r13,%r12
	mov	%r13,%rax
	shr	$2,%r13
	add	%r12,%r13			# s1 = r1 + (r1 >> 2)

	test	$31,%rdx
	jz	.Linit_avx

	add	0(%rsi),%r14		# accumulate input
	adc	8(%rsi),%rbx
	lea	16(%rsi),%rsi
	adc	%rcx,%rbp
	sub	$16,%r15

	call	__poly1305_block

.Linit_avx:
	################################# base 2^64 -> base 2^26
	mov	%r14,%rax
	mov	%r14,%rdx
	shr	$52,%r14
	mov	%rbx,%r8
	mov	%rbx,%r9
	shr	$26,%rdx
	and	$0x3ffffff,%rax	# h[0]
	shl	$12,%r8
	and	$0x3ffffff,%rdx	# h[1]
	shr	$14,%rbx
	or	%r8,%r14
	shl	$24,%rbp
	and	$0x3ffffff,%r14		# h[2]
	shr	$40,%r9
	and	$0x3ffffff,%rbx		# h[3]
	or	%r9,%rbp			# h[4]

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4
	movl	$1,20(%rdi)		# set is_base2_26

	call	__poly1305_init_avx

.Lproceed_avx:
	mov	%r15,%rdx

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
	lea	48(%rsp),%rax
	lea	48(%rsp),%rsp
.cfi_adjust_cfa_offset	-48
.Lbase2_64_avx_epilogue:
	jmp	.Ldo_avx
.cfi_endproc

.align	32
.Leven_avx:
.cfi_startproc
	vmovd		4*0(%rdi),%xmm0		# load hash value
	vmovd		4*1(%rdi),%xmm1
	vmovd		4*2(%rdi),%xmm2
	vmovd		4*3(%rdi),%xmm3
	vmovd		4*4(%rdi),%xmm4

.Ldo_avx:
	lea		-0x58(%rsp),%r11
.cfi_def_cfa		%r11,0x60
	sub		$0x178,%rsp
	sub		$64,%rdx
	lea		-32(%rsi),%rax
	cmovc		%rax,%rsi

	vmovdqu		48(%rdi),%xmm14	# preload r0^2
	lea		112(%rdi),%rdi	# size optimization
	lea		.Lconst(%rip),%rcx

	################################################################
	# load input
	vmovdqu		16*2(%rsi),%xmm5
	vmovdqu		16*3(%rsi),%xmm6
	vmovdqa		64(%rcx),%xmm15		# .Lmask26

	vpsrldq		$6,%xmm5,%xmm7		# splat input
	vpsrldq		$6,%xmm6,%xmm8
	vpunpckhqdq	%xmm6,%xmm5,%xmm9		# 4
	vpunpcklqdq	%xmm6,%xmm5,%xmm5		# 0:1
	vpunpcklqdq	%xmm8,%xmm7,%xmm8		# 2:3

	vpsrlq		$40,%xmm9,%xmm9		# 4
	vpsrlq		$26,%xmm5,%xmm6
	vpand		%xmm15,%xmm5,%xmm5		# 0
	vpsrlq		$4,%xmm8,%xmm7
	vpand		%xmm15,%xmm6,%xmm6		# 1
	vpsrlq		$30,%xmm8,%xmm8
	vpand		%xmm15,%xmm7,%xmm7		# 2
	vpand		%xmm15,%xmm8,%xmm8		# 3
	vpor		32(%rcx),%xmm9,%xmm9	# padbit, yes, always

	jbe		.Lskip_loop_avx

	# expand and copy pre-calculated table to stack
	vmovdqu		-48(%rdi),%xmm11
	vmovdqu		-32(%rdi),%xmm12
	vpshufd		$0xEE,%xmm14,%xmm13		# 34xx -> 3434
	vpshufd		$0x44,%xmm14,%xmm10		# xx12 -> 1212
	vmovdqa		%xmm13,-0x90(%r11)
	vmovdqa		%xmm10,0x00(%rsp)
	vpshufd		$0xEE,%xmm11,%xmm14
	vmovdqu		-16(%rdi),%xmm10
	vpshufd		$0x44,%xmm11,%xmm11
	vmovdqa		%xmm14,-0x80(%r11)
	vmovdqa		%xmm11,0x10(%rsp)
	vpshufd		$0xEE,%xmm12,%xmm13
	vmovdqu		0(%rdi),%xmm11
	vpshufd		$0x44,%xmm12,%xmm12
	vmovdqa		%xmm13,-0x70(%r11)
	vmovdqa		%xmm12,0x20(%rsp)
	vpshufd		$0xEE,%xmm10,%xmm14
	vmovdqu		16(%rdi),%xmm12
	vpshufd		$0x44,%xmm10,%xmm10
	vmovdqa		%xmm14,-0x60(%r11)
	vmovdqa		%xmm10,0x30(%rsp)
	vpshufd		$0xEE,%xmm11,%xmm13
	vmovdqu		32(%rdi),%xmm10
	vpshufd		$0x44,%xmm11,%xmm11
	vmovdqa		%xmm13,-0x50(%r11)
	vmovdqa		%xmm11,0x40(%rsp)
	vpshufd		$0xEE,%xmm12,%xmm14
	vmovdqu		48(%rdi),%xmm11
	vpshufd		$0x44,%xmm12,%xmm12
	vmovdqa		%xmm14,-0x40(%r11)
	vmovdqa		%xmm12,0x50(%rsp)
	vpshufd		$0xEE,%xmm10,%xmm13
	vmovdqu		64(%rdi),%xmm12
	vpshufd		$0x44,%xmm10,%xmm10
	vmovdqa		%xmm13,-0x30(%r11)
	vmovdqa		%xmm10,0x60(%rsp)
	vpshufd		$0xEE,%xmm11,%xmm14
	vpshufd		$0x44,%xmm11,%xmm11
	vmovdqa		%xmm14,-0x20(%r11)
	vmovdqa		%xmm11,0x70(%rsp)
	vpshufd		$0xEE,%xmm12,%xmm13
	 vmovdqa	0x00(%rsp),%xmm14		# preload r0^2
	vpshufd		$0x44,%xmm12,%xmm12
	vmovdqa		%xmm13,-0x10(%r11)
	vmovdqa		%xmm12,0x80(%rsp)

	jmp		.Loop_avx

.align	32
.Loop_avx:
	################################################################
	# ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2
	# ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^3+inp[7]*r
	#   ___________________/
	# ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2+inp[8])*r^2
	# ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^4+inp[7]*r^2+inp[9])*r
	#   ___________________/ ____________________/
	#
	# Note that we start with inp[2:3]*r^2. This is because it
	# doesn't depend on reduction in previous iteration.
	################################################################
	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4
	#
	# though note that  and  are "reversed" in this section,
	# and %xmm14 is preloaded with r0^2...

	vpmuludq	%xmm5,%xmm14,%xmm10		# d0 = h0*r0
	vpmuludq	%xmm6,%xmm14,%xmm11		# d1 = h1*r0
	  vmovdqa	%xmm2,0x20(%r11)				# offload hash
	vpmuludq	%xmm7,%xmm14,%xmm12		# d3 = h2*r0
	 vmovdqa	0x10(%rsp),%xmm2		# r1^2
	vpmuludq	%xmm8,%xmm14,%xmm13		# d3 = h3*r0
	vpmuludq	%xmm9,%xmm14,%xmm14		# d4 = h4*r0

	  vmovdqa	%xmm0,0x00(%r11)				#
	vpmuludq	0x20(%rsp),%xmm9,%xmm0	# h4*s1
	  vmovdqa	%xmm1,0x10(%r11)				#
	vpmuludq	%xmm8,%xmm2,%xmm1		# h3*r1
	vpaddq		%xmm0,%xmm10,%xmm10		# d0 += h4*s1
	vpaddq		%xmm1,%xmm14,%xmm14		# d4 += h3*r1
	  vmovdqa	%xmm3,0x30(%r11)				#
	vpmuludq	%xmm7,%xmm2,%xmm0		# h2*r1
	vpmuludq	%xmm6,%xmm2,%xmm1		# h1*r1
	vpaddq		%xmm0,%xmm13,%xmm13		# d3 += h2*r1
	 vmovdqa	0x30(%rsp),%xmm3		# r2^2
	vpaddq		%xmm1,%xmm12,%xmm12		# d2 += h1*r1
	  vmovdqa	%xmm4,0x40(%r11)				#
	vpmuludq	%xmm5,%xmm2,%xmm2		# h0*r1
	 vpmuludq	%xmm7,%xmm3,%xmm0		# h2*r2
	vpaddq		%xmm2,%xmm11,%xmm11		# d1 += h0*r1

	 vmovdqa	0x40(%rsp),%xmm4		# s2^2
	vpaddq		%xmm0,%xmm14,%xmm14		# d4 += h2*r2
	vpmuludq	%xmm6,%xmm3,%xmm1		# h1*r2
	vpmuludq	%xmm5,%xmm3,%xmm3		# h0*r2
	vpaddq		%xmm1,%xmm13,%xmm13		# d3 += h1*r2
	 vmovdqa	0x50(%rsp),%xmm2		# r3^2
	vpaddq		%xmm3,%xmm12,%xmm12		# d2 += h0*r2
	vpmuludq	%xmm9,%xmm4,%xmm0		# h4*s2
	vpmuludq	%xmm8,%xmm4,%xmm4		# h3*s2
	vpaddq		%xmm0,%xmm11,%xmm11		# d1 += h4*s2
	 vmovdqa	0x60(%rsp),%xmm3		# s3^2
	vpaddq		%xmm4,%xmm10,%xmm10		# d0 += h3*s2

	 vmovdqa	0x80(%rsp),%xmm4		# s4^2
	vpmuludq	%xmm6,%xmm2,%xmm1		# h1*r3
	vpmuludq	%xmm5,%xmm2,%xmm2		# h0*r3
	vpaddq		%xmm1,%xmm14,%xmm14		# d4 += h1*r3
	vpaddq		%xmm2,%xmm13,%xmm13		# d3 += h0*r3
	vpmuludq	%xmm9,%xmm3,%xmm0		# h4*s3
	vpmuludq	%xmm8,%xmm3,%xmm1		# h3*s3
	vpaddq		%xmm0,%xmm12,%xmm12		# d2 += h4*s3
	 vmovdqu	16*0(%rsi),%xmm0				# load input
	vpaddq		%xmm1,%xmm11,%xmm11		# d1 += h3*s3
	vpmuludq	%xmm7,%xmm3,%xmm3		# h2*s3
	 vpmuludq	%xmm7,%xmm4,%xmm7		# h2*s4
	vpaddq		%xmm3,%xmm10,%xmm10		# d0 += h2*s3

	 vmovdqu	16*1(%rsi),%xmm1				#
	vpaddq		%xmm7,%xmm11,%xmm11		# d1 += h2*s4
	vpmuludq	%xmm8,%xmm4,%xmm8		# h3*s4
	vpmuludq	%xmm9,%xmm4,%xmm9		# h4*s4
	 vpsrldq	$6,%xmm0,%xmm2				# splat input
	vpaddq		%xmm8,%xmm12,%xmm12		# d2 += h3*s4
	vpaddq		%xmm9,%xmm13,%xmm13		# d3 += h4*s4
	 vpsrldq	$6,%xmm1,%xmm3				#
	vpmuludq	0x70(%rsp),%xmm5,%xmm9	# h0*r4
	vpmuludq	%xmm6,%xmm4,%xmm5		# h1*s4
	 vpunpckhqdq	%xmm1,%xmm0,%xmm4		# 4
	vpaddq		%xmm9,%xmm14,%xmm14		# d4 += h0*r4
	 vmovdqa	-0x90(%r11),%xmm9		# r0^4
	vpaddq		%xmm5,%xmm10,%xmm10		# d0 += h1*s4

	vpunpcklqdq	%xmm1,%xmm0,%xmm0		# 0:1
	vpunpcklqdq	%xmm3,%xmm2,%xmm3		# 2:3

	#vpsrlq		$40,%xmm4,%xmm4		# 4
	vpsrldq		$5,%xmm4,%xmm4	# 4
	vpsrlq		$26,%xmm0,%xmm1
	vpand		%xmm15,%xmm0,%xmm0		# 0
	vpsrlq		$4,%xmm3,%xmm2
	vpand		%xmm15,%xmm1,%xmm1		# 1
	vpand		0(%rcx),%xmm4,%xmm4		# .Lmask24
	vpsrlq		$30,%xmm3,%xmm3
	vpand		%xmm15,%xmm2,%xmm2		# 2
	vpand		%xmm15,%xmm3,%xmm3		# 3
	vpor		32(%rcx),%xmm4,%xmm4	# padbit, yes, always

	vpaddq		0x00(%r11),%xmm0,%xmm0	# add hash value
	vpaddq		0x10(%r11),%xmm1,%xmm1
	vpaddq		0x20(%r11),%xmm2,%xmm2
	vpaddq		0x30(%r11),%xmm3,%xmm3
	vpaddq		0x40(%r11),%xmm4,%xmm4

	lea		16*2(%rsi),%rax
	lea		16*4(%rsi),%rsi
	sub		$64,%rdx
	cmovc		%rax,%rsi

	################################################################
	# Now we accumulate (inp[0:1]+hash)*r^4
	################################################################
	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4

	vpmuludq	%xmm0,%xmm9,%xmm5		# h0*r0
	vpmuludq	%xmm1,%xmm9,%xmm6		# h1*r0
	vpaddq		%xmm5,%xmm10,%xmm10
	vpaddq		%xmm6,%xmm11,%xmm11
	 vmovdqa	-0x80(%r11),%xmm7		# r1^4
	vpmuludq	%xmm2,%xmm9,%xmm5		# h2*r0
	vpmuludq	%xmm3,%xmm9,%xmm6		# h3*r0
	vpaddq		%xmm5,%xmm12,%xmm12
	vpaddq		%xmm6,%xmm13,%xmm13
	vpmuludq	%xmm4,%xmm9,%xmm9		# h4*r0
	 vpmuludq	-0x70(%r11),%xmm4,%xmm5	# h4*s1
	vpaddq		%xmm9,%xmm14,%xmm14

	vpaddq		%xmm5,%xmm10,%xmm10		# d0 += h4*s1
	vpmuludq	%xmm2,%xmm7,%xmm6		# h2*r1
	vpmuludq	%xmm3,%xmm7,%xmm5		# h3*r1
	vpaddq		%xmm6,%xmm13,%xmm13		# d3 += h2*r1
	 vmovdqa	-0x60(%r11),%xmm8		# r2^4
	vpaddq		%xmm5,%xmm14,%xmm14		# d4 += h3*r1
	vpmuludq	%xmm1,%xmm7,%xmm6		# h1*r1
	vpmuludq	%xmm0,%xmm7,%xmm7		# h0*r1
	vpaddq		%xmm6,%xmm12,%xmm12		# d2 += h1*r1
	vpaddq		%xmm7,%xmm11,%xmm11		# d1 += h0*r1

	 vmovdqa	-0x50(%r11),%xmm9		# s2^4
	vpmuludq	%xmm2,%xmm8,%xmm5		# h2*r2
	vpmuludq	%xmm1,%xmm8,%xmm6		# h1*r2
	vpaddq		%xmm5,%xmm14,%xmm14		# d4 += h2*r2
	vpaddq		%xmm6,%xmm13,%xmm13		# d3 += h1*r2
	 vmovdqa	-0x40(%r11),%xmm7		# r3^4
	vpmuludq	%xmm0,%xmm8,%xmm8		# h0*r2
	vpmuludq	%xmm4,%xmm9,%xmm5		# h4*s2
	vpaddq		%xmm8,%xmm12,%xmm12		# d2 += h0*r2
	vpaddq		%xmm5,%xmm11,%xmm11		# d1 += h4*s2
	 vmovdqa	-0x30(%r11),%xmm8		# s3^4
	vpmuludq	%xmm3,%xmm9,%xmm9		# h3*s2
	 vpmuludq	%xmm1,%xmm7,%xmm6		# h1*r3
	vpaddq		%xmm9,%xmm10,%xmm10		# d0 += h3*s2

	 vmovdqa	-0x10(%r11),%xmm9		# s4^4
	vpaddq		%xmm6,%xmm14,%xmm14		# d4 += h1*r3
	vpmuludq	%xmm0,%xmm7,%xmm7		# h0*r3
	vpmuludq	%xmm4,%xmm8,%xmm5		# h4*s3
	vpaddq		%xmm7,%xmm13,%xmm13		# d3 += h0*r3
	vpaddq		%xmm5,%xmm12,%xmm12		# d2 += h4*s3
	 vmovdqu	16*2(%rsi),%xmm5				# load input
	vpmuludq	%xmm3,%xmm8,%xmm7		# h3*s3
	vpmuludq	%xmm2,%xmm8,%xmm8		# h2*s3
	vpaddq		%xmm7,%xmm11,%xmm11		# d1 += h3*s3
	 vmovdqu	16*3(%rsi),%xmm6				#
	vpaddq		%xmm8,%xmm10,%xmm10		# d0 += h2*s3

	vpmuludq	%xmm2,%xmm9,%xmm2		# h2*s4
	vpmuludq	%xmm3,%xmm9,%xmm3		# h3*s4
	 vpsrldq	$6,%xmm5,%xmm7				# splat input
	vpaddq		%xmm2,%xmm11,%xmm11		# d1 += h2*s4
	vpmuludq	%xmm4,%xmm9,%xmm4		# h4*s4
	 vpsrldq	$6,%xmm6,%xmm8				#
	vpaddq		%xmm3,%xmm12,%xmm2		# h2 = d2 + h3*s4
	vpaddq		%xmm4,%xmm13,%xmm3		# h3 = d3 + h4*s4
	vpmuludq	-0x20(%r11),%xmm0,%xmm4	# h0*r4
	vpmuludq	%xmm1,%xmm9,%xmm0
	 vpunpckhqdq	%xmm6,%xmm5,%xmm9		# 4
	vpaddq		%xmm4,%xmm14,%xmm4		# h4 = d4 + h0*r4
	vpaddq		%xmm0,%xmm10,%xmm0		# h0 = d0 + h1*s4

	vpunpcklqdq	%xmm6,%xmm5,%xmm5		# 0:1
	vpunpcklqdq	%xmm8,%xmm7,%xmm8		# 2:3

	#vpsrlq		$40,%xmm9,%xmm9		# 4
	vpsrldq		$5,%xmm9,%xmm9	# 4
	vpsrlq		$26,%xmm5,%xmm6
	 vmovdqa	0x00(%rsp),%xmm14		# preload r0^2
	vpand		%xmm15,%xmm5,%xmm5		# 0
	vpsrlq		$4,%xmm8,%xmm7
	vpand		%xmm15,%xmm6,%xmm6		# 1
	vpand		0(%rcx),%xmm9,%xmm9		# .Lmask24
	vpsrlq		$30,%xmm8,%xmm8
	vpand		%xmm15,%xmm7,%xmm7		# 2
	vpand		%xmm15,%xmm8,%xmm8		# 3
	vpor		32(%rcx),%xmm9,%xmm9	# padbit, yes, always

	################################################################
	# lazy reduction as discussed in "NEON crypto" by D.J. Bernstein
	# and P. Schwabe

	vpsrlq		$26,%xmm3,%xmm13
	vpand		%xmm15,%xmm3,%xmm3
	vpaddq		%xmm13,%xmm4,%xmm4		# h3 -> h4

	vpsrlq		$26,%xmm0,%xmm10
	vpand		%xmm15,%xmm0,%xmm0
	vpaddq		%xmm10,%xmm11,%xmm1		# h0 -> h1

	vpsrlq		$26,%xmm4,%xmm10
	vpand		%xmm15,%xmm4,%xmm4

	vpsrlq		$26,%xmm1,%xmm11
	vpand		%xmm15,%xmm1,%xmm1
	vpaddq		%xmm11,%xmm2,%xmm2		# h1 -> h2

	vpaddq		%xmm10,%xmm0,%xmm0
	vpsllq		$2,%xmm10,%xmm10
	vpaddq		%xmm10,%xmm0,%xmm0		# h4 -> h0

	vpsrlq		$26,%xmm2,%xmm12
	vpand		%xmm15,%xmm2,%xmm2
	vpaddq		%xmm12,%xmm3,%xmm3		# h2 -> h3

	vpsrlq		$26,%xmm0,%xmm10
	vpand		%xmm15,%xmm0,%xmm0
	vpaddq		%xmm10,%xmm1,%xmm1		# h0 -> h1

	vpsrlq		$26,%xmm3,%xmm13
	vpand		%xmm15,%xmm3,%xmm3
	vpaddq		%xmm13,%xmm4,%xmm4		# h3 -> h4

	ja		.Loop_avx

.Lskip_loop_avx:
	################################################################
	# multiply (inp[0:1]+hash) or inp[2:3] by r^2:r^1

	vpshufd		$0x10,%xmm14,%xmm14		# r0^n, xx12 -> x1x2
	add		$32,%rdx
	jnz		.Long_tail_avx

	vpaddq		%xmm2,%xmm7,%xmm7
	vpaddq		%xmm0,%xmm5,%xmm5
	vpaddq		%xmm1,%xmm6,%xmm6
	vpaddq		%xmm3,%xmm8,%xmm8
	vpaddq		%xmm4,%xmm9,%xmm9

.Long_tail_avx:
	vmovdqa		%xmm2,0x20(%r11)
	vmovdqa		%xmm0,0x00(%r11)
	vmovdqa		%xmm1,0x10(%r11)
	vmovdqa		%xmm3,0x30(%r11)
	vmovdqa		%xmm4,0x40(%r11)

	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4

	vpmuludq	%xmm7,%xmm14,%xmm12		# d2 = h2*r0
	vpmuludq	%xmm5,%xmm14,%xmm10		# d0 = h0*r0
	 vpshufd	$0x10,-48(%rdi),%xmm2		# r1^n
	vpmuludq	%xmm6,%xmm14,%xmm11		# d1 = h1*r0
	vpmuludq	%xmm8,%xmm14,%xmm13		# d3 = h3*r0
	vpmuludq	%xmm9,%xmm14,%xmm14		# d4 = h4*r0

	vpmuludq	%xmm8,%xmm2,%xmm0		# h3*r1
	vpaddq		%xmm0,%xmm14,%xmm14		# d4 += h3*r1
	 vpshufd	$0x10,-32(%rdi),%xmm3		# s1^n
	vpmuludq	%xmm7,%xmm2,%xmm1		# h2*r1
	vpaddq		%xmm1,%xmm13,%xmm13		# d3 += h2*r1
	 vpshufd	$0x10,-16(%rdi),%xmm4		# r2^n
	vpmuludq	%xmm6,%xmm2,%xmm0		# h1*r1
	vpaddq		%xmm0,%xmm12,%xmm12		# d2 += h1*r1
	vpmuludq	%xmm5,%xmm2,%xmm2		# h0*r1
	vpaddq		%xmm2,%xmm11,%xmm11		# d1 += h0*r1
	vpmuludq	%xmm9,%xmm3,%xmm3		# h4*s1
	vpaddq		%xmm3,%xmm10,%xmm10		# d0 += h4*s1

	 vpshufd	$0x10,0(%rdi),%xmm2		# s2^n
	vpmuludq	%xmm7,%xmm4,%xmm1		# h2*r2
	vpaddq		%xmm1,%xmm14,%xmm14		# d4 += h2*r2
	vpmuludq	%xmm6,%xmm4,%xmm0		# h1*r2
	vpaddq		%xmm0,%xmm13,%xmm13		# d3 += h1*r2
	 vpshufd	$0x10,16(%rdi),%xmm3		# r3^n
	vpmuludq	%xmm5,%xmm4,%xmm4		# h0*r2
	vpaddq		%xmm4,%xmm12,%xmm12		# d2 += h0*r2
	vpmuludq	%xmm9,%xmm2,%xmm1		# h4*s2
	vpaddq		%xmm1,%xmm11,%xmm11		# d1 += h4*s2
	 vpshufd	$0x10,32(%rdi),%xmm4		# s3^n
	vpmuludq	%xmm8,%xmm2,%xmm2		# h3*s2
	vpaddq		%xmm2,%xmm10,%xmm10		# d0 += h3*s2

	vpmuludq	%xmm6,%xmm3,%xmm0		# h1*r3
	vpaddq		%xmm0,%xmm14,%xmm14		# d4 += h1*r3
	vpmuludq	%xmm5,%xmm3,%xmm3		# h0*r3
	vpaddq		%xmm3,%xmm13,%xmm13		# d3 += h0*r3
	 vpshufd	$0x10,48(%rdi),%xmm2		# r4^n
	vpmuludq	%xmm9,%xmm4,%xmm1		# h4*s3
	vpaddq		%xmm1,%xmm12,%xmm12		# d2 += h4*s3
	 vpshufd	$0x10,64(%rdi),%xmm3		# s4^n
	vpmuludq	%xmm8,%xmm4,%xmm0		# h3*s3
	vpaddq		%xmm0,%xmm11,%xmm11		# d1 += h3*s3
	vpmuludq	%xmm7,%xmm4,%xmm4		# h2*s3
	vpaddq		%xmm4,%xmm10,%xmm10		# d0 += h2*s3

	vpmuludq	%xmm5,%xmm2,%xmm2		# h0*r4
	vpaddq		%xmm2,%xmm14,%xmm14		# h4 = d4 + h0*r4
	vpmuludq	%xmm9,%xmm3,%xmm1		# h4*s4
	vpaddq		%xmm1,%xmm13,%xmm13		# h3 = d3 + h4*s4
	vpmuludq	%xmm8,%xmm3,%xmm0		# h3*s4
	vpaddq		%xmm0,%xmm12,%xmm12		# h2 = d2 + h3*s4
	vpmuludq	%xmm7,%xmm3,%xmm1		# h2*s4
	vpaddq		%xmm1,%xmm11,%xmm11		# h1 = d1 + h2*s4
	vpmuludq	%xmm6,%xmm3,%xmm3		# h1*s4
	vpaddq		%xmm3,%xmm10,%xmm10		# h0 = d0 + h1*s4

	jz		.Lshort_tail_avx

	vmovdqu		16*0(%rsi),%xmm0		# load input
	vmovdqu		16*1(%rsi),%xmm1

	vpsrldq		$6,%xmm0,%xmm2		# splat input
	vpsrldq		$6,%xmm1,%xmm3
	vpunpckhqdq	%xmm1,%xmm0,%xmm4		# 4
	vpunpcklqdq	%xmm1,%xmm0,%xmm0		# 0:1
	vpunpcklqdq	%xmm3,%xmm2,%xmm3		# 2:3

	vpsrlq		$40,%xmm4,%xmm4		# 4
	vpsrlq		$26,%xmm0,%xmm1
	vpand		%xmm15,%xmm0,%xmm0		# 0
	vpsrlq		$4,%xmm3,%xmm2
	vpand		%xmm15,%xmm1,%xmm1		# 1
	vpsrlq		$30,%xmm3,%xmm3
	vpand		%xmm15,%xmm2,%xmm2		# 2
	vpand		%xmm15,%xmm3,%xmm3		# 3
	vpor		32(%rcx),%xmm4,%xmm4	# padbit, yes, always

	vpshufd		$0x32,-64(%rdi),%xmm9	# r0^n, 34xx -> x3x4
	vpaddq		0x00(%r11),%xmm0,%xmm0
	vpaddq		0x10(%r11),%xmm1,%xmm1
	vpaddq		0x20(%r11),%xmm2,%xmm2
	vpaddq		0x30(%r11),%xmm3,%xmm3
	vpaddq		0x40(%r11),%xmm4,%xmm4

	################################################################
	# multiply (inp[0:1]+hash) by r^4:r^3 and accumulate

	vpmuludq	%xmm0,%xmm9,%xmm5		# h0*r0
	vpaddq		%xmm5,%xmm10,%xmm10		# d0 += h0*r0
	vpmuludq	%xmm1,%xmm9,%xmm6		# h1*r0
	vpaddq		%xmm6,%xmm11,%xmm11		# d1 += h1*r0
	vpmuludq	%xmm2,%xmm9,%xmm5		# h2*r0
	vpaddq		%xmm5,%xmm12,%xmm12		# d2 += h2*r0
	 vpshufd	$0x32,-48(%rdi),%xmm7		# r1^n
	vpmuludq	%xmm3,%xmm9,%xmm6		# h3*r0
	vpaddq		%xmm6,%xmm13,%xmm13		# d3 += h3*r0
	vpmuludq	%xmm4,%xmm9,%xmm9		# h4*r0
	vpaddq		%xmm9,%xmm14,%xmm14		# d4 += h4*r0

	vpmuludq	%xmm3,%xmm7,%xmm5		# h3*r1
	vpaddq		%xmm5,%xmm14,%xmm14		# d4 += h3*r1
	 vpshufd	$0x32,-32(%rdi),%xmm8		# s1
	vpmuludq	%xmm2,%xmm7,%xmm6		# h2*r1
	vpaddq		%xmm6,%xmm13,%xmm13		# d3 += h2*r1
	 vpshufd	$0x32,-16(%rdi),%xmm9		# r2
	vpmuludq	%xmm1,%xmm7,%xmm5		# h1*r1
	vpaddq		%xmm5,%xmm12,%xmm12		# d2 += h1*r1
	vpmuludq	%xmm0,%xmm7,%xmm7		# h0*r1
	vpaddq		%xmm7,%xmm11,%xmm11		# d1 += h0*r1
	vpmuludq	%xmm4,%xmm8,%xmm8		# h4*s1
	vpaddq		%xmm8,%xmm10,%xmm10		# d0 += h4*s1

	 vpshufd	$0x32,0(%rdi),%xmm7		# s2
	vpmuludq	%xmm2,%xmm9,%xmm6		# h2*r2
	vpaddq		%xmm6,%xmm14,%xmm14		# d4 += h2*r2
	vpmuludq	%xmm1,%xmm9,%xmm5		# h1*r2
	vpaddq		%xmm5,%xmm13,%xmm13		# d3 += h1*r2
	 vpshufd	$0x32,16(%rdi),%xmm8		# r3
	vpmuludq	%xmm0,%xmm9,%xmm9		# h0*r2
	vpaddq		%xmm9,%xmm12,%xmm12		# d2 += h0*r2
	vpmuludq	%xmm4,%xmm7,%xmm6		# h4*s2
	vpaddq		%xmm6,%xmm11,%xmm11		# d1 += h4*s2
	 vpshufd	$0x32,32(%rdi),%xmm9		# s3
	vpmuludq	%xmm3,%xmm7,%xmm7		# h3*s2
	vpaddq		%xmm7,%xmm10,%xmm10		# d0 += h3*s2

	vpmuludq	%xmm1,%xmm8,%xmm5		# h1*r3
	vpaddq		%xmm5,%xmm14,%xmm14		# d4 += h1*r3
	vpmuludq	%xmm0,%xmm8,%xmm8		# h0*r3
	vpaddq		%xmm8,%xmm13,%xmm13		# d3 += h0*r3
	 vpshufd	$0x32,48(%rdi),%xmm7		# r4
	vpmuludq	%xmm4,%xmm9,%xmm6		# h4*s3
	vpaddq		%xmm6,%xmm12,%xmm12		# d2 += h4*s3
	 vpshufd	$0x32,64(%rdi),%xmm8		# s4
	vpmuludq	%xmm3,%xmm9,%xmm5		# h3*s3
	vpaddq		%xmm5,%xmm11,%xmm11		# d1 += h3*s3
	vpmuludq	%xmm2,%xmm9,%xmm9		# h2*s3
	vpaddq		%xmm9,%xmm10,%xmm10		# d0 += h2*s3

	vpmuludq	%xmm0,%xmm7,%xmm7		# h0*r4
	vpaddq		%xmm7,%xmm14,%xmm14		# d4 += h0*r4
	vpmuludq	%xmm4,%xmm8,%xmm6		# h4*s4
	vpaddq		%xmm6,%xmm13,%xmm13		# d3 += h4*s4
	vpmuludq	%xmm3,%xmm8,%xmm5		# h3*s4
	vpaddq		%xmm5,%xmm12,%xmm12		# d2 += h3*s4
	vpmuludq	%xmm2,%xmm8,%xmm6		# h2*s4
	vpaddq		%xmm6,%xmm11,%xmm11		# d1 += h2*s4
	vpmuludq	%xmm1,%xmm8,%xmm8		# h1*s4
	vpaddq		%xmm8,%xmm10,%xmm10		# d0 += h1*s4

.Lshort_tail_avx:
	################################################################
	# horizontal addition

	vpsrldq		$8,%xmm14,%xmm9
	vpsrldq		$8,%xmm13,%xmm8
	vpsrldq		$8,%xmm11,%xmm6
	vpsrldq		$8,%xmm10,%xmm5
	vpsrldq		$8,%xmm12,%xmm7
	vpaddq		%xmm8,%xmm13,%xmm13
	vpaddq		%xmm9,%xmm14,%xmm14
	vpaddq		%xmm5,%xmm10,%xmm10
	vpaddq		%xmm6,%xmm11,%xmm11
	vpaddq		%xmm7,%xmm12,%xmm12

	################################################################
	# lazy reduction

	vpsrlq		$26,%xmm13,%xmm3
	vpand		%xmm15,%xmm13,%xmm13
	vpaddq		%xmm3,%xmm14,%xmm14		# h3 -> h4

	vpsrlq		$26,%xmm10,%xmm0
	vpand		%xmm15,%xmm10,%xmm10
	vpaddq		%xmm0,%xmm11,%xmm11		# h0 -> h1

	vpsrlq		$26,%xmm14,%xmm4
	vpand		%xmm15,%xmm14,%xmm14

	vpsrlq		$26,%xmm11,%xmm1
	vpand		%xmm15,%xmm11,%xmm11
	vpaddq		%xmm1,%xmm12,%xmm12		# h1 -> h2

	vpaddq		%xmm4,%xmm10,%xmm10
	vpsllq		$2,%xmm4,%xmm4
	vpaddq		%xmm4,%xmm10,%xmm10		# h4 -> h0

	vpsrlq		$26,%xmm12,%xmm2
	vpand		%xmm15,%xmm12,%xmm12
	vpaddq		%xmm2,%xmm13,%xmm13		# h2 -> h3

	vpsrlq		$26,%xmm10,%xmm0
	vpand		%xmm15,%xmm10,%xmm10
	vpaddq		%xmm0,%xmm11,%xmm11		# h0 -> h1

	vpsrlq		$26,%xmm13,%xmm3
	vpand		%xmm15,%xmm13,%xmm13
	vpaddq		%xmm3,%xmm14,%xmm14		# h3 -> h4

	vmovd		%xmm10,-112(%rdi)	# save partially reduced
	vmovd		%xmm11,-108(%rdi)
	vmovd		%xmm12,-104(%rdi)
	vmovd		%xmm13,-100(%rdi)
	vmovd		%xmm14,-96(%rdi)
	lea		0x58(%r11),%rsp
.cfi_def_cfa		%rsp,8
	vzeroupper
	ret
.cfi_endproc
.size	poly1305_blocks_avx,.-poly1305_blocks_avx

.type	poly1305_emit_avx,@function,3
.align	32
poly1305_emit_avx:
.cfi_startproc
	endbranch
	cmpl	$0,20(%rdi)	# is_base2_26?
	je	.Lemit

	mov	0(%rdi),%eax	# load hash value base 2^26
	mov	4(%rdi),%ecx
	mov	8(%rdi),%r8d
	mov	12(%rdi),%r11d
	mov	16(%rdi),%r10d

	shl	$26,%rcx	# base 2^26 -> base 2^64
	mov	%r8,%r9
	shl	$52,%r8
	add	%rcx,%rax
	shr	$12,%r9
	add	%rax,%r8	# h0
	adc	$0,%r9

	shl	$14,%r11
	mov	%r10,%rax
	shr	$24,%r10
	add	%r11,%r9
	shl	$40,%rax
	add	%rax,%r9	# h1
	adc	$0,%r10	# h2

	mov	%r10,%rax	# could be partially reduced, so reduce
	mov	%r10,%rcx
	and	$3,%r10
	shr	$2,%rax
	and	$-4,%rcx
	add	%rcx,%rax
	add	%rax,%r8
	adc	$0,%r9
	adc	$0,%r10

	mov	%r8,%rax
	add	$5,%r8		# compare to modulus
	mov	%r9,%rcx
	adc	$0,%r9
	adc	$0,%r10
	shr	$2,%r10	# did 130-bit value overflow?
	cmovnz	%r8,%rax
	cmovnz	%r9,%rcx

	add	0(%rdx),%rax	# accumulate nonce
	adc	8(%rdx),%rcx
	mov	%rax,0(%rsi)	# write result
	mov	%rcx,8(%rsi)

	ret
.cfi_endproc
.size	poly1305_emit_avx,.-poly1305_emit_avx
.type	poly1305_blocks_avx2,@function,4
.align	32
poly1305_blocks_avx2:
.cfi_startproc
	endbranch
	mov	20(%rdi),%r8d		# is_base2_26
	cmp	$128,%rdx
	jae	.Lblocks_avx2
	test	%r8d,%r8d
	jz	.Lblocks

.Lblocks_avx2:
	and	$-16,%rdx
	jz	.Lno_data_avx2

	vzeroupper

	test	%r8d,%r8d
	jz	.Lbase2_64_avx2

	test	$63,%rdx
	jz	.Leven_avx2

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
.Lblocks_avx2_body:

	mov	%rdx,%r15		# reassign %rdx

	mov	0(%rdi),%r8		# load hash value
	mov	8(%rdi),%r9
	mov	16(%rdi),%ebp

	mov	24(%rdi),%r11		# load r
	mov	32(%rdi),%r13

	################################# base 2^26 -> base 2^64
	mov	%r8d,%r14d
	and	$-2147483648,%r8
	mov	%r9,%r12			# borrow %r12
	mov	%r9d,%ebx
	and	$-2147483648,%r9

	shr	$6,%r8
	shl	$52,%r12
	add	%r8,%r14
	shr	$12,%rbx
	shr	$18,%r9
	add	%r12,%r14
	adc	%r9,%rbx

	mov	%rbp,%r8
	shl	$40,%r8
	shr	$24,%rbp
	add	%r8,%rbx
	adc	$0,%rbp			# can be partially reduced...

	mov	$-4,%r9		# ... so reduce
	mov	%rbp,%r8
	and	%rbp,%r9
	shr	$2,%r8
	and	$3,%rbp
	add	%r9,%r8			# =*5
	add	%r8,%r14
	adc	$0,%rbx
	adc	$0,%rbp

	mov	%r13,%r12
	mov	%r13,%rax
	shr	$2,%r13
	add	%r12,%r13			# s1 = r1 + (r1 >> 2)

.Lbase2_26_pre_avx2:
	add	0(%rsi),%r14		# accumulate input
	adc	8(%rsi),%rbx
	lea	16(%rsi),%rsi
	adc	%rcx,%rbp
	sub	$16,%r15

	call	__poly1305_block
	mov	%r12,%rax

	test	$63,%r15
	jnz	.Lbase2_26_pre_avx2

	test	%rcx,%rcx		# if %rcx is zero,
	jz	.Lstore_base2_64_avx2	# store hash in base 2^64 format

	################################# base 2^64 -> base 2^26
	mov	%r14,%rax
	mov	%r14,%rdx
	shr	$52,%r14
	mov	%rbx,%r11
	mov	%rbx,%r12
	shr	$26,%rdx
	and	$0x3ffffff,%rax	# h[0]
	shl	$12,%r11
	and	$0x3ffffff,%rdx	# h[1]
	shr	$14,%rbx
	or	%r11,%r14
	shl	$24,%rbp
	and	$0x3ffffff,%r14		# h[2]
	shr	$40,%r12
	and	$0x3ffffff,%rbx		# h[3]
	or	%r12,%rbp			# h[4]

	test	%r15,%r15
	jz	.Lstore_base2_26_avx2

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4
	jmp	.Lproceed_avx2

.align	32
.Lstore_base2_64_avx2:
	mov	%r14,0(%rdi)
	mov	%rbx,8(%rdi)
	mov	%rbp,16(%rdi)		# note that is_base2_26 is zeroed
	jmp	.Ldone_avx2

.align	16
.Lstore_base2_26_avx2:
	mov	%eax,0(%rdi)		# store hash value base 2^26
	mov	%edx,4(%rdi)
	mov	%r14d,8(%rdi)
	mov	%ebx,12(%rdi)
	mov	%ebp,16(%rdi)
.align	16
.Ldone_avx2:
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
.Lno_data_avx2:
.Lblocks_avx2_epilogue:
	ret
.cfi_endproc

.align	32
.Lbase2_64_avx2:
.cfi_startproc
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
.Lbase2_64_avx2_body:

	mov	%rdx,%r15		# reassign %rdx

	mov	24(%rdi),%r11		# load r
	mov	32(%rdi),%r13

	mov	0(%rdi),%r14		# load hash value
	mov	8(%rdi),%rbx
	mov	16(%rdi),%ebp

	mov	%r13,%r12
	mov	%r13,%rax
	shr	$2,%r13
	add	%r12,%r13			# s1 = r1 + (r1 >> 2)

	test	$63,%rdx
	jz	.Linit_avx2

.Lbase2_64_pre_avx2:
	add	0(%rsi),%r14		# accumulate input
	adc	8(%rsi),%rbx
	lea	16(%rsi),%rsi
	adc	%rcx,%rbp
	sub	$16,%r15

	call	__poly1305_block
	mov	%r12,%rax

	test	$63,%r15
	jnz	.Lbase2_64_pre_avx2

.Linit_avx2:
	################################# base 2^64 -> base 2^26
	mov	%r14,%rax
	mov	%r14,%rdx
	shr	$52,%r14
	mov	%rbx,%r8
	mov	%rbx,%r9
	shr	$26,%rdx
	and	$0x3ffffff,%rax	# h[0]
	shl	$12,%r8
	and	$0x3ffffff,%rdx	# h[1]
	shr	$14,%rbx
	or	%r8,%r14
	shl	$24,%rbp
	and	$0x3ffffff,%r14		# h[2]
	shr	$40,%r9
	and	$0x3ffffff,%rbx		# h[3]
	or	%r9,%rbp			# h[4]

	vmovd	%eax,%xmm0
	vmovd	%edx,%xmm1
	vmovd	%r14d,%xmm2
	vmovd	%ebx,%xmm3
	vmovd	%ebp,%xmm4
	movl	$1,20(%rdi)		# set is_base2_26

	call	__poly1305_init_avx

.Lproceed_avx2:
	mov	%r15,%rdx			# restore %rdx
	mov	OPENSSL_ia32cap_P+8(%rip),%r10d
	mov	$3221291008,%r11d

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
	lea	48(%rsp),%rax
	lea	48(%rsp),%rsp
.cfi_adjust_cfa_offset	-48
.Lbase2_64_avx2_epilogue:
	jmp	.Ldo_avx2
.cfi_endproc

.align	32
.Leven_avx2:
.cfi_startproc
	mov		OPENSSL_ia32cap_P+8(%rip),%r10d
	vmovd		4*0(%rdi),%xmm0	# load hash value base 2^26
	vmovd		4*1(%rdi),%xmm1
	vmovd		4*2(%rdi),%xmm2
	vmovd		4*3(%rdi),%xmm3
	vmovd		4*4(%rdi),%xmm4

.Ldo_avx2:
	cmp		$512,%rdx
	jb		.Lskip_avx512
	and		%r11d,%r10d
	test		$65536,%r10d		# check for AVX512F
	jnz		.Lblocks_avx512
.Lskip_avx512:
	lea		-8(%rsp),%r11
.cfi_def_cfa		%r11,16
	sub		$0x128,%rsp
	lea		.Lconst(%rip),%rcx
	lea		48+64(%rdi),%rdi	# size optimization
	vmovdqa		96(%rcx),%ymm7		# .Lpermd_avx2

	# expand and copy pre-calculated table to stack
	vmovdqu		-64(%rdi),%xmm9
	and		$-512,%rsp
	vmovdqu		-48(%rdi),%xmm10
	vmovdqu		-32(%rdi),%xmm6
	vmovdqu		-16(%rdi),%xmm11
	vmovdqu		0(%rdi),%xmm12
	vmovdqu		16(%rdi),%xmm13
	lea		0x90(%rsp),%rax		# size optimization
	vmovdqu		32(%rdi),%xmm14
	vpermd		%ymm9,%ymm7,%ymm9		# 00003412 -> 14243444
	vmovdqu		48(%rdi),%xmm15
	vpermd		%ymm10,%ymm7,%ymm10
	vmovdqu		64(%rdi),%xmm5
	vpermd		%ymm6,%ymm7,%ymm6
	vmovdqa		%ymm9,0x00(%rsp)
	vpermd		%ymm11,%ymm7,%ymm11
	vmovdqa		%ymm10,0x20-0x90(%rax)
	vpermd		%ymm12,%ymm7,%ymm12
	vmovdqa		%ymm6,0x40-0x90(%rax)
	vpermd		%ymm13,%ymm7,%ymm13
	vmovdqa		%ymm11,0x60-0x90(%rax)
	vpermd		%ymm14,%ymm7,%ymm14
	vmovdqa		%ymm12,0x80-0x90(%rax)
	vpermd		%ymm15,%ymm7,%ymm15
	vmovdqa		%ymm13,0xa0-0x90(%rax)
	vpermd		%ymm5,%ymm7,%ymm5
	vmovdqa		%ymm14,0xc0-0x90(%rax)
	vmovdqa		%ymm15,0xe0-0x90(%rax)
	vmovdqa		%ymm5,0x100-0x90(%rax)
	vmovdqa		64(%rcx),%ymm5		# .Lmask26

	################################################################
	# load input
	vmovdqu		16*0(%rsi),%xmm7
	vmovdqu		16*1(%rsi),%xmm8
	vinserti128	$1,16*2(%rsi),%ymm7,%ymm7
	vinserti128	$1,16*3(%rsi),%ymm8,%ymm8
	lea		16*4(%rsi),%rsi

	vpsrldq		$6,%ymm7,%ymm9		# splat input
	vpsrldq		$6,%ymm8,%ymm10
	vpunpckhqdq	%ymm8,%ymm7,%ymm6		# 4
	vpunpcklqdq	%ymm10,%ymm9,%ymm9		# 2:3
	vpunpcklqdq	%ymm8,%ymm7,%ymm7		# 0:1

	vpsrlq		$30,%ymm9,%ymm10
	vpsrlq		$4,%ymm9,%ymm9
	vpsrlq		$26,%ymm7,%ymm8
	vpsrlq		$40,%ymm6,%ymm6		# 4
	vpand		%ymm5,%ymm9,%ymm9		# 2
	vpand		%ymm5,%ymm7,%ymm7		# 0
	vpand		%ymm5,%ymm8,%ymm8		# 1
	vpand		%ymm5,%ymm10,%ymm10		# 3
	vpor		32(%rcx),%ymm6,%ymm6	# padbit, yes, always

	vpaddq		%ymm2,%ymm9,%ymm2		# accumulate input
	sub		$64,%rdx
	jz		.Ltail_avx2
	jmp		.Loop_avx2

.align	32
.Loop_avx2:
	################################################################
	# ((inp[0]*r^4+inp[4])*r^4+inp[ 8])*r^4
	# ((inp[1]*r^4+inp[5])*r^4+inp[ 9])*r^3
	# ((inp[2]*r^4+inp[6])*r^4+inp[10])*r^2
	# ((inp[3]*r^4+inp[7])*r^4+inp[11])*r^1
	#   ________/__________/
	################################################################
	#vpaddq		%ymm2,%ymm9,%ymm2		# accumulate input
	vpaddq		%ymm0,%ymm7,%ymm0
	vmovdqa		0(%rsp),%ymm7	# r0^4
	vpaddq		%ymm1,%ymm8,%ymm1
	vmovdqa		32(%rsp),%ymm8	# r1^4
	vpaddq		%ymm3,%ymm10,%ymm3
	vmovdqa		96(%rsp),%ymm9	# r2^4
	vpaddq		%ymm4,%ymm6,%ymm4
	vmovdqa		48(%rax),%ymm10	# s3^4
	vmovdqa		112(%rax),%ymm5	# s4^4

	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4
	#
	# however, as h2 is "chronologically" first one available pull
	# corresponding operations up, so it's
	#
	# d4 = h2*r2   + h4*r0 + h3*r1             + h1*r3   + h0*r4
	# d3 = h2*r1   + h3*r0           + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0           + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h2*5*r4 + h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3
	# d0 = h2*5*r3 + h0*r0 + h4*5*r1 + h3*5*r2           + h1*5*r4

	vpmuludq	%ymm2,%ymm7,%ymm13		# d2 = h2*r0
	vpmuludq	%ymm2,%ymm8,%ymm14		# d3 = h2*r1
	vpmuludq	%ymm2,%ymm9,%ymm15		# d4 = h2*r2
	vpmuludq	%ymm2,%ymm10,%ymm11		# d0 = h2*s3
	vpmuludq	%ymm2,%ymm5,%ymm12		# d1 = h2*s4

	vpmuludq	%ymm0,%ymm8,%ymm6		# h0*r1
	vpmuludq	%ymm1,%ymm8,%ymm2		# h1*r1, borrow %ymm2 as temp
	vpaddq		%ymm6,%ymm12,%ymm12		# d1 += h0*r1
	vpaddq		%ymm2,%ymm13,%ymm13		# d2 += h1*r1
	vpmuludq	%ymm3,%ymm8,%ymm6		# h3*r1
	vpmuludq	64(%rsp),%ymm4,%ymm2	# h4*s1
	vpaddq		%ymm6,%ymm15,%ymm15		# d4 += h3*r1
	vpaddq		%ymm2,%ymm11,%ymm11		# d0 += h4*s1
	 vmovdqa	-16(%rax),%ymm8	# s2

	vpmuludq	%ymm0,%ymm7,%ymm6		# h0*r0
	vpmuludq	%ymm1,%ymm7,%ymm2		# h1*r0
	vpaddq		%ymm6,%ymm11,%ymm11		# d0 += h0*r0
	vpaddq		%ymm2,%ymm12,%ymm12		# d1 += h1*r0
	vpmuludq	%ymm3,%ymm7,%ymm6		# h3*r0
	vpmuludq	%ymm4,%ymm7,%ymm2		# h4*r0
	 vmovdqu	16*0(%rsi),%xmm7	# load input
	vpaddq		%ymm6,%ymm14,%ymm14		# d3 += h3*r0
	vpaddq		%ymm2,%ymm15,%ymm15		# d4 += h4*r0
	 vinserti128	$1,16*2(%rsi),%ymm7,%ymm7

	vpmuludq	%ymm3,%ymm8,%ymm6		# h3*s2
	vpmuludq	%ymm4,%ymm8,%ymm2		# h4*s2
	 vmovdqu	16*1(%rsi),%xmm8
	vpaddq		%ymm6,%ymm11,%ymm11		# d0 += h3*s2
	vpaddq		%ymm2,%ymm12,%ymm12		# d1 += h4*s2
	 vmovdqa	16(%rax),%ymm2	# r3
	vpmuludq	%ymm1,%ymm9,%ymm6		# h1*r2
	vpmuludq	%ymm0,%ymm9,%ymm9		# h0*r2
	vpaddq		%ymm6,%ymm14,%ymm14		# d3 += h1*r2
	vpaddq		%ymm9,%ymm13,%ymm13		# d2 += h0*r2
	 vinserti128	$1,16*3(%rsi),%ymm8,%ymm8
	 lea		16*4(%rsi),%rsi

	vpmuludq	%ymm1,%ymm2,%ymm6		# h1*r3
	vpmuludq	%ymm0,%ymm2,%ymm2		# h0*r3
	 vpsrldq	$6,%ymm7,%ymm9		# splat input
	vpaddq		%ymm6,%ymm15,%ymm15		# d4 += h1*r3
	vpaddq		%ymm2,%ymm14,%ymm14		# d3 += h0*r3
	vpmuludq	%ymm3,%ymm10,%ymm6		# h3*s3
	vpmuludq	%ymm4,%ymm10,%ymm2		# h4*s3
	 vpsrldq	$6,%ymm8,%ymm10
	vpaddq		%ymm6,%ymm12,%ymm12		# d1 += h3*s3
	vpaddq		%ymm2,%ymm13,%ymm13		# d2 += h4*s3
	 vpunpckhqdq	%ymm8,%ymm7,%ymm6		# 4

	vpmuludq	%ymm3,%ymm5,%ymm3		# h3*s4
	vpmuludq	%ymm4,%ymm5,%ymm4		# h4*s4
	 vpunpcklqdq	%ymm8,%ymm7,%ymm7		# 0:1
	vpaddq		%ymm3,%ymm13,%ymm2		# h2 = d2 + h3*r4
	vpaddq		%ymm4,%ymm14,%ymm3		# h3 = d3 + h4*r4
	 vpunpcklqdq	%ymm10,%ymm9,%ymm10		# 2:3
	vpmuludq	80(%rax),%ymm0,%ymm4	# h0*r4
	vpmuludq	%ymm1,%ymm5,%ymm0		# h1*s4
	vmovdqa		64(%rcx),%ymm5		# .Lmask26
	vpaddq		%ymm4,%ymm15,%ymm4		# h4 = d4 + h0*r4
	vpaddq		%ymm0,%ymm11,%ymm0		# h0 = d0 + h1*s4

	################################################################
	# lazy reduction (interleaved with tail of input splat)

	vpsrlq		$26,%ymm3,%ymm14
	vpand		%ymm5,%ymm3,%ymm3
	vpaddq		%ymm14,%ymm4,%ymm4		# h3 -> h4

	vpsrlq		$26,%ymm0,%ymm11
	vpand		%ymm5,%ymm0,%ymm0
	vpaddq		%ymm11,%ymm12,%ymm1		# h0 -> h1

	vpsrlq		$26,%ymm4,%ymm15
	vpand		%ymm5,%ymm4,%ymm4

	 vpsrlq		$4,%ymm10,%ymm9

	vpsrlq		$26,%ymm1,%ymm12
	vpand		%ymm5,%ymm1,%ymm1
	vpaddq		%ymm12,%ymm2,%ymm2		# h1 -> h2

	vpaddq		%ymm15,%ymm0,%ymm0
	vpsllq		$2,%ymm15,%ymm15
	vpaddq		%ymm15,%ymm0,%ymm0		# h4 -> h0

	 vpand		%ymm5,%ymm9,%ymm9		# 2
	 vpsrlq		$26,%ymm7,%ymm8

	vpsrlq		$26,%ymm2,%ymm13
	vpand		%ymm5,%ymm2,%ymm2
	vpaddq		%ymm13,%ymm3,%ymm3		# h2 -> h3

	 vpaddq		%ymm9,%ymm2,%ymm2		# modulo-scheduled
	 vpsrlq		$30,%ymm10,%ymm10

	vpsrlq		$26,%ymm0,%ymm11
	vpand		%ymm5,%ymm0,%ymm0
	vpaddq		%ymm11,%ymm1,%ymm1		# h0 -> h1

	 vpsrlq		$40,%ymm6,%ymm6		# 4

	vpsrlq		$26,%ymm3,%ymm14
	vpand		%ymm5,%ymm3,%ymm3
	vpaddq		%ymm14,%ymm4,%ymm4		# h3 -> h4

	 vpand		%ymm5,%ymm7,%ymm7		# 0
	 vpand		%ymm5,%ymm8,%ymm8		# 1
	 vpand		%ymm5,%ymm10,%ymm10		# 3
	 vpor		32(%rcx),%ymm6,%ymm6	# padbit, yes, always

	sub		$64,%rdx
	jnz		.Loop_avx2

	.byte		0x66,0x90
.Ltail_avx2:
	################################################################
	# while above multiplications were by r^4 in all lanes, in last
	# iteration we multiply least significant lane by r^4 and most
	# significant one by r, so copy of above except that references
	# to the precomputed table are displaced by 4...

	#vpaddq		%ymm2,%ymm9,%ymm2		# accumulate input
	vpaddq		%ymm0,%ymm7,%ymm0
	vmovdqu		4(%rsp),%ymm7	# r0^4
	vpaddq		%ymm1,%ymm8,%ymm1
	vmovdqu		36(%rsp),%ymm8	# r1^4
	vpaddq		%ymm3,%ymm10,%ymm3
	vmovdqu		100(%rsp),%ymm9	# r2^4
	vpaddq		%ymm4,%ymm6,%ymm4
	vmovdqu		52(%rax),%ymm10	# s3^4
	vmovdqu		116(%rax),%ymm5	# s4^4

	vpmuludq	%ymm2,%ymm7,%ymm13		# d2 = h2*r0
	vpmuludq	%ymm2,%ymm8,%ymm14		# d3 = h2*r1
	vpmuludq	%ymm2,%ymm9,%ymm15		# d4 = h2*r2
	vpmuludq	%ymm2,%ymm10,%ymm11		# d0 = h2*s3
	vpmuludq	%ymm2,%ymm5,%ymm12		# d1 = h2*s4

	vpmuludq	%ymm0,%ymm8,%ymm6		# h0*r1
	vpmuludq	%ymm1,%ymm8,%ymm2		# h1*r1
	vpaddq		%ymm6,%ymm12,%ymm12		# d1 += h0*r1
	vpaddq		%ymm2,%ymm13,%ymm13		# d2 += h1*r1
	vpmuludq	%ymm3,%ymm8,%ymm6		# h3*r1
	vpmuludq	68(%rsp),%ymm4,%ymm2	# h4*s1
	vpaddq		%ymm6,%ymm15,%ymm15		# d4 += h3*r1
	vpaddq		%ymm2,%ymm11,%ymm11		# d0 += h4*s1

	vpmuludq	%ymm0,%ymm7,%ymm6		# h0*r0
	vpmuludq	%ymm1,%ymm7,%ymm2		# h1*r0
	vpaddq		%ymm6,%ymm11,%ymm11		# d0 += h0*r0
	 vmovdqu	-12(%rax),%ymm8	# s2
	vpaddq		%ymm2,%ymm12,%ymm12		# d1 += h1*r0
	vpmuludq	%ymm3,%ymm7,%ymm6		# h3*r0
	vpmuludq	%ymm4,%ymm7,%ymm2		# h4*r0
	vpaddq		%ymm6,%ymm14,%ymm14		# d3 += h3*r0
	vpaddq		%ymm2,%ymm15,%ymm15		# d4 += h4*r0

	vpmuludq	%ymm3,%ymm8,%ymm6		# h3*s2
	vpmuludq	%ymm4,%ymm8,%ymm2		# h4*s2
	vpaddq		%ymm6,%ymm11,%ymm11		# d0 += h3*s2
	vpaddq		%ymm2,%ymm12,%ymm12		# d1 += h4*s2
	 vmovdqu	20(%rax),%ymm2	# r3
	vpmuludq	%ymm1,%ymm9,%ymm6		# h1*r2
	vpmuludq	%ymm0,%ymm9,%ymm9		# h0*r2
	vpaddq		%ymm6,%ymm14,%ymm14		# d3 += h1*r2
	vpaddq		%ymm9,%ymm13,%ymm13		# d2 += h0*r2

	vpmuludq	%ymm1,%ymm2,%ymm6		# h1*r3
	vpmuludq	%ymm0,%ymm2,%ymm2		# h0*r3
	vpaddq		%ymm6,%ymm15,%ymm15		# d4 += h1*r3
	vpaddq		%ymm2,%ymm14,%ymm14		# d3 += h0*r3
	vpmuludq	%ymm3,%ymm10,%ymm6		# h3*s3
	vpmuludq	%ymm4,%ymm10,%ymm2		# h4*s3
	vpaddq		%ymm6,%ymm12,%ymm12		# d1 += h3*s3
	vpaddq		%ymm2,%ymm13,%ymm13		# d2 += h4*s3

	vpmuludq	%ymm3,%ymm5,%ymm3		# h3*s4
	vpmuludq	%ymm4,%ymm5,%ymm4		# h4*s4
	vpaddq		%ymm3,%ymm13,%ymm2		# h2 = d2 + h3*r4
	vpaddq		%ymm4,%ymm14,%ymm3		# h3 = d3 + h4*r4
	vpmuludq	84(%rax),%ymm0,%ymm4		# h0*r4
	vpmuludq	%ymm1,%ymm5,%ymm0		# h1*s4
	vmovdqa		64(%rcx),%ymm5		# .Lmask26
	vpaddq		%ymm4,%ymm15,%ymm4		# h4 = d4 + h0*r4
	vpaddq		%ymm0,%ymm11,%ymm0		# h0 = d0 + h1*s4

	################################################################
	# horizontal addition

	vpsrldq		$8,%ymm12,%ymm8
	vpsrldq		$8,%ymm2,%ymm9
	vpsrldq		$8,%ymm3,%ymm10
	vpsrldq		$8,%ymm4,%ymm6
	vpsrldq		$8,%ymm0,%ymm7
	vpaddq		%ymm8,%ymm12,%ymm12
	vpaddq		%ymm9,%ymm2,%ymm2
	vpaddq		%ymm10,%ymm3,%ymm3
	vpaddq		%ymm6,%ymm4,%ymm4
	vpaddq		%ymm7,%ymm0,%ymm0

	vpermq		$0x2,%ymm3,%ymm10
	vpermq		$0x2,%ymm4,%ymm6
	vpermq		$0x2,%ymm0,%ymm7
	vpermq		$0x2,%ymm12,%ymm8
	vpermq		$0x2,%ymm2,%ymm9
	vpaddq		%ymm10,%ymm3,%ymm3
	vpaddq		%ymm6,%ymm4,%ymm4
	vpaddq		%ymm7,%ymm0,%ymm0
	vpaddq		%ymm8,%ymm12,%ymm12
	vpaddq		%ymm9,%ymm2,%ymm2

	################################################################
	# lazy reduction

	vpsrlq		$26,%ymm3,%ymm14
	vpand		%ymm5,%ymm3,%ymm3
	vpaddq		%ymm14,%ymm4,%ymm4		# h3 -> h4

	vpsrlq		$26,%ymm0,%ymm11
	vpand		%ymm5,%ymm0,%ymm0
	vpaddq		%ymm11,%ymm12,%ymm1		# h0 -> h1

	vpsrlq		$26,%ymm4,%ymm15
	vpand		%ymm5,%ymm4,%ymm4

	vpsrlq		$26,%ymm1,%ymm12
	vpand		%ymm5,%ymm1,%ymm1
	vpaddq		%ymm12,%ymm2,%ymm2		# h1 -> h2

	vpaddq		%ymm15,%ymm0,%ymm0
	vpsllq		$2,%ymm15,%ymm15
	vpaddq		%ymm15,%ymm0,%ymm0		# h4 -> h0

	vpsrlq		$26,%ymm2,%ymm13
	vpand		%ymm5,%ymm2,%ymm2
	vpaddq		%ymm13,%ymm3,%ymm3		# h2 -> h3

	vpsrlq		$26,%ymm0,%ymm11
	vpand		%ymm5,%ymm0,%ymm0
	vpaddq		%ymm11,%ymm1,%ymm1		# h0 -> h1

	vpsrlq		$26,%ymm3,%ymm14
	vpand		%ymm5,%ymm3,%ymm3
	vpaddq		%ymm14,%ymm4,%ymm4		# h3 -> h4

	vmovd		%xmm0,-112(%rdi)# save partially reduced
	vmovd		%xmm1,-108(%rdi)
	vmovd		%xmm2,-104(%rdi)
	vmovd		%xmm3,-100(%rdi)
	vmovd		%xmm4,-96(%rdi)
	lea		8(%r11),%rsp
.cfi_def_cfa		%rsp,8
	vzeroupper
	ret
.cfi_endproc
.size	poly1305_blocks_avx2,.-poly1305_blocks_avx2
.type	poly1305_blocks_avx512,@function,4
.align	32
poly1305_blocks_avx512:
.cfi_startproc
	endbranch
.Lblocks_avx512:
	mov		$15,%eax
	kmovw		%eax,%k2
	lea		-8(%rsp),%r11
.cfi_def_cfa		%r11,16
	sub		$0x128,%rsp
	lea		.Lconst(%rip),%rcx
	lea		48+64(%rdi),%rdi	# size optimization
	vmovdqa		96(%rcx),%ymm9		# .Lpermd_avx2

	# expand pre-calculated table
	vmovdqu		-64(%rdi),%xmm11	# will become expanded %zmm16
	and		$-512,%rsp
	vmovdqu		-48(%rdi),%xmm12	# will become ... %zmm17
	mov		$0x20,%rax
	vmovdqu		-32(%rdi),%xmm7	# ... %zmm21
	vmovdqu		-16(%rdi),%xmm13	# ... %zmm18
	vmovdqu		0(%rdi),%xmm8	# ... %zmm22
	vmovdqu		16(%rdi),%xmm14	# ... %zmm19
	vmovdqu		32(%rdi),%xmm10	# ... %zmm23
	vmovdqu		48(%rdi),%xmm15	# ... %zmm20
	vmovdqu		64(%rdi),%xmm6	# ... %zmm24
	vpermd		%zmm11,%zmm9,%zmm16		# 00003412 -> 14243444
	vpbroadcastq	64(%rcx),%zmm5		# .Lmask26
	vpermd		%zmm12,%zmm9,%zmm17
	vpermd		%zmm7,%zmm9,%zmm21
	vpermd		%zmm13,%zmm9,%zmm18
	vmovdqa64	%zmm16,0x00(%rsp){%k2}	# save in case %rdx%128 != 0
	 vpsrlq		$32,%zmm16,%zmm7		# 14243444 -> 01020304
	vpermd		%zmm8,%zmm9,%zmm22
	vmovdqu64	%zmm17,0x00(%rsp,%rax){%k2}
	 vpsrlq		$32,%zmm17,%zmm8
	vpermd		%zmm14,%zmm9,%zmm19
	vmovdqa64	%zmm21,0x40(%rsp){%k2}
	vpermd		%zmm10,%zmm9,%zmm23
	vpermd		%zmm15,%zmm9,%zmm20
	vmovdqu64	%zmm18,0x40(%rsp,%rax){%k2}
	vpermd		%zmm6,%zmm9,%zmm24
	vmovdqa64	%zmm22,0x80(%rsp){%k2}
	vmovdqu64	%zmm19,0x80(%rsp,%rax){%k2}
	vmovdqa64	%zmm23,0xc0(%rsp){%k2}
	vmovdqu64	%zmm20,0xc0(%rsp,%rax){%k2}
	vmovdqa64	%zmm24,0x100(%rsp){%k2}

	################################################################
	# calculate 5th through 8th powers of the key
	#
	# d0 = r0'*r0 + r1'*5*r4 + r2'*5*r3 + r3'*5*r2 + r4'*5*r1
	# d1 = r0'*r1 + r1'*r0   + r2'*5*r4 + r3'*5*r3 + r4'*5*r2
	# d2 = r0'*r2 + r1'*r1   + r2'*r0   + r3'*5*r4 + r4'*5*r3
	# d3 = r0'*r3 + r1'*r2   + r2'*r1   + r3'*r0   + r4'*5*r4
	# d4 = r0'*r4 + r1'*r3   + r2'*r2   + r3'*r1   + r4'*r0

	vpmuludq	%zmm7,%zmm16,%zmm11		# d0 = r0'*r0
	vpmuludq	%zmm7,%zmm17,%zmm12		# d1 = r0'*r1
	vpmuludq	%zmm7,%zmm18,%zmm13		# d2 = r0'*r2
	vpmuludq	%zmm7,%zmm19,%zmm14		# d3 = r0'*r3
	vpmuludq	%zmm7,%zmm20,%zmm15		# d4 = r0'*r4
	 vpsrlq		$32,%zmm18,%zmm9

	vpmuludq	%zmm8,%zmm24,%zmm25
	vpmuludq	%zmm8,%zmm16,%zmm26
	vpmuludq	%zmm8,%zmm17,%zmm27
	vpmuludq	%zmm8,%zmm18,%zmm28
	vpmuludq	%zmm8,%zmm19,%zmm29
	 vpsrlq		$32,%zmm19,%zmm10
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += r1'*5*r4
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += r1'*r0
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += r1'*r1
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += r1'*r2
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += r1'*r3

	vpmuludq	%zmm9,%zmm23,%zmm25
	vpmuludq	%zmm9,%zmm24,%zmm26
	vpmuludq	%zmm9,%zmm17,%zmm28
	vpmuludq	%zmm9,%zmm18,%zmm29
	vpmuludq	%zmm9,%zmm16,%zmm27
	 vpsrlq		$32,%zmm20,%zmm6
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += r2'*5*r3
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += r2'*5*r4
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += r2'*r1
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += r2'*r2
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += r2'*r0

	vpmuludq	%zmm10,%zmm22,%zmm25
	vpmuludq	%zmm10,%zmm16,%zmm28
	vpmuludq	%zmm10,%zmm17,%zmm29
	vpmuludq	%zmm10,%zmm23,%zmm26
	vpmuludq	%zmm10,%zmm24,%zmm27
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += r3'*5*r2
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += r3'*r0
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += r3'*r1
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += r3'*5*r3
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += r3'*5*r4

	vpmuludq	%zmm6,%zmm24,%zmm28
	vpmuludq	%zmm6,%zmm16,%zmm29
	vpmuludq	%zmm6,%zmm21,%zmm25
	vpmuludq	%zmm6,%zmm22,%zmm26
	vpmuludq	%zmm6,%zmm23,%zmm27
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += r2'*5*r4
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += r2'*r0
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += r2'*5*r1
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += r2'*5*r2
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += r2'*5*r3

	################################################################
	# load input
	vmovdqu64	16*0(%rsi),%zmm10
	vmovdqu64	16*4(%rsi),%zmm6
	lea		16*8(%rsi),%rsi

	################################################################
	# lazy reduction

	vpsrlq		$26,%zmm14,%zmm28
	vpandq		%zmm5,%zmm14,%zmm14
	vpaddq		%zmm28,%zmm15,%zmm15		# d3 -> d4

	vpsrlq		$26,%zmm11,%zmm25
	vpandq		%zmm5,%zmm11,%zmm11
	vpaddq		%zmm25,%zmm12,%zmm12		# d0 -> d1

	vpsrlq		$26,%zmm15,%zmm29
	vpandq		%zmm5,%zmm15,%zmm15

	vpsrlq		$26,%zmm12,%zmm26
	vpandq		%zmm5,%zmm12,%zmm12
	vpaddq		%zmm26,%zmm13,%zmm13		# d1 -> d2

	vpaddq		%zmm29,%zmm11,%zmm11
	vpsllq		$2,%zmm29,%zmm29
	vpaddq		%zmm29,%zmm11,%zmm11		# d4 -> d0

	vpsrlq		$26,%zmm13,%zmm27
	vpandq		%zmm5,%zmm13,%zmm13
	vpaddq		%zmm27,%zmm14,%zmm14		# d2 -> d3

	vpsrlq		$26,%zmm11,%zmm25
	vpandq		%zmm5,%zmm11,%zmm11
	vpaddq		%zmm25,%zmm12,%zmm12		# d0 -> d1

	vpsrlq		$26,%zmm14,%zmm28
	vpandq		%zmm5,%zmm14,%zmm14
	vpaddq		%zmm28,%zmm15,%zmm15		# d3 -> d4

	################################################################
	# at this point we have 14243444 in %zmm16-%zmm24 and 05060708 in
	# %zmm11-%zmm15, ...

	vpunpcklqdq	%zmm6,%zmm10,%zmm7	# transpose input
	vpunpckhqdq	%zmm6,%zmm10,%zmm6

	# ... since input 64-bit lanes are ordered as 73625140, we could
	# "vperm" it to 76543210 (here and in each loop iteration), *or*
	# we could just flow along, hence the goal for %zmm16-%zmm24 is
	# 1858286838784888 ...

	vmovdqa32	128(%rcx),%zmm25		# .Lpermd_avx512:
	mov		$0x7777,%eax
	kmovw		%eax,%k1

	vpermd		%zmm16,%zmm25,%zmm16		# 14243444 -> 1---2---3---4---
	vpermd		%zmm17,%zmm25,%zmm17
	vpermd		%zmm18,%zmm25,%zmm18
	vpermd		%zmm19,%zmm25,%zmm19
	vpermd		%zmm20,%zmm25,%zmm20

	vpermd		%zmm11,%zmm25,%zmm16{%k1}	# 05060708 -> 1858286838784888
	vpermd		%zmm12,%zmm25,%zmm17{%k1}
	vpermd		%zmm13,%zmm25,%zmm18{%k1}
	vpermd		%zmm14,%zmm25,%zmm19{%k1}
	vpermd		%zmm15,%zmm25,%zmm20{%k1}

	vpslld		$2,%zmm17,%zmm21		# *5
	vpslld		$2,%zmm18,%zmm22
	vpslld		$2,%zmm19,%zmm23
	vpslld		$2,%zmm20,%zmm24
	vpaddd		%zmm17,%zmm21,%zmm21
	vpaddd		%zmm18,%zmm22,%zmm22
	vpaddd		%zmm19,%zmm23,%zmm23
	vpaddd		%zmm20,%zmm24,%zmm24

	vpbroadcastq	32(%rcx),%zmm30	# .L129

	vpsrlq		$52,%zmm7,%zmm9		# splat input
	vpsllq		$12,%zmm6,%zmm10
	vporq		%zmm10,%zmm9,%zmm9
	vpsrlq		$26,%zmm7,%zmm8
	vpsrlq		$14,%zmm6,%zmm10
	vpsrlq		$40,%zmm6,%zmm6		# 4
	vpandq		%zmm5,%zmm9,%zmm9		# 2
	vpandq		%zmm5,%zmm7,%zmm7		# 0
	#vpandq		%zmm5,%zmm8,%zmm8		# 1
	#vpandq		%zmm5,%zmm10,%zmm10		# 3
	#vporq		%zmm30,%zmm6,%zmm6		# padbit, yes, always

	vpaddq		%zmm2,%zmm9,%zmm2		# accumulate input
	sub		$192,%rdx
	jbe		.Ltail_avx512
	jmp		.Loop_avx512

.align	32
.Loop_avx512:
	################################################################
	# ((inp[0]*r^8+inp[ 8])*r^8+inp[16])*r^8
	# ((inp[1]*r^8+inp[ 9])*r^8+inp[17])*r^7
	# ((inp[2]*r^8+inp[10])*r^8+inp[18])*r^6
	# ((inp[3]*r^8+inp[11])*r^8+inp[19])*r^5
	# ((inp[4]*r^8+inp[12])*r^8+inp[20])*r^4
	# ((inp[5]*r^8+inp[13])*r^8+inp[21])*r^3
	# ((inp[6]*r^8+inp[14])*r^8+inp[22])*r^2
	# ((inp[7]*r^8+inp[15])*r^8+inp[23])*r^1
	#   ________/___________/
	################################################################
	#vpaddq		%zmm2,%zmm9,%zmm2		# accumulate input

	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4
	#
	# however, as h2 is "chronologically" first one available pull
	# corresponding operations up, so it's
	#
	# d3 = h2*r1   + h0*r3 + h1*r2   + h3*r0 + h4*5*r4
	# d4 = h2*r2   + h0*r4 + h1*r3   + h3*r1 + h4*r0
	# d0 = h2*5*r3 + h0*r0 + h1*5*r4         + h3*5*r2 + h4*5*r1
	# d1 = h2*5*r4 + h0*r1           + h1*r0 + h3*5*r3 + h4*5*r2
	# d2 = h2*r0           + h0*r2   + h1*r1 + h3*5*r4 + h4*5*r3

	vpmuludq	%zmm2,%zmm17,%zmm14		# d3 = h2*r1
	 vpaddq		%zmm0,%zmm7,%zmm0
	vpmuludq	%zmm2,%zmm18,%zmm15		# d4 = h2*r2
	 vpandq		%zmm5,%zmm8,%zmm8		# 1
	vpmuludq	%zmm2,%zmm23,%zmm11		# d0 = h2*s3
	 vpandq		%zmm5,%zmm10,%zmm10		# 3
	vpmuludq	%zmm2,%zmm24,%zmm12		# d1 = h2*s4
	 vporq		%zmm30,%zmm6,%zmm6		# padbit, yes, always
	vpmuludq	%zmm2,%zmm16,%zmm13		# d2 = h2*r0
	 vpaddq		%zmm1,%zmm8,%zmm1		# accumulate input
	 vpaddq		%zmm3,%zmm10,%zmm3
	 vpaddq		%zmm4,%zmm6,%zmm4

	  vmovdqu64	16*0(%rsi),%zmm10		# load input
	  vmovdqu64	16*4(%rsi),%zmm6
	  lea		16*8(%rsi),%rsi
	vpmuludq	%zmm0,%zmm19,%zmm28
	vpmuludq	%zmm0,%zmm20,%zmm29
	vpmuludq	%zmm0,%zmm16,%zmm25
	vpmuludq	%zmm0,%zmm17,%zmm26
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += h0*r3
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h0*r4
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += h0*r0
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += h0*r1

	vpmuludq	%zmm1,%zmm18,%zmm28
	vpmuludq	%zmm1,%zmm19,%zmm29
	vpmuludq	%zmm1,%zmm24,%zmm25
	vpmuludq	%zmm0,%zmm18,%zmm27
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += h1*r2
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h1*r3
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += h1*s4
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += h0*r2

	  vpunpcklqdq	%zmm6,%zmm10,%zmm7		# transpose input
	  vpunpckhqdq	%zmm6,%zmm10,%zmm6

	vpmuludq	%zmm3,%zmm16,%zmm28
	vpmuludq	%zmm3,%zmm17,%zmm29
	vpmuludq	%zmm1,%zmm16,%zmm26
	vpmuludq	%zmm1,%zmm17,%zmm27
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += h3*r0
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h3*r1
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += h1*r0
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += h1*r1

	vpmuludq	%zmm4,%zmm24,%zmm28
	vpmuludq	%zmm4,%zmm16,%zmm29
	vpmuludq	%zmm3,%zmm22,%zmm25
	vpmuludq	%zmm3,%zmm23,%zmm26
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += h4*s4
	vpmuludq	%zmm3,%zmm24,%zmm27
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h4*r0
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += h3*s2
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += h3*s3
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += h3*s4

	vpmuludq	%zmm4,%zmm21,%zmm25
	vpmuludq	%zmm4,%zmm22,%zmm26
	vpmuludq	%zmm4,%zmm23,%zmm27
	vpaddq		%zmm25,%zmm11,%zmm0		# h0 = d0 + h4*s1
	vpaddq		%zmm26,%zmm12,%zmm1		# h1 = d2 + h4*s2
	vpaddq		%zmm27,%zmm13,%zmm2		# h2 = d3 + h4*s3

	################################################################
	# lazy reduction (interleaved with input splat)

	 vpsrlq		$52,%zmm7,%zmm9		# splat input
	 vpsllq		$12,%zmm6,%zmm10

	vpsrlq		$26,%zmm14,%zmm3
	vpandq		%zmm5,%zmm14,%zmm14
	vpaddq		%zmm3,%zmm15,%zmm4		# h3 -> h4

	 vporq		%zmm10,%zmm9,%zmm9

	vpsrlq		$26,%zmm0,%zmm11
	vpandq		%zmm5,%zmm0,%zmm0
	vpaddq		%zmm11,%zmm1,%zmm1		# h0 -> h1

	 vpandq		%zmm5,%zmm9,%zmm9		# 2

	vpsrlq		$26,%zmm4,%zmm15
	vpandq		%zmm5,%zmm4,%zmm4

	vpsrlq		$26,%zmm1,%zmm12
	vpandq		%zmm5,%zmm1,%zmm1
	vpaddq		%zmm12,%zmm2,%zmm2		# h1 -> h2

	vpaddq		%zmm15,%zmm0,%zmm0
	vpsllq		$2,%zmm15,%zmm15
	vpaddq		%zmm15,%zmm0,%zmm0		# h4 -> h0

	 vpaddq		%zmm9,%zmm2,%zmm2		# modulo-scheduled
	 vpsrlq		$26,%zmm7,%zmm8

	vpsrlq		$26,%zmm2,%zmm13
	vpandq		%zmm5,%zmm2,%zmm2
	vpaddq		%zmm13,%zmm14,%zmm3		# h2 -> h3

	 vpsrlq		$14,%zmm6,%zmm10

	vpsrlq		$26,%zmm0,%zmm11
	vpandq		%zmm5,%zmm0,%zmm0
	vpaddq		%zmm11,%zmm1,%zmm1		# h0 -> h1

	 vpsrlq		$40,%zmm6,%zmm6		# 4

	vpsrlq		$26,%zmm3,%zmm14
	vpandq		%zmm5,%zmm3,%zmm3
	vpaddq		%zmm14,%zmm4,%zmm4		# h3 -> h4

	 vpandq		%zmm5,%zmm7,%zmm7		# 0
	 #vpandq	%zmm5,%zmm8,%zmm8		# 1
	 #vpandq	%zmm5,%zmm10,%zmm10		# 3
	 #vporq		%zmm30,%zmm6,%zmm6		# padbit, yes, always

	sub		$128,%rdx
	ja		.Loop_avx512

.Ltail_avx512:
	################################################################
	# while above multiplications were by r^8 in all lanes, in last
	# iteration we multiply least significant lane by r^8 and most
	# significant one by r, that's why table gets shifted...

	vpsrlq		$32,%zmm16,%zmm16		# 0105020603070408
	vpsrlq		$32,%zmm17,%zmm17
	vpsrlq		$32,%zmm18,%zmm18
	vpsrlq		$32,%zmm23,%zmm23
	vpsrlq		$32,%zmm24,%zmm24
	vpsrlq		$32,%zmm19,%zmm19
	vpsrlq		$32,%zmm20,%zmm20
	vpsrlq		$32,%zmm21,%zmm21
	vpsrlq		$32,%zmm22,%zmm22

	################################################################
	# load either next or last 64 byte of input
	lea		(%rsi,%rdx),%rsi

	#vpaddq		%zmm2,%zmm9,%zmm2		# accumulate input
	vpaddq		%zmm0,%zmm7,%zmm0

	vpmuludq	%zmm2,%zmm17,%zmm14		# d3 = h2*r1
	vpmuludq	%zmm2,%zmm18,%zmm15		# d4 = h2*r2
	vpmuludq	%zmm2,%zmm23,%zmm11		# d0 = h2*s3
	 vpandq		%zmm5,%zmm8,%zmm8		# 1
	vpmuludq	%zmm2,%zmm24,%zmm12		# d1 = h2*s4
	 vpandq		%zmm5,%zmm10,%zmm10		# 3
	vpmuludq	%zmm2,%zmm16,%zmm13		# d2 = h2*r0
	 vporq		%zmm30,%zmm6,%zmm6		# padbit, yes, always
	 vpaddq		%zmm1,%zmm8,%zmm1		# accumulate input
	 vpaddq		%zmm3,%zmm10,%zmm3
	 vpaddq		%zmm4,%zmm6,%zmm4

	  vmovdqu	16*0(%rsi),%xmm7
	vpmuludq	%zmm0,%zmm19,%zmm28
	vpmuludq	%zmm0,%zmm20,%zmm29
	vpmuludq	%zmm0,%zmm16,%zmm25
	vpmuludq	%zmm0,%zmm17,%zmm26
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += h0*r3
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h0*r4
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += h0*r0
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += h0*r1

	  vmovdqu	16*1(%rsi),%xmm8
	vpmuludq	%zmm1,%zmm18,%zmm28
	vpmuludq	%zmm1,%zmm19,%zmm29
	vpmuludq	%zmm1,%zmm24,%zmm25
	vpmuludq	%zmm0,%zmm18,%zmm27
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += h1*r2
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h1*r3
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += h1*s4
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += h0*r2

	  vinserti128	$1,16*2(%rsi),%ymm7,%ymm7
	vpmuludq	%zmm3,%zmm16,%zmm28
	vpmuludq	%zmm3,%zmm17,%zmm29
	vpmuludq	%zmm1,%zmm16,%zmm26
	vpmuludq	%zmm1,%zmm17,%zmm27
	vpaddq		%zmm28,%zmm14,%zmm14		# d3 += h3*r0
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h3*r1
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += h1*r0
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += h1*r1

	  vinserti128	$1,16*3(%rsi),%ymm8,%ymm8
	vpmuludq	%zmm4,%zmm24,%zmm28
	vpmuludq	%zmm4,%zmm16,%zmm29
	vpmuludq	%zmm3,%zmm22,%zmm25
	vpmuludq	%zmm3,%zmm23,%zmm26
	vpmuludq	%zmm3,%zmm24,%zmm27
	vpaddq		%zmm28,%zmm14,%zmm3		# h3 = d3 + h4*s4
	vpaddq		%zmm29,%zmm15,%zmm15		# d4 += h4*r0
	vpaddq		%zmm25,%zmm11,%zmm11		# d0 += h3*s2
	vpaddq		%zmm26,%zmm12,%zmm12		# d1 += h3*s3
	vpaddq		%zmm27,%zmm13,%zmm13		# d2 += h3*s4

	vpmuludq	%zmm4,%zmm21,%zmm25
	vpmuludq	%zmm4,%zmm22,%zmm26
	vpmuludq	%zmm4,%zmm23,%zmm27
	vpaddq		%zmm25,%zmm11,%zmm0		# h0 = d0 + h4*s1
	vpaddq		%zmm26,%zmm12,%zmm1		# h1 = d2 + h4*s2
	vpaddq		%zmm27,%zmm13,%zmm2		# h2 = d3 + h4*s3

	################################################################
	# horizontal addition

	mov		$1,%eax
	vpermq		$0xb1,%zmm3,%zmm14
	vpermq		$0xb1,%zmm15,%zmm4
	vpermq		$0xb1,%zmm0,%zmm11
	vpermq		$0xb1,%zmm1,%zmm12
	vpermq		$0xb1,%zmm2,%zmm13
	vpaddq		%zmm14,%zmm3,%zmm3
	vpaddq		%zmm15,%zmm4,%zmm4
	vpaddq		%zmm11,%zmm0,%zmm0
	vpaddq		%zmm12,%zmm1,%zmm1
	vpaddq		%zmm13,%zmm2,%zmm2

	kmovw		%eax,%k3
	vpermq		$0x2,%zmm3,%zmm14
	vpermq		$0x2,%zmm4,%zmm15
	vpermq		$0x2,%zmm0,%zmm11
	vpermq		$0x2,%zmm1,%zmm12
	vpermq		$0x2,%zmm2,%zmm13
	vpaddq		%zmm14,%zmm3,%zmm3
	vpaddq		%zmm15,%zmm4,%zmm4
	vpaddq		%zmm11,%zmm0,%zmm0
	vpaddq		%zmm12,%zmm1,%zmm1
	vpaddq		%zmm13,%zmm2,%zmm2

	vextracti64x4	$0x1,%zmm3,%ymm14
	vextracti64x4	$0x1,%zmm4,%ymm15
	vextracti64x4	$0x1,%zmm0,%ymm11
	vextracti64x4	$0x1,%zmm1,%ymm12
	vextracti64x4	$0x1,%zmm2,%ymm13
	vpaddq		%zmm14,%zmm3,%zmm3{%k3}{z}	# keep single qword in case
	vpaddq		%zmm15,%zmm4,%zmm4{%k3}{z}	# it's passed to .Ltail_avx2
	vpaddq		%zmm11,%zmm0,%zmm0{%k3}{z}
	vpaddq		%zmm12,%zmm1,%zmm1{%k3}{z}
	vpaddq		%zmm13,%zmm2,%zmm2{%k3}{z}
	################################################################
	# lazy reduction (interleaved with input splat)

	vpsrlq		$26,%ymm3,%ymm14
	vpand		%ymm5,%ymm3,%ymm3
	 vpsrldq	$6,%ymm7,%ymm9		# splat input
	 vpsrldq	$6,%ymm8,%ymm10
	 vpunpckhqdq	%ymm8,%ymm7,%ymm6		# 4
	vpaddq		%ymm14,%ymm4,%ymm4		# h3 -> h4

	vpsrlq		$26,%ymm0,%ymm11
	vpand		%ymm5,%ymm0,%ymm0
	 vpunpcklqdq	%ymm10,%ymm9,%ymm9		# 2:3
	 vpunpcklqdq	%ymm8,%ymm7,%ymm7		# 0:1
	vpaddq		%ymm11,%ymm1,%ymm1		# h0 -> h1

	vpsrlq		$26,%ymm4,%ymm15
	vpand		%ymm5,%ymm4,%ymm4

	vpsrlq		$26,%ymm1,%ymm12
	vpand		%ymm5,%ymm1,%ymm1
	 vpsrlq		$30,%ymm9,%ymm10
	 vpsrlq		$4,%ymm9,%ymm9
	vpaddq		%ymm12,%ymm2,%ymm2		# h1 -> h2

	vpaddq		%ymm15,%ymm0,%ymm0
	vpsllq		$2,%ymm15,%ymm15
	 vpsrlq		$26,%ymm7,%ymm8
	 vpsrlq		$40,%ymm6,%ymm6		# 4
	vpaddq		%ymm15,%ymm0,%ymm0		# h4 -> h0

	vpsrlq		$26,%ymm2,%ymm13
	vpand		%ymm5,%ymm2,%ymm2
	 vpand		%ymm5,%ymm9,%ymm9		# 2
	 vpand		%ymm5,%ymm7,%ymm7		# 0
	vpaddq		%ymm13,%ymm3,%ymm3		# h2 -> h3

	vpsrlq		$26,%ymm0,%ymm11
	vpand		%ymm5,%ymm0,%ymm0
	 vpaddq		%ymm2,%ymm9,%ymm2		# accumulate input for .Ltail_avx2
	 vpand		%ymm5,%ymm8,%ymm8		# 1
	vpaddq		%ymm11,%ymm1,%ymm1		# h0 -> h1

	vpsrlq		$26,%ymm3,%ymm14
	vpand		%ymm5,%ymm3,%ymm3
	 vpand		%ymm5,%ymm10,%ymm10		# 3
	 vpor		32(%rcx),%ymm6,%ymm6	# padbit, yes, always
	vpaddq		%ymm14,%ymm4,%ymm4		# h3 -> h4

	lea		0x90(%rsp),%rax		# size optimization for .Ltail_avx2
	add		$64,%rdx
	jnz		.Ltail_avx2

	vpsubq		%ymm9,%ymm2,%ymm2		# undo input accumulation
	vmovd		%xmm0,-112(%rdi)# save partially reduced
	vmovd		%xmm1,-108(%rdi)
	vmovd		%xmm2,-104(%rdi)
	vmovd		%xmm3,-100(%rdi)
	vmovd		%xmm4,-96(%rdi)
	vzeroall
	lea		8(%r11),%rsp
.cfi_def_cfa		%rsp,8
	ret
.cfi_endproc
.size	poly1305_blocks_avx512,.-poly1305_blocks_avx512
.type	poly1305_init_base2_44,@function,3
.align	32
poly1305_init_base2_44:
.cfi_startproc
	xor	%rax,%rax
	mov	%rax,0(%rdi)		# initialize hash value
	mov	%rax,8(%rdi)
	mov	%rax,16(%rdi)

.Linit_base2_44:
	lea	poly1305_blocks_vpmadd52(%rip),%r10
	lea	poly1305_emit_base2_44(%rip),%r11

	mov	$0x0ffffffc0fffffff,%rax
	mov	$0x0ffffffc0ffffffc,%rcx
	and	0(%rsi),%rax
	mov	$0x00000fffffffffff,%r8
	and	8(%rsi),%rcx
	mov	$0x00000fffffffffff,%r9
	and	%rax,%r8
	shrd	$44,%rcx,%rax
	mov	%r8,40(%rdi)		# r0
	and	%r9,%rax
	shr	$24,%rcx
	mov	%rax,48(%rdi)		# r1
	lea	(%rax,%rax,4),%rax	# *5
	mov	%rcx,56(%rdi)		# r2
	shl	$2,%rax		# magic <<2
	lea	(%rcx,%rcx,4),%rcx	# *5
	shl	$2,%rcx		# magic <<2
	mov	%rax,24(%rdi)		# s1
	mov	%rcx,32(%rdi)		# s2
	movq	$-1,64(%rdi)		# write impossible value
	mov	%r10,0(%rdx)
	mov	%r11,8(%rdx)
	mov	$1,%eax
	ret
.cfi_endproc
.size	poly1305_init_base2_44,.-poly1305_init_base2_44
.type	poly1305_blocks_vpmadd52,@function,4
.align	32
poly1305_blocks_vpmadd52:
.cfi_startproc
	endbranch
	shr	$4,%rdx
	jz	.Lno_data_vpmadd52		# too short

	shl	$40,%rcx
	mov	64(%rdi),%r8			# peek on power of the key

	# if powers of the key are not calculated yet, process up to 3
	# blocks with this single-block subroutine, otherwise ensure that
	# length is divisible by 2 blocks and pass the rest down to next
	# subroutine...

	mov	$3,%rax
	mov	$1,%r10
	cmp	$4,%rdx			# is input long
	cmovae	%r10,%rax
	test	%r8,%r8				# is power value impossible?
	cmovns	%r10,%rax

	and	%rdx,%rax			# is input of favourable length?
	jz	.Lblocks_vpmadd52_4x

	sub		%rax,%rdx
	mov		$7,%r10d
	mov		$1,%r11d
	kmovw		%r10d,%k7
	lea		.L2_44_inp_permd(%rip),%r10
	kmovw		%r11d,%k1

	vmovq		%rcx,%xmm21
	vmovdqa64	0(%r10),%ymm19	# .L2_44_inp_permd
	vmovdqa64	32(%r10),%ymm20	# .L2_44_inp_shift
	vpermq		$0xcf,%ymm21,%ymm21
	vmovdqa64	64(%r10),%ymm22	# .L2_44_mask

	vmovdqu64	0(%rdi),%ymm16{%k7}{z}		# load hash value
	vmovdqu64	40(%rdi),%ymm3{%k7}{z}	# load keys
	vmovdqu64	32(%rdi),%ymm4{%k7}{z}
	vmovdqu64	24(%rdi),%ymm5{%k7}{z}

	vmovdqa64	96(%r10),%ymm23	# .L2_44_shift_rgt
	vmovdqa64	128(%r10),%ymm24	# .L2_44_shift_lft

	jmp		.Loop_vpmadd52

.align	32
.Loop_vpmadd52:
	vmovdqu32	0(%rsi),%xmm18		# load input as ----3210
	lea		16(%rsi),%rsi

	vpermd		%ymm18,%ymm19,%ymm18	# ----3210 -> --322110
	vpsrlvq		%ymm20,%ymm18,%ymm18
	vpandq		%ymm22,%ymm18,%ymm18
	vporq		%ymm21,%ymm18,%ymm18

	vpaddq		%ymm18,%ymm16,%ymm16		# accumulate input

	vpermq		$0,%ymm16,%ymm0{%k7}{z}	# smash hash value
	vpermq		$0b01010101,%ymm16,%ymm1{%k7}{z}
	vpermq		$0b10101010,%ymm16,%ymm2{%k7}{z}

	vpxord		%ymm16,%ymm16,%ymm16
	vpxord		%ymm17,%ymm17,%ymm17

	vpmadd52luq	%ymm3,%ymm0,%ymm16
	vpmadd52huq	%ymm3,%ymm0,%ymm17

	vpmadd52luq	%ymm4,%ymm1,%ymm16
	vpmadd52huq	%ymm4,%ymm1,%ymm17

	vpmadd52luq	%ymm5,%ymm2,%ymm16
	vpmadd52huq	%ymm5,%ymm2,%ymm17

	vpsrlvq		%ymm23,%ymm16,%ymm18	# 0 in topmost qword
	vpsllvq		%ymm24,%ymm17,%ymm17	# 0 in topmost qword
	vpandq		%ymm22,%ymm16,%ymm16

	vpaddq		%ymm18,%ymm17,%ymm17

	vpermq		$0b10010011,%ymm17,%ymm17	# 0 in lowest qword

	vpaddq		%ymm17,%ymm16,%ymm16		# note topmost qword :-)

	vpsrlvq		%ymm23,%ymm16,%ymm18	# 0 in topmost word
	vpandq		%ymm22,%ymm16,%ymm16

	vpermq		$0b10010011,%ymm18,%ymm18

	vpaddq		%ymm18,%ymm16,%ymm16

	vpermq		$0b10010011,%ymm16,%ymm18{%k1}{z}

	vpaddq		%ymm18,%ymm16,%ymm16
	vpsllq		$2,%ymm18,%ymm18

	vpaddq		%ymm18,%ymm16,%ymm16

	dec		%rax			# len-=16
	jnz		.Loop_vpmadd52

	vmovdqu64	%ymm16,0(%rdi){%k7}	# store hash value

	test		%rdx,%rdx
	jnz		.Lblocks_vpmadd52_4x

.Lno_data_vpmadd52:
	ret
.cfi_endproc
.size	poly1305_blocks_vpmadd52,.-poly1305_blocks_vpmadd52
.type	poly1305_blocks_vpmadd52_4x,@function,4
.align	32
poly1305_blocks_vpmadd52_4x:
.cfi_startproc
	shr	$4,%rdx
	jz	.Lno_data_vpmadd52_4x		# too short

	shl	$40,%rcx
	mov	64(%rdi),%r8			# peek on power of the key

.Lblocks_vpmadd52_4x:
	vpbroadcastq	%rcx,%ymm31

	vmovdqa64	.Lx_mask44(%rip),%ymm28
	mov		$5,%eax
	vmovdqa64	.Lx_mask42(%rip),%ymm29
	kmovw		%eax,%k1		# used in 2x path

	test		%r8,%r8			# is power value impossible?
	js		.Linit_vpmadd52		# if it is, then init R[4]

	vmovq		0(%rdi),%xmm0		# load current hash value
	vmovq		8(%rdi),%xmm1
	vmovq		16(%rdi),%xmm2

	test		$3,%rdx		# is length 4*n+2?
	jnz		.Lblocks_vpmadd52_2x_do

.Lblocks_vpmadd52_4x_do:
	vpbroadcastq	64(%rdi),%ymm3		# load 4th power of the key
	vpbroadcastq	96(%rdi),%ymm4
	vpbroadcastq	128(%rdi),%ymm5
	vpbroadcastq	160(%rdi),%ymm16

.Lblocks_vpmadd52_4x_key_loaded:
	vpsllq		$2,%ymm5,%ymm17		# S2 = R2*5*4
	vpaddq		%ymm5,%ymm17,%ymm17
	vpsllq		$2,%ymm17,%ymm17

	test		$7,%rdx		# is len 8*n?
	jz		.Lblocks_vpmadd52_8x

	vmovdqu64	16*0(%rsi),%ymm26		# load data
	vmovdqu64	16*2(%rsi),%ymm27
	lea		16*4(%rsi),%rsi

	vpunpcklqdq	%ymm27,%ymm26,%ymm25		# transpose data
	vpunpckhqdq	%ymm27,%ymm26,%ymm27

	# at this point 64-bit lanes are ordered as 3-1-2-0

	vpsrlq		$24,%ymm27,%ymm26		# splat the data
	vporq		%ymm31,%ymm26,%ymm26
	 vpaddq		%ymm26,%ymm2,%ymm2		# accumulate input
	vpandq		%ymm28,%ymm25,%ymm24
	vpsrlq		$44,%ymm25,%ymm25
	vpsllq		$20,%ymm27,%ymm27
	vporq		%ymm27,%ymm25,%ymm25
	vpandq		%ymm28,%ymm25,%ymm25

	sub		$4,%rdx
	jz		.Ltail_vpmadd52_4x
	jmp		.Loop_vpmadd52_4x
	ud2

.align	32
.Linit_vpmadd52:
	vmovq		24(%rdi),%xmm16		# load key
	vmovq		56(%rdi),%xmm2
	vmovq		32(%rdi),%xmm17
	vmovq		40(%rdi),%xmm3
	vmovq		48(%rdi),%xmm4

	vmovdqa		%ymm3,%ymm0
	vmovdqa		%ymm4,%ymm1
	vmovdqa		%ymm2,%ymm5

	mov		$2,%eax

.Lmul_init_vpmadd52:
	vpxorq		%ymm18,%ymm18,%ymm18
	vpmadd52luq	%ymm2,%ymm16,%ymm18
	vpxorq		%ymm19,%ymm19,%ymm19
	vpmadd52huq	%ymm2,%ymm16,%ymm19
	vpxorq		%ymm20,%ymm20,%ymm20
	vpmadd52luq	%ymm2,%ymm17,%ymm20
	vpxorq		%ymm21,%ymm21,%ymm21
	vpmadd52huq	%ymm2,%ymm17,%ymm21
	vpxorq		%ymm22,%ymm22,%ymm22
	vpmadd52luq	%ymm2,%ymm3,%ymm22
	vpxorq		%ymm23,%ymm23,%ymm23
	vpmadd52huq	%ymm2,%ymm3,%ymm23

	vpmadd52luq	%ymm0,%ymm3,%ymm18
	vpmadd52huq	%ymm0,%ymm3,%ymm19
	vpmadd52luq	%ymm0,%ymm4,%ymm20
	vpmadd52huq	%ymm0,%ymm4,%ymm21
	vpmadd52luq	%ymm0,%ymm5,%ymm22
	vpmadd52huq	%ymm0,%ymm5,%ymm23

	vpmadd52luq	%ymm1,%ymm17,%ymm18
	vpmadd52huq	%ymm1,%ymm17,%ymm19
	vpmadd52luq	%ymm1,%ymm3,%ymm20
	vpmadd52huq	%ymm1,%ymm3,%ymm21
	vpmadd52luq	%ymm1,%ymm4,%ymm22
	vpmadd52huq	%ymm1,%ymm4,%ymm23

	################################################################
	# partial reduction
	vpsrlq		$44,%ymm18,%ymm30
	vpsllq		$8,%ymm19,%ymm19
	vpandq		%ymm28,%ymm18,%ymm0
	vpaddq		%ymm30,%ymm19,%ymm19

	vpaddq		%ymm19,%ymm20,%ymm20

	vpsrlq		$44,%ymm20,%ymm30
	vpsllq		$8,%ymm21,%ymm21
	vpandq		%ymm28,%ymm20,%ymm1
	vpaddq		%ymm30,%ymm21,%ymm21

	vpaddq		%ymm21,%ymm22,%ymm22

	vpsrlq		$42,%ymm22,%ymm30
	vpsllq		$10,%ymm23,%ymm23
	vpandq		%ymm29,%ymm22,%ymm2
	vpaddq		%ymm30,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm0,%ymm0
	vpsllq		$2,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm0,%ymm0

	vpsrlq		$44,%ymm0,%ymm30		# additional step
	vpandq		%ymm28,%ymm0,%ymm0

	vpaddq		%ymm30,%ymm1,%ymm1

	dec		%eax
	jz		.Ldone_init_vpmadd52

	vpunpcklqdq	%ymm4,%ymm1,%ymm4		# 1,2
	vpbroadcastq	%xmm1,%xmm1		# 2,2
	vpunpcklqdq	%ymm5,%ymm2,%ymm5
	vpbroadcastq	%xmm2,%xmm2
	vpunpcklqdq	%ymm3,%ymm0,%ymm3
	vpbroadcastq	%xmm0,%xmm0

	vpsllq		$2,%ymm4,%ymm16		# S1 = R1*5*4
	vpsllq		$2,%ymm5,%ymm17		# S2 = R2*5*4
	vpaddq		%ymm4,%ymm16,%ymm16
	vpaddq		%ymm5,%ymm17,%ymm17
	vpsllq		$2,%ymm16,%ymm16
	vpsllq		$2,%ymm17,%ymm17

	jmp		.Lmul_init_vpmadd52
	ud2

.align	32
.Ldone_init_vpmadd52:
	vinserti128	$1,%xmm4,%ymm1,%ymm4	# 1,2,3,4
	vinserti128	$1,%xmm5,%ymm2,%ymm5
	vinserti128	$1,%xmm3,%ymm0,%ymm3

	vpermq		$0b11011000,%ymm4,%ymm4	# 1,3,2,4
	vpermq		$0b11011000,%ymm5,%ymm5
	vpermq		$0b11011000,%ymm3,%ymm3

	vpsllq		$2,%ymm4,%ymm16		# S1 = R1*5*4
	vpaddq		%ymm4,%ymm16,%ymm16
	vpsllq		$2,%ymm16,%ymm16

	vmovq		0(%rdi),%xmm0		# load current hash value
	vmovq		8(%rdi),%xmm1
	vmovq		16(%rdi),%xmm2

	test		$3,%rdx		# is length 4*n+2?
	jnz		.Ldone_init_vpmadd52_2x

	vmovdqu64	%ymm3,64(%rdi)		# save key powers
	vpbroadcastq	%xmm3,%ymm3		# broadcast 4th power
	vmovdqu64	%ymm4,96(%rdi)
	vpbroadcastq	%xmm4,%ymm4
	vmovdqu64	%ymm5,128(%rdi)
	vpbroadcastq	%xmm5,%ymm5
	vmovdqu64	%ymm16,160(%rdi)
	vpbroadcastq	%xmm16,%ymm16

	jmp		.Lblocks_vpmadd52_4x_key_loaded
	ud2

.align	32
.Ldone_init_vpmadd52_2x:
	vmovdqu64	%ymm3,64(%rdi)		# save key powers
	vpsrldq		$8,%ymm3,%ymm3		# 0-1-0-2
	vmovdqu64	%ymm4,96(%rdi)
	vpsrldq		$8,%ymm4,%ymm4
	vmovdqu64	%ymm5,128(%rdi)
	vpsrldq		$8,%ymm5,%ymm5
	vmovdqu64	%ymm16,160(%rdi)
	vpsrldq		$8,%ymm16,%ymm16
	jmp		.Lblocks_vpmadd52_2x_key_loaded
	ud2

.align	32
.Lblocks_vpmadd52_2x_do:
	vmovdqu64	128+8(%rdi),%ymm5{%k1}{z}# load 2nd and 1st key powers
	vmovdqu64	160+8(%rdi),%ymm16{%k1}{z}
	vmovdqu64	64+8(%rdi),%ymm3{%k1}{z}
	vmovdqu64	96+8(%rdi),%ymm4{%k1}{z}

.Lblocks_vpmadd52_2x_key_loaded:
	vmovdqu64	16*0(%rsi),%ymm26		# load data
	vpxorq		%ymm27,%ymm27,%ymm27
	lea		16*2(%rsi),%rsi

	vpunpcklqdq	%ymm27,%ymm26,%ymm25		# transpose data
	vpunpckhqdq	%ymm27,%ymm26,%ymm27

	# at this point 64-bit lanes are ordered as x-1-x-0

	vpsrlq		$24,%ymm27,%ymm26		# splat the data
	vporq		%ymm31,%ymm26,%ymm26
	 vpaddq		%ymm26,%ymm2,%ymm2		# accumulate input
	vpandq		%ymm28,%ymm25,%ymm24
	vpsrlq		$44,%ymm25,%ymm25
	vpsllq		$20,%ymm27,%ymm27
	vporq		%ymm27,%ymm25,%ymm25
	vpandq		%ymm28,%ymm25,%ymm25

	jmp		.Ltail_vpmadd52_2x
	ud2

.align	32
.Loop_vpmadd52_4x:
	#vpaddq		%ymm26,%ymm2,%ymm2		# accumulate input
	vpaddq		%ymm24,%ymm0,%ymm0
	vpaddq		%ymm25,%ymm1,%ymm1

	vpxorq		%ymm18,%ymm18,%ymm18
	vpmadd52luq	%ymm2,%ymm16,%ymm18
	vpxorq		%ymm19,%ymm19,%ymm19
	vpmadd52huq	%ymm2,%ymm16,%ymm19
	vpxorq		%ymm20,%ymm20,%ymm20
	vpmadd52luq	%ymm2,%ymm17,%ymm20
	vpxorq		%ymm21,%ymm21,%ymm21
	vpmadd52huq	%ymm2,%ymm17,%ymm21
	vpxorq		%ymm22,%ymm22,%ymm22
	vpmadd52luq	%ymm2,%ymm3,%ymm22
	vpxorq		%ymm23,%ymm23,%ymm23
	vpmadd52huq	%ymm2,%ymm3,%ymm23

	 vmovdqu64	16*0(%rsi),%ymm26		# load data
	 vmovdqu64	16*2(%rsi),%ymm27
	 lea		16*4(%rsi),%rsi
	vpmadd52luq	%ymm0,%ymm3,%ymm18
	vpmadd52huq	%ymm0,%ymm3,%ymm19
	vpmadd52luq	%ymm0,%ymm4,%ymm20
	vpmadd52huq	%ymm0,%ymm4,%ymm21
	vpmadd52luq	%ymm0,%ymm5,%ymm22
	vpmadd52huq	%ymm0,%ymm5,%ymm23

	 vpunpcklqdq	%ymm27,%ymm26,%ymm25		# transpose data
	 vpunpckhqdq	%ymm27,%ymm26,%ymm27
	vpmadd52luq	%ymm1,%ymm17,%ymm18
	vpmadd52huq	%ymm1,%ymm17,%ymm19
	vpmadd52luq	%ymm1,%ymm3,%ymm20
	vpmadd52huq	%ymm1,%ymm3,%ymm21
	vpmadd52luq	%ymm1,%ymm4,%ymm22
	vpmadd52huq	%ymm1,%ymm4,%ymm23

	################################################################
	# partial reduction (interleaved with data splat)
	vpsrlq		$44,%ymm18,%ymm30
	vpsllq		$8,%ymm19,%ymm19
	vpandq		%ymm28,%ymm18,%ymm0
	vpaddq		%ymm30,%ymm19,%ymm19

	 vpsrlq		$24,%ymm27,%ymm26
	 vporq		%ymm31,%ymm26,%ymm26
	vpaddq		%ymm19,%ymm20,%ymm20

	vpsrlq		$44,%ymm20,%ymm30
	vpsllq		$8,%ymm21,%ymm21
	vpandq		%ymm28,%ymm20,%ymm1
	vpaddq		%ymm30,%ymm21,%ymm21

	 vpandq		%ymm28,%ymm25,%ymm24
	 vpsrlq		$44,%ymm25,%ymm25
	 vpsllq		$20,%ymm27,%ymm27
	vpaddq		%ymm21,%ymm22,%ymm22

	vpsrlq		$42,%ymm22,%ymm30
	vpsllq		$10,%ymm23,%ymm23
	vpandq		%ymm29,%ymm22,%ymm2
	vpaddq		%ymm30,%ymm23,%ymm23

	  vpaddq	%ymm26,%ymm2,%ymm2		# accumulate input
	vpaddq		%ymm23,%ymm0,%ymm0
	vpsllq		$2,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm0,%ymm0
	 vporq		%ymm27,%ymm25,%ymm25
	 vpandq		%ymm28,%ymm25,%ymm25

	vpsrlq		$44,%ymm0,%ymm30		# additional step
	vpandq		%ymm28,%ymm0,%ymm0

	vpaddq		%ymm30,%ymm1,%ymm1

	sub		$4,%rdx		# len-=64
	jnz		.Loop_vpmadd52_4x

.Ltail_vpmadd52_4x:
	vmovdqu64	128(%rdi),%ymm5		# load all key powers
	vmovdqu64	160(%rdi),%ymm16
	vmovdqu64	64(%rdi),%ymm3
	vmovdqu64	96(%rdi),%ymm4

.Ltail_vpmadd52_2x:
	vpsllq		$2,%ymm5,%ymm17		# S2 = R2*5*4
	vpaddq		%ymm5,%ymm17,%ymm17
	vpsllq		$2,%ymm17,%ymm17

	#vpaddq		%ymm26,%ymm2,%ymm2		# accumulate input
	vpaddq		%ymm24,%ymm0,%ymm0
	vpaddq		%ymm25,%ymm1,%ymm1

	vpxorq		%ymm18,%ymm18,%ymm18
	vpmadd52luq	%ymm2,%ymm16,%ymm18
	vpxorq		%ymm19,%ymm19,%ymm19
	vpmadd52huq	%ymm2,%ymm16,%ymm19
	vpxorq		%ymm20,%ymm20,%ymm20
	vpmadd52luq	%ymm2,%ymm17,%ymm20
	vpxorq		%ymm21,%ymm21,%ymm21
	vpmadd52huq	%ymm2,%ymm17,%ymm21
	vpxorq		%ymm22,%ymm22,%ymm22
	vpmadd52luq	%ymm2,%ymm3,%ymm22
	vpxorq		%ymm23,%ymm23,%ymm23
	vpmadd52huq	%ymm2,%ymm3,%ymm23

	vpmadd52luq	%ymm0,%ymm3,%ymm18
	vpmadd52huq	%ymm0,%ymm3,%ymm19
	vpmadd52luq	%ymm0,%ymm4,%ymm20
	vpmadd52huq	%ymm0,%ymm4,%ymm21
	vpmadd52luq	%ymm0,%ymm5,%ymm22
	vpmadd52huq	%ymm0,%ymm5,%ymm23

	vpmadd52luq	%ymm1,%ymm17,%ymm18
	vpmadd52huq	%ymm1,%ymm17,%ymm19
	vpmadd52luq	%ymm1,%ymm3,%ymm20
	vpmadd52huq	%ymm1,%ymm3,%ymm21
	vpmadd52luq	%ymm1,%ymm4,%ymm22
	vpmadd52huq	%ymm1,%ymm4,%ymm23

	################################################################
	# horizontal addition

	mov		$1,%eax
	kmovw		%eax,%k1
	vpsrldq		$8,%ymm18,%ymm24
	vpsrldq		$8,%ymm19,%ymm0
	vpsrldq		$8,%ymm20,%ymm25
	vpsrldq		$8,%ymm21,%ymm1
	vpaddq		%ymm24,%ymm18,%ymm18
	vpaddq		%ymm0,%ymm19,%ymm19
	vpsrldq		$8,%ymm22,%ymm26
	vpsrldq		$8,%ymm23,%ymm2
	vpaddq		%ymm25,%ymm20,%ymm20
	vpaddq		%ymm1,%ymm21,%ymm21
	 vpermq		$0x2,%ymm18,%ymm24
	 vpermq		$0x2,%ymm19,%ymm0
	vpaddq		%ymm26,%ymm22,%ymm22
	vpaddq		%ymm2,%ymm23,%ymm23

	vpermq		$0x2,%ymm20,%ymm25
	vpermq		$0x2,%ymm21,%ymm1
	vpaddq		%ymm24,%ymm18,%ymm18{%k1}{z}
	vpaddq		%ymm0,%ymm19,%ymm19{%k1}{z}
	vpermq		$0x2,%ymm22,%ymm26
	vpermq		$0x2,%ymm23,%ymm2
	vpaddq		%ymm25,%ymm20,%ymm20{%k1}{z}
	vpaddq		%ymm1,%ymm21,%ymm21{%k1}{z}
	vpaddq		%ymm26,%ymm22,%ymm22{%k1}{z}
	vpaddq		%ymm2,%ymm23,%ymm23{%k1}{z}

	################################################################
	# partial reduction
	vpsrlq		$44,%ymm18,%ymm30
	vpsllq		$8,%ymm19,%ymm19
	vpandq		%ymm28,%ymm18,%ymm0
	vpaddq		%ymm30,%ymm19,%ymm19

	vpaddq		%ymm19,%ymm20,%ymm20

	vpsrlq		$44,%ymm20,%ymm30
	vpsllq		$8,%ymm21,%ymm21
	vpandq		%ymm28,%ymm20,%ymm1
	vpaddq		%ymm30,%ymm21,%ymm21

	vpaddq		%ymm21,%ymm22,%ymm22

	vpsrlq		$42,%ymm22,%ymm30
	vpsllq		$10,%ymm23,%ymm23
	vpandq		%ymm29,%ymm22,%ymm2
	vpaddq		%ymm30,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm0,%ymm0
	vpsllq		$2,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm0,%ymm0

	vpsrlq		$44,%ymm0,%ymm30		# additional step
	vpandq		%ymm28,%ymm0,%ymm0

	vpaddq		%ymm30,%ymm1,%ymm1
						# at this point %rdx is
						# either 4*n+2 or 0...
	sub		$2,%rdx		# len-=32
	ja		.Lblocks_vpmadd52_4x_do

	vmovq		%xmm0,0(%rdi)
	vmovq		%xmm1,8(%rdi)
	vmovq		%xmm2,16(%rdi)
	vzeroall

.Lno_data_vpmadd52_4x:
	ret
.cfi_endproc
.size	poly1305_blocks_vpmadd52_4x,.-poly1305_blocks_vpmadd52_4x
.type	poly1305_blocks_vpmadd52_8x,@function,4
.align	32
poly1305_blocks_vpmadd52_8x:
.cfi_startproc
	shr	$4,%rdx
	jz	.Lno_data_vpmadd52_8x		# too short

	shl	$40,%rcx
	mov	64(%rdi),%r8			# peek on power of the key

	vmovdqa64	.Lx_mask44(%rip),%ymm28
	vmovdqa64	.Lx_mask42(%rip),%ymm29

	test	%r8,%r8				# is power value impossible?
	js	.Linit_vpmadd52			# if it is, then init R[4]

	vmovq	0(%rdi),%xmm0			# load current hash value
	vmovq	8(%rdi),%xmm1
	vmovq	16(%rdi),%xmm2

.Lblocks_vpmadd52_8x:
	################################################################
	# fist we calculate more key powers

	vmovdqu64	128(%rdi),%ymm5		# load 1-3-2-4 powers
	vmovdqu64	160(%rdi),%ymm16
	vmovdqu64	64(%rdi),%ymm3
	vmovdqu64	96(%rdi),%ymm4

	vpsllq		$2,%ymm5,%ymm17		# S2 = R2*5*4
	vpaddq		%ymm5,%ymm17,%ymm17
	vpsllq		$2,%ymm17,%ymm17

	vpbroadcastq	%xmm5,%ymm8		# broadcast 4th power
	vpbroadcastq	%xmm3,%ymm6
	vpbroadcastq	%xmm4,%ymm7

	vpxorq		%ymm18,%ymm18,%ymm18
	vpmadd52luq	%ymm8,%ymm16,%ymm18
	vpxorq		%ymm19,%ymm19,%ymm19
	vpmadd52huq	%ymm8,%ymm16,%ymm19
	vpxorq		%ymm20,%ymm20,%ymm20
	vpmadd52luq	%ymm8,%ymm17,%ymm20
	vpxorq		%ymm21,%ymm21,%ymm21
	vpmadd52huq	%ymm8,%ymm17,%ymm21
	vpxorq		%ymm22,%ymm22,%ymm22
	vpmadd52luq	%ymm8,%ymm3,%ymm22
	vpxorq		%ymm23,%ymm23,%ymm23
	vpmadd52huq	%ymm8,%ymm3,%ymm23

	vpmadd52luq	%ymm6,%ymm3,%ymm18
	vpmadd52huq	%ymm6,%ymm3,%ymm19
	vpmadd52luq	%ymm6,%ymm4,%ymm20
	vpmadd52huq	%ymm6,%ymm4,%ymm21
	vpmadd52luq	%ymm6,%ymm5,%ymm22
	vpmadd52huq	%ymm6,%ymm5,%ymm23

	vpmadd52luq	%ymm7,%ymm17,%ymm18
	vpmadd52huq	%ymm7,%ymm17,%ymm19
	vpmadd52luq	%ymm7,%ymm3,%ymm20
	vpmadd52huq	%ymm7,%ymm3,%ymm21
	vpmadd52luq	%ymm7,%ymm4,%ymm22
	vpmadd52huq	%ymm7,%ymm4,%ymm23

	################################################################
	# partial reduction
	vpsrlq		$44,%ymm18,%ymm30
	vpsllq		$8,%ymm19,%ymm19
	vpandq		%ymm28,%ymm18,%ymm6
	vpaddq		%ymm30,%ymm19,%ymm19

	vpaddq		%ymm19,%ymm20,%ymm20

	vpsrlq		$44,%ymm20,%ymm30
	vpsllq		$8,%ymm21,%ymm21
	vpandq		%ymm28,%ymm20,%ymm7
	vpaddq		%ymm30,%ymm21,%ymm21

	vpaddq		%ymm21,%ymm22,%ymm22

	vpsrlq		$42,%ymm22,%ymm30
	vpsllq		$10,%ymm23,%ymm23
	vpandq		%ymm29,%ymm22,%ymm8
	vpaddq		%ymm30,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm6,%ymm6
	vpsllq		$2,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm6,%ymm6

	vpsrlq		$44,%ymm6,%ymm30		# additional step
	vpandq		%ymm28,%ymm6,%ymm6

	vpaddq		%ymm30,%ymm7,%ymm7

	################################################################
	# At this point Rx holds 1324 powers, RRx - 5768, and the goal
	# is 15263748, which reflects how data is loaded...

	vpunpcklqdq	%ymm5,%ymm8,%ymm26		# 3748
	vpunpckhqdq	%ymm5,%ymm8,%ymm5		# 1526
	vpunpcklqdq	%ymm3,%ymm6,%ymm24
	vpunpckhqdq	%ymm3,%ymm6,%ymm3
	vpunpcklqdq	%ymm4,%ymm7,%ymm25
	vpunpckhqdq	%ymm4,%ymm7,%ymm4
	vshufi64x2	$0x44,%zmm5,%zmm26,%zmm8	# 15263748
	vshufi64x2	$0x44,%zmm3,%zmm24,%zmm6
	vshufi64x2	$0x44,%zmm4,%zmm25,%zmm7

	vmovdqu64	16*0(%rsi),%zmm26		# load data
	vmovdqu64	16*4(%rsi),%zmm27
	lea		16*8(%rsi),%rsi

	vpsllq		$2,%zmm8,%zmm10		# S2 = R2*5*4
	vpsllq		$2,%zmm7,%zmm9		# S1 = R1*5*4
	vpaddq		%zmm8,%zmm10,%zmm10
	vpaddq		%zmm7,%zmm9,%zmm9
	vpsllq		$2,%zmm10,%zmm10
	vpsllq		$2,%zmm9,%zmm9

	vpbroadcastq	%rcx,%zmm31
	vpbroadcastq	%xmm28,%zmm28
	vpbroadcastq	%xmm29,%zmm29

	vpbroadcastq	%xmm9,%zmm16		# broadcast 8th power
	vpbroadcastq	%xmm10,%zmm17
	vpbroadcastq	%xmm6,%zmm3
	vpbroadcastq	%xmm7,%zmm4
	vpbroadcastq	%xmm8,%zmm5

	vpunpcklqdq	%zmm27,%zmm26,%zmm25		# transpose data
	vpunpckhqdq	%zmm27,%zmm26,%zmm27

	# at this point 64-bit lanes are ordered as 73625140

	vpsrlq		$24,%zmm27,%zmm26		# splat the data
	vporq		%zmm31,%zmm26,%zmm26
	 vpaddq		%zmm26,%zmm2,%zmm2		# accumulate input
	vpandq		%zmm28,%zmm25,%zmm24
	vpsrlq		$44,%zmm25,%zmm25
	vpsllq		$20,%zmm27,%zmm27
	vporq		%zmm27,%zmm25,%zmm25
	vpandq		%zmm28,%zmm25,%zmm25

	sub		$8,%rdx
	jz		.Ltail_vpmadd52_8x
	jmp		.Loop_vpmadd52_8x

.align	32
.Loop_vpmadd52_8x:
	#vpaddq		%zmm26,%zmm2,%zmm2		# accumulate input
	vpaddq		%zmm24,%zmm0,%zmm0
	vpaddq		%zmm25,%zmm1,%zmm1

	vpxorq		%zmm18,%zmm18,%zmm18
	vpmadd52luq	%zmm2,%zmm16,%zmm18
	vpxorq		%zmm19,%zmm19,%zmm19
	vpmadd52huq	%zmm2,%zmm16,%zmm19
	vpxorq		%zmm20,%zmm20,%zmm20
	vpmadd52luq	%zmm2,%zmm17,%zmm20
	vpxorq		%zmm21,%zmm21,%zmm21
	vpmadd52huq	%zmm2,%zmm17,%zmm21
	vpxorq		%zmm22,%zmm22,%zmm22
	vpmadd52luq	%zmm2,%zmm3,%zmm22
	vpxorq		%zmm23,%zmm23,%zmm23
	vpmadd52huq	%zmm2,%zmm3,%zmm23

	 vmovdqu64	16*0(%rsi),%zmm26		# load data
	 vmovdqu64	16*4(%rsi),%zmm27
	 lea		16*8(%rsi),%rsi
	vpmadd52luq	%zmm0,%zmm3,%zmm18
	vpmadd52huq	%zmm0,%zmm3,%zmm19
	vpmadd52luq	%zmm0,%zmm4,%zmm20
	vpmadd52huq	%zmm0,%zmm4,%zmm21
	vpmadd52luq	%zmm0,%zmm5,%zmm22
	vpmadd52huq	%zmm0,%zmm5,%zmm23

	 vpunpcklqdq	%zmm27,%zmm26,%zmm25		# transpose data
	 vpunpckhqdq	%zmm27,%zmm26,%zmm27
	vpmadd52luq	%zmm1,%zmm17,%zmm18
	vpmadd52huq	%zmm1,%zmm17,%zmm19
	vpmadd52luq	%zmm1,%zmm3,%zmm20
	vpmadd52huq	%zmm1,%zmm3,%zmm21
	vpmadd52luq	%zmm1,%zmm4,%zmm22
	vpmadd52huq	%zmm1,%zmm4,%zmm23

	################################################################
	# partial reduction (interleaved with data splat)
	vpsrlq		$44,%zmm18,%zmm30
	vpsllq		$8,%zmm19,%zmm19
	vpandq		%zmm28,%zmm18,%zmm0
	vpaddq		%zmm30,%zmm19,%zmm19

	 vpsrlq		$24,%zmm27,%zmm26
	 vporq		%zmm31,%zmm26,%zmm26
	vpaddq		%zmm19,%zmm20,%zmm20

	vpsrlq		$44,%zmm20,%zmm30
	vpsllq		$8,%zmm21,%zmm21
	vpandq		%zmm28,%zmm20,%zmm1
	vpaddq		%zmm30,%zmm21,%zmm21

	 vpandq		%zmm28,%zmm25,%zmm24
	 vpsrlq		$44,%zmm25,%zmm25
	 vpsllq		$20,%zmm27,%zmm27
	vpaddq		%zmm21,%zmm22,%zmm22

	vpsrlq		$42,%zmm22,%zmm30
	vpsllq		$10,%zmm23,%zmm23
	vpandq		%zmm29,%zmm22,%zmm2
	vpaddq		%zmm30,%zmm23,%zmm23

	  vpaddq	%zmm26,%zmm2,%zmm2		# accumulate input
	vpaddq		%zmm23,%zmm0,%zmm0
	vpsllq		$2,%zmm23,%zmm23

	vpaddq		%zmm23,%zmm0,%zmm0
	 vporq		%zmm27,%zmm25,%zmm25
	 vpandq		%zmm28,%zmm25,%zmm25

	vpsrlq		$44,%zmm0,%zmm30		# additional step
	vpandq		%zmm28,%zmm0,%zmm0

	vpaddq		%zmm30,%zmm1,%zmm1

	sub		$8,%rdx		# len-=128
	jnz		.Loop_vpmadd52_8x

.Ltail_vpmadd52_8x:
	#vpaddq		%zmm26,%zmm2,%zmm2		# accumulate input
	vpaddq		%zmm24,%zmm0,%zmm0
	vpaddq		%zmm25,%zmm1,%zmm1

	vpxorq		%zmm18,%zmm18,%zmm18
	vpmadd52luq	%zmm2,%zmm9,%zmm18
	vpxorq		%zmm19,%zmm19,%zmm19
	vpmadd52huq	%zmm2,%zmm9,%zmm19
	vpxorq		%zmm20,%zmm20,%zmm20
	vpmadd52luq	%zmm2,%zmm10,%zmm20
	vpxorq		%zmm21,%zmm21,%zmm21
	vpmadd52huq	%zmm2,%zmm10,%zmm21
	vpxorq		%zmm22,%zmm22,%zmm22
	vpmadd52luq	%zmm2,%zmm6,%zmm22
	vpxorq		%zmm23,%zmm23,%zmm23
	vpmadd52huq	%zmm2,%zmm6,%zmm23

	vpmadd52luq	%zmm0,%zmm6,%zmm18
	vpmadd52huq	%zmm0,%zmm6,%zmm19
	vpmadd52luq	%zmm0,%zmm7,%zmm20
	vpmadd52huq	%zmm0,%zmm7,%zmm21
	vpmadd52luq	%zmm0,%zmm8,%zmm22
	vpmadd52huq	%zmm0,%zmm8,%zmm23

	vpmadd52luq	%zmm1,%zmm10,%zmm18
	vpmadd52huq	%zmm1,%zmm10,%zmm19
	vpmadd52luq	%zmm1,%zmm6,%zmm20
	vpmadd52huq	%zmm1,%zmm6,%zmm21
	vpmadd52luq	%zmm1,%zmm7,%zmm22
	vpmadd52huq	%zmm1,%zmm7,%zmm23

	################################################################
	# horizontal addition

	mov		$1,%eax
	kmovw		%eax,%k1
	vpsrldq		$8,%zmm18,%zmm24
	vpsrldq		$8,%zmm19,%zmm0
	vpsrldq		$8,%zmm20,%zmm25
	vpsrldq		$8,%zmm21,%zmm1
	vpaddq		%zmm24,%zmm18,%zmm18
	vpaddq		%zmm0,%zmm19,%zmm19
	vpsrldq		$8,%zmm22,%zmm26
	vpsrldq		$8,%zmm23,%zmm2
	vpaddq		%zmm25,%zmm20,%zmm20
	vpaddq		%zmm1,%zmm21,%zmm21
	 vpermq		$0x2,%zmm18,%zmm24
	 vpermq		$0x2,%zmm19,%zmm0
	vpaddq		%zmm26,%zmm22,%zmm22
	vpaddq		%zmm2,%zmm23,%zmm23

	vpermq		$0x2,%zmm20,%zmm25
	vpermq		$0x2,%zmm21,%zmm1
	vpaddq		%zmm24,%zmm18,%zmm18
	vpaddq		%zmm0,%zmm19,%zmm19
	vpermq		$0x2,%zmm22,%zmm26
	vpermq		$0x2,%zmm23,%zmm2
	vpaddq		%zmm25,%zmm20,%zmm20
	vpaddq		%zmm1,%zmm21,%zmm21
	 vextracti64x4	$1,%zmm18,%ymm24
	 vextracti64x4	$1,%zmm19,%ymm0
	vpaddq		%zmm26,%zmm22,%zmm22
	vpaddq		%zmm2,%zmm23,%zmm23

	vextracti64x4	$1,%zmm20,%ymm25
	vextracti64x4	$1,%zmm21,%ymm1
	vextracti64x4	$1,%zmm22,%ymm26
	vextracti64x4	$1,%zmm23,%ymm2
	vpaddq		%ymm24,%ymm18,%ymm18{%k1}{z}
	vpaddq		%ymm0,%ymm19,%ymm19{%k1}{z}
	vpaddq		%ymm25,%ymm20,%ymm20{%k1}{z}
	vpaddq		%ymm1,%ymm21,%ymm21{%k1}{z}
	vpaddq		%ymm26,%ymm22,%ymm22{%k1}{z}
	vpaddq		%ymm2,%ymm23,%ymm23{%k1}{z}

	################################################################
	# partial reduction
	vpsrlq		$44,%ymm18,%ymm30
	vpsllq		$8,%ymm19,%ymm19
	vpandq		%ymm28,%ymm18,%ymm0
	vpaddq		%ymm30,%ymm19,%ymm19

	vpaddq		%ymm19,%ymm20,%ymm20

	vpsrlq		$44,%ymm20,%ymm30
	vpsllq		$8,%ymm21,%ymm21
	vpandq		%ymm28,%ymm20,%ymm1
	vpaddq		%ymm30,%ymm21,%ymm21

	vpaddq		%ymm21,%ymm22,%ymm22

	vpsrlq		$42,%ymm22,%ymm30
	vpsllq		$10,%ymm23,%ymm23
	vpandq		%ymm29,%ymm22,%ymm2
	vpaddq		%ymm30,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm0,%ymm0
	vpsllq		$2,%ymm23,%ymm23

	vpaddq		%ymm23,%ymm0,%ymm0

	vpsrlq		$44,%ymm0,%ymm30		# additional step
	vpandq		%ymm28,%ymm0,%ymm0

	vpaddq		%ymm30,%ymm1,%ymm1

	################################################################

	vmovq		%xmm0,0(%rdi)
	vmovq		%xmm1,8(%rdi)
	vmovq		%xmm2,16(%rdi)
	vzeroall

.Lno_data_vpmadd52_8x:
	ret
.cfi_endproc
.size	poly1305_blocks_vpmadd52_8x,.-poly1305_blocks_vpmadd52_8x
.type	poly1305_emit_base2_44,@function,3
.align	32
poly1305_emit_base2_44:
.cfi_startproc
	endbranch
	mov	0(%rdi),%r8	# load hash value
	mov	8(%rdi),%r9
	mov	16(%rdi),%r10

	mov	%r9,%rax
	shr	$20,%r9
	shl	$44,%rax
	mov	%r10,%rcx
	shr	$40,%r10
	shl	$24,%rcx

	add	%rax,%r8
	adc	%rcx,%r9
	adc	$0,%r10

	mov	%r8,%rax
	add	$5,%r8		# compare to modulus
	mov	%r9,%rcx
	adc	$0,%r9
	adc	$0,%r10
	shr	$2,%r10	# did 130-bit value overflow?
	cmovnz	%r8,%rax
	cmovnz	%r9,%rcx

	add	0(%rdx),%rax	# accumulate nonce
	adc	8(%rdx),%rcx
	mov	%rax,0(%rsi)	# write result
	mov	%rcx,8(%rsi)

	ret
.cfi_endproc
.size	poly1305_emit_base2_44,.-poly1305_emit_base2_44
.section .rodata align=64
.align	64
.Lconst:
.Lmask24:
.long	0x0ffffff,0,0x0ffffff,0,0x0ffffff,0,0x0ffffff,0
.L129:
.long	16777216,0,16777216,0,16777216,0,16777216,0
.Lmask26:
.long	0x3ffffff,0,0x3ffffff,0,0x3ffffff,0,0x3ffffff,0
.Lpermd_avx2:
.long	2,2,2,3,2,0,2,1
.Lpermd_avx512:
.long	0,0,0,1, 0,2,0,3, 0,4,0,5, 0,6,0,7

.L2_44_inp_permd:
.long	0,1,1,2,2,3,7,7
.L2_44_inp_shift:
.quad	0,12,24,64
.L2_44_mask:
.quad	0xfffffffffff,0xfffffffffff,0x3ffffffffff,0xffffffffffffffff
.L2_44_shift_rgt:
.quad	44,44,42,64
.L2_44_shift_lft:
.quad	8,8,10,64

.align	64
.Lx_mask44:
.quad	0xfffffffffff,0xfffffffffff,0xfffffffffff,0xfffffffffff
.quad	0xfffffffffff,0xfffffffffff,0xfffffffffff,0xfffffffffff
.Lx_mask42:
.quad	0x3ffffffffff,0x3ffffffffff,0x3ffffffffff,0x3ffffffffff
.quad	0x3ffffffffff,0x3ffffffffff,0x3ffffffffff,0x3ffffffffff
.previous
.asciz	"Poly1305 for x86_64, CRYPTOGAMS by <appro@openssl.org>"
.align	16
.globl	xor128_encrypt_n_pad
.type	xor128_encrypt_n_pad,@abi-omnipotent
.align	16
xor128_encrypt_n_pad:
.cfi_startproc
	sub	%rdx,%rsi
	sub	%rdx,%rdi
	mov	%rcx,%r10		# put len aside
	shr	$4,%rcx		# len / 16
	jz	.Ltail_enc
	nop
.Loop_enc_xmm:
	movdqu	(%rsi,%rdx),%xmm0
	pxor	(%rdx),%xmm0
	movdqu	%xmm0,(%rdi,%rdx)
	movdqa	%xmm0,(%rdx)
	lea	16(%rdx),%rdx
	dec	%rcx
	jnz	.Loop_enc_xmm

	and	$15,%r10		# len % 16
	jz	.Ldone_enc

.Ltail_enc:
	mov	$16,%rcx
	sub	%r10,%rcx
	xor	%eax,%eax
.Loop_enc_byte:
	mov	(%rsi,%rdx),%al
	xor	(%rdx),%al
	mov	%al,(%rdi,%rdx)
	mov	%al,(%rdx)
	lea	1(%rdx),%rdx
	dec	%r10
	jnz	.Loop_enc_byte

	xor	%eax,%eax
.Loop_enc_pad:
	mov	%al,(%rdx)
	lea	1(%rdx),%rdx
	dec	%rcx
	jnz	.Loop_enc_pad

.Ldone_enc:
	mov	%rdx,%rax
	ret
.cfi_endproc
.size	xor128_encrypt_n_pad,.-xor128_encrypt_n_pad

.globl	xor128_decrypt_n_pad
.type	xor128_decrypt_n_pad,@abi-omnipotent
.align	16
xor128_decrypt_n_pad:
.cfi_startproc
	sub	%rdx,%rsi
	sub	%rdx,%rdi
	mov	%rcx,%r10		# put len aside
	shr	$4,%rcx		# len / 16
	jz	.Ltail_dec
	nop
.Loop_dec_xmm:
	movdqu	(%rsi,%rdx),%xmm0
	movdqa	(%rdx),%xmm1
	pxor	%xmm0,%xmm1
	movdqu	%xmm1,(%rdi,%rdx)
	movdqa	%xmm0,(%rdx)
	lea	16(%rdx),%rdx
	dec	%rcx
	jnz	.Loop_dec_xmm

	pxor	%xmm1,%xmm1
	and	$15,%r10		# len % 16
	jz	.Ldone_dec

.Ltail_dec:
	mov	$16,%rcx
	sub	%r10,%rcx
	xor	%eax,%eax
	xor	%r11,%r11
.Loop_dec_byte:
	mov	(%rsi,%rdx),%r11b
	mov	(%rdx),%al
	xor	%r11b,%al
	mov	%al,(%rdi,%rdx)
	mov	%r11b,(%rdx)
	lea	1(%rdx),%rdx
	dec	%r10
	jnz	.Loop_dec_byte

	xor	%eax,%eax
.Loop_dec_pad:
	mov	%al,(%rdx)
	lea	1(%rdx),%rdx
	dec	%rcx
	jnz	.Loop_dec_pad

.Ldone_dec:
	mov	%rdx,%rax
	ret
.cfi_endproc
.size	xor128_decrypt_n_pad,.-xor128_decrypt_n_pad
`;

export default translateAssembly(code);
