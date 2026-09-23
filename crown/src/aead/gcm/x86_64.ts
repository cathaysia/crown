/**
 * AES-NI-CTR+GHASH stitch (GCM) for x86_64.
 *
 * TypeScript port of OpenSSL crypto/modes/asm/aesni-gcm-x86_64.pl.
 * Copyright 2013-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $avx=2, $win64=0 (unix SysV
 * argument registers; the Win64 SEH handlers are omitted). The perl
 * probes the assembler; $avx=2 emits the full _aesni_ctr32_ghash_6x
 * stitch used by aesni_gcm_encrypt/aesni_gcm_decrypt.
 *
 * Register map (from the perl):
 *   inp=%rdi out=%rsi len=%rdx key=%rcx ivp=%r8 Xip=%r9
 *   xmm0..xmm8 = Ii,T1,T2,Hkey,Z0,Z1,Z2,Z3,Xi
 *   xmm9..xmm15 = inout0..inout5,rndkey
 *   ebx=counter ebp=rounds r10=ret r11=const r14=in0 r15=end0
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text

.type	_aesni_ctr32_ghash_6x,@abi-omnipotent
.align	32
_aesni_ctr32_ghash_6x:
.cfi_startproc
	vmovdqu		0x20(%r11),%xmm2	# borrow %xmm2, .Lone_msb
	sub		$6,%rdx
	vpxor		%xmm4,%xmm4,%xmm4		# %xmm4   = 0
	vmovdqu		0x00-0x80(%rcx),%xmm15
	vpaddb		%xmm2,%xmm1,%xmm10
	vpaddb		%xmm2,%xmm10,%xmm11
	vpaddb		%xmm2,%xmm11,%xmm12
	vpaddb		%xmm2,%xmm12,%xmm13
	vpaddb		%xmm2,%xmm13,%xmm14
	vpxor		%xmm15,%xmm1,%xmm9
	vmovdqu		%xmm4,16+8(%rsp)		# "%xmm7" = 0
	jmp		.Loop6x

.align	32
.Loop6x:
	add		$100663296,%ebx
	jc		.Lhandle_ctr32		# discard ?
	vmovdqu		0x00-0x20(%r9),%xmm3	# %xmm3^1
	  vpaddb	%xmm2,%xmm14,%xmm1		# next counter value
	  vpxor		%xmm15,%xmm10,%xmm10
	  vpxor		%xmm15,%xmm11,%xmm11

.Lresume_ctr32:
	vmovdqu		%xmm1,(%r8)		# save next counter value
	vpclmulqdq	$0x10,%xmm3,%xmm7,%xmm5
	  vpxor		%xmm15,%xmm12,%xmm12
	  vmovups	0x10-0x80(%rcx),%xmm2	# borrow %xmm2 for %xmm15
	vpclmulqdq	$0x01,%xmm3,%xmm7,%xmm6
	xor		%r12,%r12
	cmp		%r14,%r15

	  vaesenc	%xmm2,%xmm9,%xmm9
	vmovdqu		0x30+8(%rsp),%xmm0	# I[4]
	  vpxor		%xmm15,%xmm13,%xmm13
	vpclmulqdq	$0x00,%xmm3,%xmm7,%xmm1
	  vaesenc	%xmm2,%xmm10,%xmm10
	  vpxor		%xmm15,%xmm14,%xmm14
	setnc		%r12b
	vpclmulqdq	$0x11,%xmm3,%xmm7,%xmm7
	  vaesenc	%xmm2,%xmm11,%xmm11
	vmovdqu		0x10-0x20(%r9),%xmm3	# %xmm3^2
	neg		%r12
	  vaesenc	%xmm2,%xmm12,%xmm12
	 vpxor		%xmm5,%xmm6,%xmm6
	vpclmulqdq	$0x00,%xmm3,%xmm0,%xmm5
	 vpxor		%xmm4,%xmm8,%xmm8		# modulo-scheduled
	  vaesenc	%xmm2,%xmm13,%xmm13
	 vpxor		%xmm5,%xmm1,%xmm4
	and		$0x60,%r12
	  vmovups	0x20-0x80(%rcx),%xmm15
	vpclmulqdq	$0x10,%xmm3,%xmm0,%xmm1
	  vaesenc	%xmm2,%xmm14,%xmm14

	vpclmulqdq	$0x01,%xmm3,%xmm0,%xmm2
	lea		(%r14,%r12),%r14
	  vaesenc	%xmm15,%xmm9,%xmm9
	 vpxor		16+8(%rsp),%xmm8,%xmm8	# modulo-scheduled [vpxor %xmm7,%xmm8,%xmm8]
	vpclmulqdq	$0x11,%xmm3,%xmm0,%xmm3
	 vmovdqu	0x40+8(%rsp),%xmm0	# I[3]
	  vaesenc	%xmm15,%xmm10,%xmm10
	movbe		0x58(%r14),%r13
	  vaesenc	%xmm15,%xmm11,%xmm11
	movbe		0x50(%r14),%r12
	  vaesenc	%xmm15,%xmm12,%xmm12
	mov		%r13,0x20+8(%rsp)
	  vaesenc	%xmm15,%xmm13,%xmm13
	mov		%r12,0x28+8(%rsp)
	vmovdqu		0x30-0x20(%r9),%xmm5	# borrow %xmm5 for %xmm3^3
	  vaesenc	%xmm15,%xmm14,%xmm14

	  vmovups	0x30-0x80(%rcx),%xmm15
	 vpxor		%xmm1,%xmm6,%xmm6
	vpclmulqdq	$0x00,%xmm5,%xmm0,%xmm1
	  vaesenc	%xmm15,%xmm9,%xmm9
	 vpxor		%xmm2,%xmm6,%xmm6
	vpclmulqdq	$0x10,%xmm5,%xmm0,%xmm2
	  vaesenc	%xmm15,%xmm10,%xmm10
	 vpxor		%xmm3,%xmm7,%xmm7
	vpclmulqdq	$0x01,%xmm5,%xmm0,%xmm3
	  vaesenc	%xmm15,%xmm11,%xmm11
	vpclmulqdq	$0x11,%xmm5,%xmm0,%xmm5
	 vmovdqu	0x50+8(%rsp),%xmm0	# I[2]
	  vaesenc	%xmm15,%xmm12,%xmm12
	  vaesenc	%xmm15,%xmm13,%xmm13
	 vpxor		%xmm1,%xmm4,%xmm4
	vmovdqu		0x40-0x20(%r9),%xmm1	# borrow %xmm1 for %xmm3^4
	  vaesenc	%xmm15,%xmm14,%xmm14

	  vmovups	0x40-0x80(%rcx),%xmm15
	 vpxor		%xmm2,%xmm6,%xmm6
	vpclmulqdq	$0x00,%xmm1,%xmm0,%xmm2
	  vaesenc	%xmm15,%xmm9,%xmm9
	 vpxor		%xmm3,%xmm6,%xmm6
	vpclmulqdq	$0x10,%xmm1,%xmm0,%xmm3
	  vaesenc	%xmm15,%xmm10,%xmm10
	movbe		0x48(%r14),%r13
	 vpxor		%xmm5,%xmm7,%xmm7
	vpclmulqdq	$0x01,%xmm1,%xmm0,%xmm5
	  vaesenc	%xmm15,%xmm11,%xmm11
	movbe		0x40(%r14),%r12
	vpclmulqdq	$0x11,%xmm1,%xmm0,%xmm1
	 vmovdqu	0x60+8(%rsp),%xmm0	# I[1]
	  vaesenc	%xmm15,%xmm12,%xmm12
	mov		%r13,0x30+8(%rsp)
	  vaesenc	%xmm15,%xmm13,%xmm13
	mov		%r12,0x38+8(%rsp)
	 vpxor		%xmm2,%xmm4,%xmm4
	vmovdqu		0x60-0x20(%r9),%xmm2	# borrow %xmm2 for %xmm3^5
	  vaesenc	%xmm15,%xmm14,%xmm14

	  vmovups	0x50-0x80(%rcx),%xmm15
	 vpxor		%xmm3,%xmm6,%xmm6
	vpclmulqdq	$0x00,%xmm2,%xmm0,%xmm3
	  vaesenc	%xmm15,%xmm9,%xmm9
	 vpxor		%xmm5,%xmm6,%xmm6
	vpclmulqdq	$0x10,%xmm2,%xmm0,%xmm5
	  vaesenc	%xmm15,%xmm10,%xmm10
	movbe		0x38(%r14),%r13
	 vpxor		%xmm1,%xmm7,%xmm7
	vpclmulqdq	$0x01,%xmm2,%xmm0,%xmm1
	 vpxor		0x70+8(%rsp),%xmm8,%xmm8	# accumulate I[0]
	  vaesenc	%xmm15,%xmm11,%xmm11
	movbe		0x30(%r14),%r12
	vpclmulqdq	$0x11,%xmm2,%xmm0,%xmm2
	  vaesenc	%xmm15,%xmm12,%xmm12
	mov		%r13,0x40+8(%rsp)
	  vaesenc	%xmm15,%xmm13,%xmm13
	mov		%r12,0x48+8(%rsp)
	 vpxor		%xmm3,%xmm4,%xmm4
	 vmovdqu	0x70-0x20(%r9),%xmm3	# %xmm3^6
	  vaesenc	%xmm15,%xmm14,%xmm14

	  vmovups	0x60-0x80(%rcx),%xmm15
	 vpxor		%xmm5,%xmm6,%xmm6
	vpclmulqdq	$0x10,%xmm3,%xmm8,%xmm5
	  vaesenc	%xmm15,%xmm9,%xmm9
	 vpxor		%xmm1,%xmm6,%xmm6
	vpclmulqdq	$0x01,%xmm3,%xmm8,%xmm1
	  vaesenc	%xmm15,%xmm10,%xmm10
	movbe		0x28(%r14),%r13
	 vpxor		%xmm2,%xmm7,%xmm7
	vpclmulqdq	$0x00,%xmm3,%xmm8,%xmm2
	  vaesenc	%xmm15,%xmm11,%xmm11
	movbe		0x20(%r14),%r12
	vpclmulqdq	$0x11,%xmm3,%xmm8,%xmm8
	  vaesenc	%xmm15,%xmm12,%xmm12
	mov		%r13,0x50+8(%rsp)
	  vaesenc	%xmm15,%xmm13,%xmm13
	mov		%r12,0x58+8(%rsp)
	vpxor		%xmm5,%xmm6,%xmm6
	  vaesenc	%xmm15,%xmm14,%xmm14
	vpxor		%xmm1,%xmm6,%xmm6

	  vmovups	0x70-0x80(%rcx),%xmm15
	vpslldq		$8,%xmm6,%xmm5
	vpxor		%xmm2,%xmm4,%xmm4
	vmovdqu		0x10(%r11),%xmm3	# .Lpoly

	  vaesenc	%xmm15,%xmm9,%xmm9
	vpxor		%xmm8,%xmm7,%xmm7
	  vaesenc	%xmm15,%xmm10,%xmm10
	vpxor		%xmm5,%xmm4,%xmm4
	movbe		0x18(%r14),%r13
	  vaesenc	%xmm15,%xmm11,%xmm11
	movbe		0x10(%r14),%r12
	vpalignr	$8,%xmm4,%xmm4,%xmm0		# 1st phase
	vpclmulqdq	$0x10,%xmm3,%xmm4,%xmm4
	mov		%r13,0x60+8(%rsp)
	  vaesenc	%xmm15,%xmm12,%xmm12
	mov		%r12,0x68+8(%rsp)
	  vaesenc	%xmm15,%xmm13,%xmm13
	  vmovups	0x80-0x80(%rcx),%xmm1	# borrow %xmm1 for %xmm15
	  vaesenc	%xmm15,%xmm14,%xmm14

	  vaesenc	%xmm1,%xmm9,%xmm9
	  vmovups	0x90-0x80(%rcx),%xmm15
	  vaesenc	%xmm1,%xmm10,%xmm10
	vpsrldq		$8,%xmm6,%xmm6
	  vaesenc	%xmm1,%xmm11,%xmm11
	vpxor		%xmm6,%xmm7,%xmm7
	  vaesenc	%xmm1,%xmm12,%xmm12
	vpxor		%xmm0,%xmm4,%xmm4
	movbe		0x08(%r14),%r13
	  vaesenc	%xmm1,%xmm13,%xmm13
	movbe		0x00(%r14),%r12
	  vaesenc	%xmm1,%xmm14,%xmm14
	  vmovups	0xa0-0x80(%rcx),%xmm1
	  cmp		$11,%ebp
	  jb		.Lenc_tail		# 128-bit key

	  vaesenc	%xmm15,%xmm9,%xmm9
	  vaesenc	%xmm15,%xmm10,%xmm10
	  vaesenc	%xmm15,%xmm11,%xmm11
	  vaesenc	%xmm15,%xmm12,%xmm12
	  vaesenc	%xmm15,%xmm13,%xmm13
	  vaesenc	%xmm15,%xmm14,%xmm14

	  vaesenc	%xmm1,%xmm9,%xmm9
	  vaesenc	%xmm1,%xmm10,%xmm10
	  vaesenc	%xmm1,%xmm11,%xmm11
	  vaesenc	%xmm1,%xmm12,%xmm12
	  vaesenc	%xmm1,%xmm13,%xmm13
	  vmovups	0xb0-0x80(%rcx),%xmm15
	  vaesenc	%xmm1,%xmm14,%xmm14
	  vmovups	0xc0-0x80(%rcx),%xmm1
	  je		.Lenc_tail		# 192-bit key

	  vaesenc	%xmm15,%xmm9,%xmm9
	  vaesenc	%xmm15,%xmm10,%xmm10
	  vaesenc	%xmm15,%xmm11,%xmm11
	  vaesenc	%xmm15,%xmm12,%xmm12
	  vaesenc	%xmm15,%xmm13,%xmm13
	  vaesenc	%xmm15,%xmm14,%xmm14

	  vaesenc	%xmm1,%xmm9,%xmm9
	  vaesenc	%xmm1,%xmm10,%xmm10
	  vaesenc	%xmm1,%xmm11,%xmm11
	  vaesenc	%xmm1,%xmm12,%xmm12
	  vaesenc	%xmm1,%xmm13,%xmm13
	  vmovups	0xd0-0x80(%rcx),%xmm15
	  vaesenc	%xmm1,%xmm14,%xmm14
	  vmovups	0xe0-0x80(%rcx),%xmm1
	  jmp		.Lenc_tail		# 256-bit key

.align	32
.Lhandle_ctr32:
	vmovdqu		(%r11),%xmm0		# borrow %xmm0 for .Lbswap_mask
	  vpshufb	%xmm0,%xmm1,%xmm6		# byte-swap counter
	  vmovdqu	0x30(%r11),%xmm5	# borrow %xmm5, .Ltwo_lsb
	  vpaddd	0x40(%r11),%xmm6,%xmm10	# .Lone_lsb
	  vpaddd	%xmm5,%xmm6,%xmm11
	vmovdqu		0x00-0x20(%r9),%xmm3	# %xmm3^1
	  vpaddd	%xmm5,%xmm10,%xmm12
	  vpshufb	%xmm0,%xmm10,%xmm10
	  vpaddd	%xmm5,%xmm11,%xmm13
	  vpshufb	%xmm0,%xmm11,%xmm11
	  vpxor		%xmm15,%xmm10,%xmm10
	  vpaddd	%xmm5,%xmm12,%xmm14
	  vpshufb	%xmm0,%xmm12,%xmm12
	  vpxor		%xmm15,%xmm11,%xmm11
	  vpaddd	%xmm5,%xmm13,%xmm1		# byte-swapped next counter value
	  vpshufb	%xmm0,%xmm13,%xmm13
	  vpshufb	%xmm0,%xmm14,%xmm14
	  vpshufb	%xmm0,%xmm1,%xmm1		# next counter value
	jmp		.Lresume_ctr32

.align	32
.Lenc_tail:
	  vaesenc	%xmm15,%xmm9,%xmm9
	vmovdqu		%xmm7,16+8(%rsp)		# postpone vpxor %xmm7,%xmm8,%xmm8
	vpalignr	$8,%xmm4,%xmm4,%xmm8		# 2nd phase
	  vaesenc	%xmm15,%xmm10,%xmm10
	vpclmulqdq	$0x10,%xmm3,%xmm4,%xmm4
	  vpxor		0x00(%rdi),%xmm1,%xmm2
	  vaesenc	%xmm15,%xmm11,%xmm11
	  vpxor		0x10(%rdi),%xmm1,%xmm0
	  vaesenc	%xmm15,%xmm12,%xmm12
	  vpxor		0x20(%rdi),%xmm1,%xmm5
	  vaesenc	%xmm15,%xmm13,%xmm13
	  vpxor		0x30(%rdi),%xmm1,%xmm6
	  vaesenc	%xmm15,%xmm14,%xmm14
	  vpxor		0x40(%rdi),%xmm1,%xmm7
	  vpxor		0x50(%rdi),%xmm1,%xmm3
	  vmovdqu	(%r8),%xmm1		# load next counter value

	  vaesenclast	%xmm2,%xmm9,%xmm9
	  vmovdqu	0x20(%r11),%xmm2	# borrow %xmm2, .Lone_msb
	  vaesenclast	%xmm0,%xmm10,%xmm10
	 vpaddb		%xmm2,%xmm1,%xmm0
	mov		%r13,0x70+8(%rsp)
	lea		0x60(%rdi),%rdi
	  vaesenclast	%xmm5,%xmm11,%xmm11
	 vpaddb		%xmm2,%xmm0,%xmm5
	mov		%r12,0x78+8(%rsp)
	lea		0x60(%rsi),%rsi
	  vmovdqu	0x00-0x80(%rcx),%xmm15
	  vaesenclast	%xmm6,%xmm12,%xmm12
	 vpaddb		%xmm2,%xmm5,%xmm6
	  vaesenclast	%xmm7, %xmm13,%xmm13
	 vpaddb		%xmm2,%xmm6,%xmm7
	  vaesenclast	%xmm3,%xmm14,%xmm14
	 vpaddb		%xmm2,%xmm7,%xmm3

	add		$0x60,%r10
	sub		$0x6,%rdx
	jc		.L6x_done

	  vmovups	%xmm9,-0x60(%rsi)	# save output
	 vpxor		%xmm15,%xmm1,%xmm9
	  vmovups	%xmm10,-0x50(%rsi)
	 vmovdqa	%xmm0,%xmm10		# 0 latency
	  vmovups	%xmm11,-0x40(%rsi)
	 vmovdqa	%xmm5,%xmm11		# 0 latency
	  vmovups	%xmm12,-0x30(%rsi)
	 vmovdqa	%xmm6,%xmm12		# 0 latency
	  vmovups	%xmm13,-0x20(%rsi)
	 vmovdqa	%xmm7,%xmm13		# 0 latency
	  vmovups	%xmm14,-0x10(%rsi)
	 vmovdqa	%xmm3,%xmm14		# 0 latency
	vmovdqu		0x20+8(%rsp),%xmm7	# I[5]
	jmp		.Loop6x

.L6x_done:
	vpxor		16+8(%rsp),%xmm8,%xmm8	# modulo-scheduled
	vpxor		%xmm4,%xmm8,%xmm8		# modulo-scheduled

	ret
.cfi_endproc
.size	_aesni_ctr32_ghash_6x,.-_aesni_ctr32_ghash_6x
.globl	aesni_gcm_decrypt
.type	aesni_gcm_decrypt,@function,6
.align	32
aesni_gcm_decrypt:
.cfi_startproc
	xor	%r10,%r10
	cmp	$0x60,%rdx			# minimal accepted length
	jb	.Lgcm_dec_abort

	lea	(%rsp),%rax			# save stack pointer
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
	vzeroupper

	vmovdqu		(%r8),%xmm1		# input counter value
	add		$-128,%rsp
	mov		12(%r8),%ebx
	lea		.Lbswap_mask(%rip),%r11
	lea		-0x80(%rcx),%r14	# borrow %r14
	mov		$0xf80,%r15		# borrow %r15
	vmovdqu		(%r9),%xmm8		# load Xi
	and		$-128,%rsp		# ensure stack alignment
	vmovdqu		(%r11),%xmm0		# borrow %xmm0 for .Lbswap_mask
	lea		0x80(%rcx),%rcx		# size optimization
	lea		0x20+0x20(%r9),%r9	# size optimization
	mov		0xf0-0x80(%rcx),%ebp
	vpshufb		%xmm0,%xmm8,%xmm8

	and		%r15,%r14
	and		%rsp,%r15
	sub		%r14,%r15
	jc		.Ldec_no_key_aliasing
	cmp		$768,%r15
	jnc		.Ldec_no_key_aliasing
	sub		%r15,%rsp		# avoid aliasing with key
.Ldec_no_key_aliasing:

	vmovdqu		0x50(%rdi),%xmm7		# I[5]
	lea		(%rdi),%r14
	vmovdqu		0x40(%rdi),%xmm4
	lea		-0xc0(%rdi,%rdx),%r15
	vmovdqu		0x30(%rdi),%xmm5
	shr		$4,%rdx
	xor		%r10,%r10
	vmovdqu		0x20(%rdi),%xmm6
	 vpshufb	%xmm0,%xmm7,%xmm7		# passed to _aesni_ctr32_ghash_6x
	vmovdqu		0x10(%rdi),%xmm2
	 vpshufb	%xmm0,%xmm4,%xmm4
	vmovdqu		(%rdi),%xmm3
	 vpshufb	%xmm0,%xmm5,%xmm5
	vmovdqu		%xmm4,0x30(%rsp)
	 vpshufb	%xmm0,%xmm6,%xmm6
	vmovdqu		%xmm5,0x40(%rsp)
	 vpshufb	%xmm0,%xmm2,%xmm2
	vmovdqu		%xmm6,0x50(%rsp)
	 vpshufb	%xmm0,%xmm3,%xmm3
	vmovdqu		%xmm2,0x60(%rsp)
	vmovdqu		%xmm3,0x70(%rsp)

	call		_aesni_ctr32_ghash_6x

	vmovups		%xmm9,-0x60(%rsi)	# save output
	vmovups		%xmm10,-0x50(%rsi)
	vmovups		%xmm11,-0x40(%rsi)
	vmovups		%xmm12,-0x30(%rsi)
	vmovups		%xmm13,-0x20(%rsi)
	vmovups		%xmm14,-0x10(%rsi)

	vpshufb		(%r11),%xmm8,%xmm8	# .Lbswap_mask
	vmovdqu		%xmm8,-0x40(%r9)		# output Xi

	vzeroupper
	mov	-48(%rax),%r15
.cfi_restore	%r15
	mov	-40(%rax),%r14
.cfi_restore	%r14
	mov	-32(%rax),%r13
.cfi_restore	%r13
	mov	-24(%rax),%r12
.cfi_restore	%r12
	mov	-16(%rax),%rbp
.cfi_restore	%rbp
	mov	-8(%rax),%rbx
.cfi_restore	%rbx
	lea	(%rax),%rsp		# restore %rsp
.cfi_def_cfa_register	%rsp
.Lgcm_dec_abort:
	mov	%r10,%rax		# return value
	ret
.cfi_endproc
.size	aesni_gcm_decrypt,.-aesni_gcm_decrypt
.type	_aesni_ctr32_6x,@abi-omnipotent
.align	32
_aesni_ctr32_6x:
.cfi_startproc
	vmovdqu		0x00-0x80(%rcx),%xmm4	# borrow %xmm4 for %xmm15
	vmovdqu		0x20(%r11),%xmm2	# borrow %xmm2, .Lone_msb
	lea		-1(%ebp),%r13
	vmovups		0x10-0x80(%rcx),%xmm15
	lea		0x20-0x80(%rcx),%r12
	vpxor		%xmm4,%xmm1,%xmm9
	add		$100663296,%ebx
	jc		.Lhandle_ctr32_2
	vpaddb		%xmm2,%xmm1,%xmm10
	vpaddb		%xmm2,%xmm10,%xmm11
	vpxor		%xmm4,%xmm10,%xmm10
	vpaddb		%xmm2,%xmm11,%xmm12
	vpxor		%xmm4,%xmm11,%xmm11
	vpaddb		%xmm2,%xmm12,%xmm13
	vpxor		%xmm4,%xmm12,%xmm12
	vpaddb		%xmm2,%xmm13,%xmm14
	vpxor		%xmm4,%xmm13,%xmm13
	vpaddb		%xmm2,%xmm14,%xmm1
	vpxor		%xmm4,%xmm14,%xmm14
	jmp		.Loop_ctr32

.align	16
.Loop_ctr32:
	vaesenc		%xmm15,%xmm9,%xmm9
	vaesenc		%xmm15,%xmm10,%xmm10
	vaesenc		%xmm15,%xmm11,%xmm11
	vaesenc		%xmm15,%xmm12,%xmm12
	vaesenc		%xmm15,%xmm13,%xmm13
	vaesenc		%xmm15,%xmm14,%xmm14
	vmovups		(%r12),%xmm15
	lea		0x10(%r12),%r12
	dec		%r13d
	jnz		.Loop_ctr32

	vmovdqu		(%r12),%xmm3		# last round key
	vaesenc		%xmm15,%xmm9,%xmm9
	vpxor		0x00(%rdi),%xmm3,%xmm4
	vaesenc		%xmm15,%xmm10,%xmm10
	vpxor		0x10(%rdi),%xmm3,%xmm5
	vaesenc		%xmm15,%xmm11,%xmm11
	vpxor		0x20(%rdi),%xmm3,%xmm6
	vaesenc		%xmm15,%xmm12,%xmm12
	vpxor		0x30(%rdi),%xmm3,%xmm8
	vaesenc		%xmm15,%xmm13,%xmm13
	vpxor		0x40(%rdi),%xmm3,%xmm2
	vaesenc		%xmm15,%xmm14,%xmm14
	vpxor		0x50(%rdi),%xmm3,%xmm3
	lea		0x60(%rdi),%rdi

	vaesenclast	%xmm4,%xmm9,%xmm9
	vaesenclast	%xmm5,%xmm10,%xmm10
	vaesenclast	%xmm6,%xmm11,%xmm11
	vaesenclast	%xmm8,%xmm12,%xmm12
	vaesenclast	%xmm2,%xmm13,%xmm13
	vaesenclast	%xmm3,%xmm14,%xmm14
	vmovups		%xmm9,0x00(%rsi)
	vmovups		%xmm10,0x10(%rsi)
	vmovups		%xmm11,0x20(%rsi)
	vmovups		%xmm12,0x30(%rsi)
	vmovups		%xmm13,0x40(%rsi)
	vmovups		%xmm14,0x50(%rsi)
	lea		0x60(%rsi),%rsi

	ret
.align	32
.Lhandle_ctr32_2:
	vpshufb		%xmm0,%xmm1,%xmm6		# byte-swap counter
	vmovdqu		0x30(%r11),%xmm5	# borrow %xmm5, .Ltwo_lsb
	vpaddd		0x40(%r11),%xmm6,%xmm10	# .Lone_lsb
	vpaddd		%xmm5,%xmm6,%xmm11
	vpaddd		%xmm5,%xmm10,%xmm12
	vpshufb		%xmm0,%xmm10,%xmm10
	vpaddd		%xmm5,%xmm11,%xmm13
	vpshufb		%xmm0,%xmm11,%xmm11
	vpxor		%xmm4,%xmm10,%xmm10
	vpaddd		%xmm5,%xmm12,%xmm14
	vpshufb		%xmm0,%xmm12,%xmm12
	vpxor		%xmm4,%xmm11,%xmm11
	vpaddd		%xmm5,%xmm13,%xmm1		# byte-swapped next counter value
	vpshufb		%xmm0,%xmm13,%xmm13
	vpxor		%xmm4,%xmm12,%xmm12
	vpshufb		%xmm0,%xmm14,%xmm14
	vpxor		%xmm4,%xmm13,%xmm13
	vpshufb		%xmm0,%xmm1,%xmm1		# next counter value
	vpxor		%xmm4,%xmm14,%xmm14
	jmp	.Loop_ctr32
.cfi_endproc
.size	_aesni_ctr32_6x,.-_aesni_ctr32_6x

.globl	aesni_gcm_encrypt
.type	aesni_gcm_encrypt,@function,6
.align	32
aesni_gcm_encrypt:
.cfi_startproc
	xor	%r10,%r10
	cmp	$0x60*3,%rdx			# minimal accepted length
	jb	.Lgcm_enc_abort

	lea	(%rsp),%rax			# save stack pointer
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
	vzeroupper

	vmovdqu		(%r8),%xmm1		# input counter value
	add		$-128,%rsp
	mov		12(%r8),%ebx
	lea		.Lbswap_mask(%rip),%r11
	lea		-0x80(%rcx),%r14	# borrow %r14
	mov		$0xf80,%r15		# borrow %r15
	lea		0x80(%rcx),%rcx		# size optimization
	vmovdqu		(%r11),%xmm0		# borrow %xmm0 for .Lbswap_mask
	and		$-128,%rsp		# ensure stack alignment
	mov		0xf0-0x80(%rcx),%ebp

	and		%r15,%r14
	and		%rsp,%r15
	sub		%r14,%r15
	jc		.Lenc_no_key_aliasing
	cmp		$768,%r15
	jnc		.Lenc_no_key_aliasing
	sub		%r15,%rsp		# avoid aliasing with key
.Lenc_no_key_aliasing:

	lea		(%rsi),%r14
	lea		-0xc0(%rsi,%rdx),%r15
	shr		$4,%rdx

	call		_aesni_ctr32_6x
	vpshufb		%xmm0,%xmm9,%xmm8		# save bswapped output on stack
	vpshufb		%xmm0,%xmm10,%xmm2
	vmovdqu		%xmm8,0x70(%rsp)
	vpshufb		%xmm0,%xmm11,%xmm4
	vmovdqu		%xmm2,0x60(%rsp)
	vpshufb		%xmm0,%xmm12,%xmm5
	vmovdqu		%xmm4,0x50(%rsp)
	vpshufb		%xmm0,%xmm13,%xmm6
	vmovdqu		%xmm5,0x40(%rsp)
	vpshufb		%xmm0,%xmm14,%xmm7		# passed to _aesni_ctr32_ghash_6x
	vmovdqu		%xmm6,0x30(%rsp)

	call		_aesni_ctr32_6x

	vmovdqu		(%r9),%xmm8		# load Xi
	lea		0x20+0x20(%r9),%r9	# size optimization
	sub		$12,%rdx
	mov		$0x60*2,%r10
	vpshufb		%xmm0,%xmm8,%xmm8

	call		_aesni_ctr32_ghash_6x
	vmovdqu		0x20(%rsp),%xmm7		# I[5]
	 vmovdqu	(%r11),%xmm0		# borrow %xmm0 for .Lbswap_mask
	vmovdqu		0x00-0x20(%r9),%xmm3	# %xmm3^1
	vpunpckhqdq	%xmm7,%xmm7,%xmm1
	vmovdqu		0x20-0x20(%r9),%xmm15	# borrow %xmm15 for
	 vmovups	%xmm9,-0x60(%rsi)	# save output
	 vpshufb	%xmm0,%xmm9,%xmm9	# but keep bswapped copy
	vpxor		%xmm7,%xmm1,%xmm1
	 vmovups	%xmm10,-0x50(%rsi)
	 vpshufb	%xmm0,%xmm10,%xmm10
	 vmovups	%xmm11,-0x40(%rsi)
	 vpshufb	%xmm0,%xmm11,%xmm11
	 vmovups	%xmm12,-0x30(%rsi)
	 vpshufb	%xmm0,%xmm12,%xmm12
	 vmovups	%xmm13,-0x20(%rsi)
	 vpshufb	%xmm0,%xmm13,%xmm13
	 vmovups	%xmm14,-0x10(%rsi)
	 vpshufb	%xmm0,%xmm14,%xmm14
	 vmovdqu	%xmm9,0x10(%rsp)	# free %xmm9
	 vmovdqu	0x30(%rsp),%xmm6		# I[4]
	 vmovdqu	0x10-0x20(%r9),%xmm0	# borrow %xmm0 for %xmm3^2
	 vpunpckhqdq	%xmm6,%xmm6,%xmm2
	vpclmulqdq	$0x00,%xmm3,%xmm7,%xmm5
	 vpxor		%xmm6,%xmm2,%xmm2
	vpclmulqdq	$0x11,%xmm3,%xmm7,%xmm7
	vpclmulqdq	$0x00,%xmm15,%xmm1,%xmm1

	 vmovdqu	0x40(%rsp),%xmm9		# I[3]
	vpclmulqdq	$0x00,%xmm0,%xmm6,%xmm4
	 vmovdqu	0x30-0x20(%r9),%xmm3	# %xmm3^3
	vpxor		%xmm5,%xmm4,%xmm4
	 vpunpckhqdq	%xmm9,%xmm9,%xmm5
	vpclmulqdq	$0x11,%xmm0,%xmm6,%xmm6
	 vpxor		%xmm9,%xmm5,%xmm5
	vpxor		%xmm7,%xmm6,%xmm6
	vpclmulqdq	$0x10,%xmm15,%xmm2,%xmm2
	 vmovdqu	0x50-0x20(%r9),%xmm15
	vpxor		%xmm1,%xmm2,%xmm2

	 vmovdqu	0x50(%rsp),%xmm1		# I[2]
	vpclmulqdq	$0x00,%xmm3,%xmm9,%xmm7
	 vmovdqu	0x40-0x20(%r9),%xmm0	# borrow %xmm0 for %xmm3^4
	vpxor		%xmm4,%xmm7,%xmm7
	 vpunpckhqdq	%xmm1,%xmm1,%xmm4
	vpclmulqdq	$0x11,%xmm3,%xmm9,%xmm9
	 vpxor		%xmm1,%xmm4,%xmm4
	vpxor		%xmm6,%xmm9,%xmm9
	vpclmulqdq	$0x00,%xmm15,%xmm5,%xmm5
	vpxor		%xmm2,%xmm5,%xmm5

	 vmovdqu	0x60(%rsp),%xmm2		# I[1]
	vpclmulqdq	$0x00,%xmm0,%xmm1,%xmm6
	 vmovdqu	0x60-0x20(%r9),%xmm3	# %xmm3^5
	vpxor		%xmm7,%xmm6,%xmm6
	 vpunpckhqdq	%xmm2,%xmm2,%xmm7
	vpclmulqdq	$0x11,%xmm0,%xmm1,%xmm1
	 vpxor		%xmm2,%xmm7,%xmm7
	vpxor		%xmm9,%xmm1,%xmm1
	vpclmulqdq	$0x10,%xmm15,%xmm4,%xmm4
	 vmovdqu	0x80-0x20(%r9),%xmm15
	vpxor		%xmm5,%xmm4,%xmm4

	 vpxor		0x70(%rsp),%xmm8,%xmm8	# accumulate I[0]
	vpclmulqdq	$0x00,%xmm3,%xmm2,%xmm5
	 vmovdqu	0x70-0x20(%r9),%xmm0	# borrow %xmm0 for %xmm3^6
	 vpunpckhqdq	%xmm8,%xmm8,%xmm9
	vpxor		%xmm6,%xmm5,%xmm5
	vpclmulqdq	$0x11,%xmm3,%xmm2,%xmm2
	 vpxor		%xmm8,%xmm9,%xmm9
	vpxor		%xmm1,%xmm2,%xmm2
	vpclmulqdq	$0x00,%xmm15,%xmm7,%xmm7
	vpxor		%xmm4,%xmm7,%xmm4

	vpclmulqdq	$0x00,%xmm0,%xmm8,%xmm6
	 vmovdqu	0x00-0x20(%r9),%xmm3	# %xmm3^1
	 vpunpckhqdq	%xmm14,%xmm14,%xmm1
	vpclmulqdq	$0x11,%xmm0,%xmm8,%xmm8
	 vpxor		%xmm14,%xmm1,%xmm1
	vpxor		%xmm5,%xmm6,%xmm5
	vpclmulqdq	$0x10,%xmm15,%xmm9,%xmm9
	 vmovdqu	0x20-0x20(%r9),%xmm15
	vpxor		%xmm2,%xmm8,%xmm7
	vpxor		%xmm4,%xmm9,%xmm6

	 vmovdqu	0x10-0x20(%r9),%xmm0	# borrow %xmm0 for %xmm3^2
	  vpxor		%xmm5,%xmm7,%xmm9		# aggregated Karatsuba post-processing
	vpclmulqdq	$0x00,%xmm3,%xmm14,%xmm4
	  vpxor		%xmm9,%xmm6,%xmm6
	 vpunpckhqdq	%xmm13,%xmm13,%xmm2
	vpclmulqdq	$0x11,%xmm3,%xmm14,%xmm14
	 vpxor		%xmm13,%xmm2,%xmm2
	  vpslldq	$8,%xmm6,%xmm9
	vpclmulqdq	$0x00,%xmm15,%xmm1,%xmm1
	  vpxor		%xmm9,%xmm5,%xmm8
	  vpsrldq	$8,%xmm6,%xmm6
	  vpxor		%xmm6,%xmm7,%xmm7

	vpclmulqdq	$0x00,%xmm0,%xmm13,%xmm5
	 vmovdqu	0x30-0x20(%r9),%xmm3	# %xmm3^3
	vpxor		%xmm4,%xmm5,%xmm5
	 vpunpckhqdq	%xmm12,%xmm12,%xmm9
	vpclmulqdq	$0x11,%xmm0,%xmm13,%xmm13
	 vpxor		%xmm12,%xmm9,%xmm9
	vpxor		%xmm14,%xmm13,%xmm13
	  vpalignr	$8,%xmm8,%xmm8,%xmm14	# 1st phase
	vpclmulqdq	$0x10,%xmm15,%xmm2,%xmm2
	 vmovdqu	0x50-0x20(%r9),%xmm15
	vpxor		%xmm1,%xmm2,%xmm2

	vpclmulqdq	$0x00,%xmm3,%xmm12,%xmm4
	 vmovdqu	0x40-0x20(%r9),%xmm0	# borrow %xmm0 for %xmm3^4
	vpxor		%xmm5,%xmm4,%xmm4
	 vpunpckhqdq	%xmm11,%xmm11,%xmm1
	vpclmulqdq	$0x11,%xmm3,%xmm12,%xmm12
	 vpxor		%xmm11,%xmm1,%xmm1
	vpxor		%xmm13,%xmm12,%xmm12
	  vxorps	0x10(%rsp),%xmm7,%xmm7	# accumulate %xmm9
	vpclmulqdq	$0x00,%xmm15,%xmm9,%xmm9
	vpxor		%xmm2,%xmm9,%xmm9

	  vpclmulqdq	$0x10,0x10(%r11),%xmm8,%xmm8
	  vxorps	%xmm14,%xmm8,%xmm8

	vpclmulqdq	$0x00,%xmm0,%xmm11,%xmm5
	 vmovdqu	0x60-0x20(%r9),%xmm3	# %xmm3^5
	vpxor		%xmm4,%xmm5,%xmm5
	 vpunpckhqdq	%xmm10,%xmm10,%xmm2
	vpclmulqdq	$0x11,%xmm0,%xmm11,%xmm11
	 vpxor		%xmm10,%xmm2,%xmm2
	  vpalignr	$8,%xmm8,%xmm8,%xmm14	# 2nd phase
	vpxor		%xmm12,%xmm11,%xmm11
	vpclmulqdq	$0x10,%xmm15,%xmm1,%xmm1
	 vmovdqu	0x80-0x20(%r9),%xmm15
	vpxor		%xmm9,%xmm1,%xmm1

	  vxorps	%xmm7,%xmm14,%xmm14
	  vpclmulqdq	$0x10,0x10(%r11),%xmm8,%xmm8
	  vxorps	%xmm14,%xmm8,%xmm8

	vpclmulqdq	$0x00,%xmm3,%xmm10,%xmm4
	 vmovdqu	0x70-0x20(%r9),%xmm0	# borrow %xmm0 for %xmm3^6
	vpxor		%xmm5,%xmm4,%xmm4
	 vpunpckhqdq	%xmm8,%xmm8,%xmm9
	vpclmulqdq	$0x11,%xmm3,%xmm10,%xmm10
	 vpxor		%xmm8,%xmm9,%xmm9
	vpxor		%xmm11,%xmm10,%xmm10
	vpclmulqdq	$0x00,%xmm15,%xmm2,%xmm2
	vpxor		%xmm1,%xmm2,%xmm2

	vpclmulqdq	$0x00,%xmm0,%xmm8,%xmm5
	vpclmulqdq	$0x11,%xmm0,%xmm8,%xmm7
	vpxor		%xmm4,%xmm5,%xmm5
	vpclmulqdq	$0x10,%xmm15,%xmm9,%xmm6
	vpxor		%xmm10,%xmm7,%xmm7
	vpxor		%xmm2,%xmm6,%xmm6

	vpxor		%xmm5,%xmm7,%xmm4		# aggregated Karatsuba post-processing
	vpxor		%xmm4,%xmm6,%xmm6
	vpslldq		$8,%xmm6,%xmm1
	vmovdqu		0x10(%r11),%xmm3	# .Lpoly
	vpsrldq		$8,%xmm6,%xmm6
	vpxor		%xmm1,%xmm5,%xmm8
	vpxor		%xmm6,%xmm7,%xmm7

	vpalignr	$8,%xmm8,%xmm8,%xmm2		# 1st phase
	vpclmulqdq	$0x10,%xmm3,%xmm8,%xmm8
	vpxor		%xmm2,%xmm8,%xmm8

	vpalignr	$8,%xmm8,%xmm8,%xmm2		# 2nd phase
	vpclmulqdq	$0x10,%xmm3,%xmm8,%xmm8
	vpxor		%xmm7,%xmm2,%xmm2
	vpxor		%xmm2,%xmm8,%xmm8
	vpshufb		(%r11),%xmm8,%xmm8	# .Lbswap_mask
	vmovdqu		%xmm8,-0x40(%r9)		# output Xi

	vzeroupper
	mov	-48(%rax),%r15
.cfi_restore	%r15
	mov	-40(%rax),%r14
.cfi_restore	%r14
	mov	-32(%rax),%r13
.cfi_restore	%r13
	mov	-24(%rax),%r12
.cfi_restore	%r12
	mov	-16(%rax),%rbp
.cfi_restore	%rbp
	mov	-8(%rax),%rbx
.cfi_restore	%rbx
	lea	(%rax),%rsp		# restore %rsp
.cfi_def_cfa_register	%rsp
.Lgcm_enc_abort:
	mov	%r10,%rax		# return value
	ret
.cfi_endproc
.size	aesni_gcm_encrypt,.-aesni_gcm_encrypt
.section .rodata align=64
.align	64
.Lbswap_mask:
	.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
.Lpoly:
	.byte	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xc2
.Lone_msb:
	.byte	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
.Ltwo_lsb:
	.byte	2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
.Lone_lsb:
	.byte	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
.asciz	"AES-NI GCM module for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.previous
.align	64
`;

export default translateAssembly(code);
