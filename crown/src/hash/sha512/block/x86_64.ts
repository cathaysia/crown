/**
 * sha512_block_data_order for x86_64.
 *
 * TypeScript port of the $SZ==8 branch of OpenSSL
 * crypto/sha/asm/sha512-x86_64.pl (selected by an output name containing
 * "512").
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the full x86_64 configuration of a stock OpenSSL build: with
 * GNU as >= 2.19 the perl emits the IALU, XOP, AVX and AVX2 bodies and
 * `sha512_block_data_order` dispatches between them at run time from
 * OPENSSL_ia32cap_P. SHA-512 has no SHA-NI path, so the AVX2 body is the
 * fast path on every modern part.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text

.extern	OPENSSL_ia32cap_P
.globl	sha512_block_data_order
.type	sha512_block_data_order,@function,3
.align	16
sha512_block_data_order:
.cfi_startproc
	lea	OPENSSL_ia32cap_P(%rip),%r11
	mov	0(%r11),%r9d
	mov	4(%r11),%r10d
	mov	8(%r11),%r11d
	test	$2048,%r10d		# check for XOP
	jnz	.Lxop_shortcut
	and	$296,%r11d	# check for BMI2+AVX2+BMI1
	cmp	$296,%r11d
	je	.Lavx2_shortcut
	and	$1073741824,%r9d		# mask "Intel CPU" bit
	and	$268435968,%r10d	# mask AVX and SSSE3 bits
	or	%r9d,%r10d
	cmp	$1342177792,%r10d
	je	.Lavx_shortcut
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
	sub	$16*8+4*8,%rsp
	lea	(%rsi,%rdx,8),%rdx	# inp+num*16*8
	and	$-64,%rsp		# align stack frame
	mov	%rdi,16*8+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*8+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*8+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,152(%rsp)		# save copy of %rsp
.cfi_cfa_expression	152(%rsp),deref,+8
.Lprologue:

	mov	8*0(%rdi),%rax
	mov	8*1(%rdi),%rbx
	mov	8*2(%rdi),%rcx
	mov	8*3(%rdi),%rdx
	mov	8*4(%rdi),%r8
	mov	8*5(%rdi),%r9
	mov	8*6(%rdi),%r10
	mov	8*7(%rdi),%r11
	jmp	.Lloop

.align	16
.Lloop:
	mov	%rbx,%rdi
	lea	K512(%rip),%rbp
	xor	%rcx,%rdi			# magic
	mov	8*0(%rsi),%r12
	mov	%r8,%r13
	mov	%rax,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r9,%r15

	xor	%r8,%r13
	ror	$5,%r14
	xor	%r10,%r15			# f^g

	mov	%r12,0(%rsp)
	xor	%rax,%r14
	and	%r8,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r11,%r12			# T1+=h
	xor	%r10,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r8,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rax,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rax,%r14

	xor	%rbx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rbx,%r11

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r11			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rdx			# d+=T1
	add	%r12,%r11			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%r11			# h+=Sigma0(a)
	mov	8*1(%rsi),%r12
	mov	%rdx,%r13
	mov	%r11,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r8,%rdi

	xor	%rdx,%r13
	ror	$5,%r14
	xor	%r9,%rdi			# f^g

	mov	%r12,8(%rsp)
	xor	%r11,%r14
	and	%rdx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r10,%r12			# T1+=h
	xor	%r9,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rdx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r11,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r11,%r14

	xor	%rax,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rax,%r10

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r10			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rcx			# d+=T1
	add	%r12,%r10			# h+=T1

	lea	24(%rbp),%rbp	# round++
	add	%r14,%r10			# h+=Sigma0(a)
	mov	8*2(%rsi),%r12
	mov	%rcx,%r13
	mov	%r10,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rdx,%r15

	xor	%rcx,%r13
	ror	$5,%r14
	xor	%r8,%r15			# f^g

	mov	%r12,16(%rsp)
	xor	%r10,%r14
	and	%rcx,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r9,%r12			# T1+=h
	xor	%r8,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rcx,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r10,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r10,%r14

	xor	%r11,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r11,%r9

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r9			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rbx			# d+=T1
	add	%r12,%r9			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%r9			# h+=Sigma0(a)
	mov	8*3(%rsi),%r12
	mov	%rbx,%r13
	mov	%r9,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rcx,%rdi

	xor	%rbx,%r13
	ror	$5,%r14
	xor	%rdx,%rdi			# f^g

	mov	%r12,24(%rsp)
	xor	%r9,%r14
	and	%rbx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r8,%r12			# T1+=h
	xor	%rdx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rbx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r9,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r9,%r14

	xor	%r10,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r10,%r8

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r8			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rax			# d+=T1
	add	%r12,%r8			# h+=T1

	lea	24(%rbp),%rbp	# round++
	add	%r14,%r8			# h+=Sigma0(a)
	mov	8*4(%rsi),%r12
	mov	%rax,%r13
	mov	%r8,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rbx,%r15

	xor	%rax,%r13
	ror	$5,%r14
	xor	%rcx,%r15			# f^g

	mov	%r12,32(%rsp)
	xor	%r8,%r14
	and	%rax,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rdx,%r12			# T1+=h
	xor	%rcx,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rax,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r8,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r8,%r14

	xor	%r9,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r9,%rdx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rdx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r11			# d+=T1
	add	%r12,%rdx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%rdx			# h+=Sigma0(a)
	mov	8*5(%rsi),%r12
	mov	%r11,%r13
	mov	%rdx,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rax,%rdi

	xor	%r11,%r13
	ror	$5,%r14
	xor	%rbx,%rdi			# f^g

	mov	%r12,40(%rsp)
	xor	%rdx,%r14
	and	%r11,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rcx,%r12			# T1+=h
	xor	%rbx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r11,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rdx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rdx,%r14

	xor	%r8,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r8,%rcx

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rcx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r10			# d+=T1
	add	%r12,%rcx			# h+=T1

	lea	24(%rbp),%rbp	# round++
	add	%r14,%rcx			# h+=Sigma0(a)
	mov	8*6(%rsi),%r12
	mov	%r10,%r13
	mov	%rcx,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r11,%r15

	xor	%r10,%r13
	ror	$5,%r14
	xor	%rax,%r15			# f^g

	mov	%r12,48(%rsp)
	xor	%rcx,%r14
	and	%r10,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rbx,%r12			# T1+=h
	xor	%rax,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r10,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rcx,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rcx,%r14

	xor	%rdx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rdx,%rbx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rbx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r9			# d+=T1
	add	%r12,%rbx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%rbx			# h+=Sigma0(a)
	mov	8*7(%rsi),%r12
	mov	%r9,%r13
	mov	%rbx,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r10,%rdi

	xor	%r9,%r13
	ror	$5,%r14
	xor	%r11,%rdi			# f^g

	mov	%r12,56(%rsp)
	xor	%rbx,%r14
	and	%r9,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rax,%r12			# T1+=h
	xor	%r11,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r9,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rbx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rbx,%r14

	xor	%rcx,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rcx,%rax

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r8			# d+=T1
	add	%r12,%rax			# h+=T1

	lea	24(%rbp),%rbp	# round++
	add	%r14,%rax			# h+=Sigma0(a)
	mov	8*8(%rsi),%r12
	mov	%r8,%r13
	mov	%rax,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r9,%r15

	xor	%r8,%r13
	ror	$5,%r14
	xor	%r10,%r15			# f^g

	mov	%r12,64(%rsp)
	xor	%rax,%r14
	and	%r8,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r11,%r12			# T1+=h
	xor	%r10,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r8,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rax,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rax,%r14

	xor	%rbx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rbx,%r11

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r11			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rdx			# d+=T1
	add	%r12,%r11			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%r11			# h+=Sigma0(a)
	mov	8*9(%rsi),%r12
	mov	%rdx,%r13
	mov	%r11,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r8,%rdi

	xor	%rdx,%r13
	ror	$5,%r14
	xor	%r9,%rdi			# f^g

	mov	%r12,72(%rsp)
	xor	%r11,%r14
	and	%rdx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r10,%r12			# T1+=h
	xor	%r9,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rdx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r11,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r11,%r14

	xor	%rax,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rax,%r10

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r10			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rcx			# d+=T1
	add	%r12,%r10			# h+=T1

	lea	24(%rbp),%rbp	# round++
	add	%r14,%r10			# h+=Sigma0(a)
	mov	8*10(%rsi),%r12
	mov	%rcx,%r13
	mov	%r10,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rdx,%r15

	xor	%rcx,%r13
	ror	$5,%r14
	xor	%r8,%r15			# f^g

	mov	%r12,80(%rsp)
	xor	%r10,%r14
	and	%rcx,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r9,%r12			# T1+=h
	xor	%r8,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rcx,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r10,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r10,%r14

	xor	%r11,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r11,%r9

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r9			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rbx			# d+=T1
	add	%r12,%r9			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%r9			# h+=Sigma0(a)
	mov	8*11(%rsi),%r12
	mov	%rbx,%r13
	mov	%r9,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rcx,%rdi

	xor	%rbx,%r13
	ror	$5,%r14
	xor	%rdx,%rdi			# f^g

	mov	%r12,88(%rsp)
	xor	%r9,%r14
	and	%rbx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r8,%r12			# T1+=h
	xor	%rdx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rbx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r9,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r9,%r14

	xor	%r10,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r10,%r8

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r8			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rax			# d+=T1
	add	%r12,%r8			# h+=T1

	lea	24(%rbp),%rbp	# round++
	add	%r14,%r8			# h+=Sigma0(a)
	mov	8*12(%rsi),%r12
	mov	%rax,%r13
	mov	%r8,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rbx,%r15

	xor	%rax,%r13
	ror	$5,%r14
	xor	%rcx,%r15			# f^g

	mov	%r12,96(%rsp)
	xor	%r8,%r14
	and	%rax,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rdx,%r12			# T1+=h
	xor	%rcx,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rax,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r8,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r8,%r14

	xor	%r9,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r9,%rdx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rdx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r11			# d+=T1
	add	%r12,%rdx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%rdx			# h+=Sigma0(a)
	mov	8*13(%rsi),%r12
	mov	%r11,%r13
	mov	%rdx,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%rax,%rdi

	xor	%r11,%r13
	ror	$5,%r14
	xor	%rbx,%rdi			# f^g

	mov	%r12,104(%rsp)
	xor	%rdx,%r14
	and	%r11,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rcx,%r12			# T1+=h
	xor	%rbx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r11,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rdx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rdx,%r14

	xor	%r8,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r8,%rcx

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rcx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r10			# d+=T1
	add	%r12,%rcx			# h+=T1

	lea	24(%rbp),%rbp	# round++
	add	%r14,%rcx			# h+=Sigma0(a)
	mov	8*14(%rsi),%r12
	mov	%r10,%r13
	mov	%rcx,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r11,%r15

	xor	%r10,%r13
	ror	$5,%r14
	xor	%rax,%r15			# f^g

	mov	%r12,112(%rsp)
	xor	%rcx,%r14
	and	%r10,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rbx,%r12			# T1+=h
	xor	%rax,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r10,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rcx,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rcx,%r14

	xor	%rdx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rdx,%rbx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rbx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r9			# d+=T1
	add	%r12,%rbx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	add	%r14,%rbx			# h+=Sigma0(a)
	mov	8*15(%rsi),%r12
	mov	%r9,%r13
	mov	%rbx,%r14
	bswap	%r12
	ror	$23,%r13
	mov	%r10,%rdi

	xor	%r9,%r13
	ror	$5,%r14
	xor	%r11,%rdi			# f^g

	mov	%r12,120(%rsp)
	xor	%rbx,%r14
	and	%r9,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rax,%r12			# T1+=h
	xor	%r11,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r9,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rbx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rbx,%r14

	xor	%rcx,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rcx,%rax

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r8			# d+=T1
	add	%r12,%rax			# h+=T1

	lea	24(%rbp),%rbp	# round++
	jmp	.Lrounds_16_xx
.align	16
.Lrounds_16_xx:
	mov	8(%rsp),%r13
	mov	112(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rax			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	72(%rsp),%r12

	add	0(%rsp),%r12
	mov	%r8,%r13
	add	%r15,%r12
	mov	%rax,%r14
	ror	$23,%r13
	mov	%r9,%r15

	xor	%r8,%r13
	ror	$5,%r14
	xor	%r10,%r15			# f^g

	mov	%r12,0(%rsp)
	xor	%rax,%r14
	and	%r8,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r11,%r12			# T1+=h
	xor	%r10,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r8,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rax,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rax,%r14

	xor	%rbx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rbx,%r11

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r11			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rdx			# d+=T1
	add	%r12,%r11			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	16(%rsp),%r13
	mov	120(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r11			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	80(%rsp),%r12

	add	8(%rsp),%r12
	mov	%rdx,%r13
	add	%rdi,%r12
	mov	%r11,%r14
	ror	$23,%r13
	mov	%r8,%rdi

	xor	%rdx,%r13
	ror	$5,%r14
	xor	%r9,%rdi			# f^g

	mov	%r12,8(%rsp)
	xor	%r11,%r14
	and	%rdx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r10,%r12			# T1+=h
	xor	%r9,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rdx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r11,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r11,%r14

	xor	%rax,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rax,%r10

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r10			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rcx			# d+=T1
	add	%r12,%r10			# h+=T1

	lea	24(%rbp),%rbp	# round++
	mov	24(%rsp),%r13
	mov	0(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r10			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	88(%rsp),%r12

	add	16(%rsp),%r12
	mov	%rcx,%r13
	add	%r15,%r12
	mov	%r10,%r14
	ror	$23,%r13
	mov	%rdx,%r15

	xor	%rcx,%r13
	ror	$5,%r14
	xor	%r8,%r15			# f^g

	mov	%r12,16(%rsp)
	xor	%r10,%r14
	and	%rcx,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r9,%r12			# T1+=h
	xor	%r8,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rcx,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r10,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r10,%r14

	xor	%r11,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r11,%r9

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r9			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rbx			# d+=T1
	add	%r12,%r9			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	32(%rsp),%r13
	mov	8(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r9			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	96(%rsp),%r12

	add	24(%rsp),%r12
	mov	%rbx,%r13
	add	%rdi,%r12
	mov	%r9,%r14
	ror	$23,%r13
	mov	%rcx,%rdi

	xor	%rbx,%r13
	ror	$5,%r14
	xor	%rdx,%rdi			# f^g

	mov	%r12,24(%rsp)
	xor	%r9,%r14
	and	%rbx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r8,%r12			# T1+=h
	xor	%rdx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rbx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r9,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r9,%r14

	xor	%r10,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r10,%r8

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r8			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rax			# d+=T1
	add	%r12,%r8			# h+=T1

	lea	24(%rbp),%rbp	# round++
	mov	40(%rsp),%r13
	mov	16(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r8			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	104(%rsp),%r12

	add	32(%rsp),%r12
	mov	%rax,%r13
	add	%r15,%r12
	mov	%r8,%r14
	ror	$23,%r13
	mov	%rbx,%r15

	xor	%rax,%r13
	ror	$5,%r14
	xor	%rcx,%r15			# f^g

	mov	%r12,32(%rsp)
	xor	%r8,%r14
	and	%rax,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rdx,%r12			# T1+=h
	xor	%rcx,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rax,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r8,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r8,%r14

	xor	%r9,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r9,%rdx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rdx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r11			# d+=T1
	add	%r12,%rdx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	48(%rsp),%r13
	mov	24(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rdx			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	112(%rsp),%r12

	add	40(%rsp),%r12
	mov	%r11,%r13
	add	%rdi,%r12
	mov	%rdx,%r14
	ror	$23,%r13
	mov	%rax,%rdi

	xor	%r11,%r13
	ror	$5,%r14
	xor	%rbx,%rdi			# f^g

	mov	%r12,40(%rsp)
	xor	%rdx,%r14
	and	%r11,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rcx,%r12			# T1+=h
	xor	%rbx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r11,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rdx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rdx,%r14

	xor	%r8,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r8,%rcx

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rcx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r10			# d+=T1
	add	%r12,%rcx			# h+=T1

	lea	24(%rbp),%rbp	# round++
	mov	56(%rsp),%r13
	mov	32(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rcx			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	120(%rsp),%r12

	add	48(%rsp),%r12
	mov	%r10,%r13
	add	%r15,%r12
	mov	%rcx,%r14
	ror	$23,%r13
	mov	%r11,%r15

	xor	%r10,%r13
	ror	$5,%r14
	xor	%rax,%r15			# f^g

	mov	%r12,48(%rsp)
	xor	%rcx,%r14
	and	%r10,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rbx,%r12			# T1+=h
	xor	%rax,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r10,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rcx,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rcx,%r14

	xor	%rdx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rdx,%rbx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rbx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r9			# d+=T1
	add	%r12,%rbx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	64(%rsp),%r13
	mov	40(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rbx			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	0(%rsp),%r12

	add	56(%rsp),%r12
	mov	%r9,%r13
	add	%rdi,%r12
	mov	%rbx,%r14
	ror	$23,%r13
	mov	%r10,%rdi

	xor	%r9,%r13
	ror	$5,%r14
	xor	%r11,%rdi			# f^g

	mov	%r12,56(%rsp)
	xor	%rbx,%r14
	and	%r9,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rax,%r12			# T1+=h
	xor	%r11,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r9,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rbx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rbx,%r14

	xor	%rcx,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rcx,%rax

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r8			# d+=T1
	add	%r12,%rax			# h+=T1

	lea	24(%rbp),%rbp	# round++
	mov	72(%rsp),%r13
	mov	48(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rax			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	8(%rsp),%r12

	add	64(%rsp),%r12
	mov	%r8,%r13
	add	%r15,%r12
	mov	%rax,%r14
	ror	$23,%r13
	mov	%r9,%r15

	xor	%r8,%r13
	ror	$5,%r14
	xor	%r10,%r15			# f^g

	mov	%r12,64(%rsp)
	xor	%rax,%r14
	and	%r8,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r11,%r12			# T1+=h
	xor	%r10,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r8,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rax,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rax,%r14

	xor	%rbx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rbx,%r11

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r11			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rdx			# d+=T1
	add	%r12,%r11			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	80(%rsp),%r13
	mov	56(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r11			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	16(%rsp),%r12

	add	72(%rsp),%r12
	mov	%rdx,%r13
	add	%rdi,%r12
	mov	%r11,%r14
	ror	$23,%r13
	mov	%r8,%rdi

	xor	%rdx,%r13
	ror	$5,%r14
	xor	%r9,%rdi			# f^g

	mov	%r12,72(%rsp)
	xor	%r11,%r14
	and	%rdx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r10,%r12			# T1+=h
	xor	%r9,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rdx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r11,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r11,%r14

	xor	%rax,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rax,%r10

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r10			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rcx			# d+=T1
	add	%r12,%r10			# h+=T1

	lea	24(%rbp),%rbp	# round++
	mov	88(%rsp),%r13
	mov	64(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r10			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	24(%rsp),%r12

	add	80(%rsp),%r12
	mov	%rcx,%r13
	add	%r15,%r12
	mov	%r10,%r14
	ror	$23,%r13
	mov	%rdx,%r15

	xor	%rcx,%r13
	ror	$5,%r14
	xor	%r8,%r15			# f^g

	mov	%r12,80(%rsp)
	xor	%r10,%r14
	and	%rcx,%r15			# (f^g)&e

	ror	$4,%r13
	add	%r9,%r12			# T1+=h
	xor	%r8,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rcx,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r10,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r10,%r14

	xor	%r11,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r11,%r9

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%r9			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rbx			# d+=T1
	add	%r12,%r9			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	96(%rsp),%r13
	mov	72(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r9			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	32(%rsp),%r12

	add	88(%rsp),%r12
	mov	%rbx,%r13
	add	%rdi,%r12
	mov	%r9,%r14
	ror	$23,%r13
	mov	%rcx,%rdi

	xor	%rbx,%r13
	ror	$5,%r14
	xor	%rdx,%rdi			# f^g

	mov	%r12,88(%rsp)
	xor	%r9,%r14
	and	%rbx,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%r8,%r12			# T1+=h
	xor	%rdx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rbx,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%r9,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r9,%r14

	xor	%r10,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r10,%r8

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%r8			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%rax			# d+=T1
	add	%r12,%r8			# h+=T1

	lea	24(%rbp),%rbp	# round++
	mov	104(%rsp),%r13
	mov	80(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%r8			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	40(%rsp),%r12

	add	96(%rsp),%r12
	mov	%rax,%r13
	add	%r15,%r12
	mov	%r8,%r14
	ror	$23,%r13
	mov	%rbx,%r15

	xor	%rax,%r13
	ror	$5,%r14
	xor	%rcx,%r15			# f^g

	mov	%r12,96(%rsp)
	xor	%r8,%r14
	and	%rax,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rdx,%r12			# T1+=h
	xor	%rcx,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%rax,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%r8,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%r8,%r14

	xor	%r9,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r9,%rdx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rdx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r11			# d+=T1
	add	%r12,%rdx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	112(%rsp),%r13
	mov	88(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rdx			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	48(%rsp),%r12

	add	104(%rsp),%r12
	mov	%r11,%r13
	add	%rdi,%r12
	mov	%rdx,%r14
	ror	$23,%r13
	mov	%rax,%rdi

	xor	%r11,%r13
	ror	$5,%r14
	xor	%rbx,%rdi			# f^g

	mov	%r12,104(%rsp)
	xor	%rdx,%r14
	and	%r11,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rcx,%r12			# T1+=h
	xor	%rbx,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r11,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rdx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rdx,%r14

	xor	%r8,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%r8,%rcx

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rcx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r10			# d+=T1
	add	%r12,%rcx			# h+=T1

	lea	24(%rbp),%rbp	# round++
	mov	120(%rsp),%r13
	mov	96(%rsp),%r15

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rcx			# modulo-scheduled h+=Sigma0(a)
	mov	%r15,%r14
	ror	$42,%r15

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%r15
	shr	$6,%r14

	ror	$19,%r15
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%r15			# sigma1(X[(i+14)&0xf])
	add	56(%rsp),%r12

	add	112(%rsp),%r12
	mov	%r10,%r13
	add	%r15,%r12
	mov	%rcx,%r14
	ror	$23,%r13
	mov	%r11,%r15

	xor	%r10,%r13
	ror	$5,%r14
	xor	%rax,%r15			# f^g

	mov	%r12,112(%rsp)
	xor	%rcx,%r14
	and	%r10,%r15			# (f^g)&e

	ror	$4,%r13
	add	%rbx,%r12			# T1+=h
	xor	%rax,%r15			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r10,%r13
	add	%r15,%r12			# T1+=Ch(e,f,g)

	mov	%rcx,%r15
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rcx,%r14

	xor	%rdx,%r15			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rdx,%rbx

	and	%r15,%rdi
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%rdi,%rbx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r9			# d+=T1
	add	%r12,%rbx			# h+=T1

	lea	8(%rbp),%rbp	# round++
	mov	0(%rsp),%r13
	mov	104(%rsp),%rdi

	mov	%r13,%r12
	ror	$7,%r13
	add	%r14,%rbx			# modulo-scheduled h+=Sigma0(a)
	mov	%rdi,%r14
	ror	$42,%rdi

	xor	%r12,%r13
	shr	$7,%r12
	ror	$1,%r13
	xor	%r14,%rdi
	shr	$6,%r14

	ror	$19,%rdi
	xor	%r13,%r12			# sigma0(X[(i+1)&0xf])
	xor	%r14,%rdi			# sigma1(X[(i+14)&0xf])
	add	64(%rsp),%r12

	add	120(%rsp),%r12
	mov	%r9,%r13
	add	%rdi,%r12
	mov	%rbx,%r14
	ror	$23,%r13
	mov	%r10,%rdi

	xor	%r9,%r13
	ror	$5,%r14
	xor	%r11,%rdi			# f^g

	mov	%r12,120(%rsp)
	xor	%rbx,%r14
	and	%r9,%rdi			# (f^g)&e

	ror	$4,%r13
	add	%rax,%r12			# T1+=h
	xor	%r11,%rdi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$6,%r14
	xor	%r9,%r13
	add	%rdi,%r12			# T1+=Ch(e,f,g)

	mov	%rbx,%rdi
	add	(%rbp),%r12		# T1+=K[round]
	xor	%rbx,%r14

	xor	%rcx,%rdi			# a^b, b^c in next round
	ror	$14,%r13	# Sigma1(e)
	mov	%rcx,%rax

	and	%rdi,%r15
	ror	$28,%r14	# Sigma0(a)
	add	%r13,%r12			# T1+=Sigma1(e)

	xor	%r15,%rax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12,%r8			# d+=T1
	add	%r12,%rax			# h+=T1

	lea	24(%rbp),%rbp	# round++
	cmpb	$0,7(%rbp)
	jnz	.Lrounds_16_xx

	mov	16*8+0*8(%rsp),%rdi
	add	%r14,%rax			# modulo-scheduled h+=Sigma0(a)
	lea	16*8(%rsi),%rsi

	add	8*0(%rdi),%rax
	add	8*1(%rdi),%rbx
	add	8*2(%rdi),%rcx
	add	8*3(%rdi),%rdx
	add	8*4(%rdi),%r8
	add	8*5(%rdi),%r9
	add	8*6(%rdi),%r10
	add	8*7(%rdi),%r11

	cmp	16*8+2*8(%rsp),%rsi

	mov	%rax,8*0(%rdi)
	mov	%rbx,8*1(%rdi)
	mov	%rcx,8*2(%rdi)
	mov	%rdx,8*3(%rdi)
	mov	%r8,8*4(%rdi)
	mov	%r9,8*5(%rdi)
	mov	%r10,8*6(%rdi)
	mov	%r11,8*7(%rdi)
	jb	.Lloop

	mov	152(%rsp),%rsi
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
.size	sha512_block_data_order,.-sha512_block_data_order
.section .rodata align=64
.align	64
.type	K512,@object
K512:
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
	.asciz	"SHA512 block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
.previous
.type	sha512_block_data_order_xop,@function,3
.align	64
sha512_block_data_order_xop:
.cfi_startproc
.Lxop_shortcut:
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
	sub	$160,%rsp
	lea	(%rsi,%rdx,8),%rdx	# inp+num*16*8
	and	$-64,%rsp		# align stack frame
	mov	%rdi,16*8+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*8+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*8+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,152(%rsp)		# save copy of %rsp
.cfi_cfa_expression	152(%rsp),deref,+8
.Lprologue_xop:

	vzeroupper
	mov	8*0(%rdi),%rax
	mov	8*1(%rdi),%rbx
	mov	8*2(%rdi),%rcx
	mov	8*3(%rdi),%rdx
	mov	8*4(%rdi),%r8
	mov	8*5(%rdi),%r9
	mov	8*6(%rdi),%r10
	mov	8*7(%rdi),%r11
	jmp	.Lloop_xop
.align	16
.Lloop_xop:
	vmovdqa	K512+1280(%rip),%xmm11
	vmovdqu	0x00(%rsi),%xmm0
	lea	K512+0x80(%rip),%rbp	# size optimization
	vmovdqu	0x10(%rsi),%xmm1
	vmovdqu	0x20(%rsi),%xmm2
	vpshufb	%xmm11,%xmm0,%xmm0
	vmovdqu	0x30(%rsi),%xmm3
	vpshufb	%xmm11,%xmm1,%xmm1
	vmovdqu	0x40(%rsi),%xmm4
	vpshufb	%xmm11,%xmm2,%xmm2
	vmovdqu	0x50(%rsi),%xmm5
	vpshufb	%xmm11,%xmm3,%xmm3
	vmovdqu	0x60(%rsi),%xmm6
	vpshufb	%xmm11,%xmm4,%xmm4
	vmovdqu	0x70(%rsi),%xmm7
	vpshufb	%xmm11,%xmm5,%xmm5
	vpaddq	-0x80(%rbp),%xmm0,%xmm8
	vpshufb	%xmm11,%xmm6,%xmm6
	vpaddq	-0x60(%rbp),%xmm1,%xmm9
	vpshufb	%xmm11,%xmm7,%xmm7
	vpaddq	-0x40(%rbp),%xmm2,%xmm10
	vpaddq	-0x20(%rbp),%xmm3,%xmm11
	vmovdqa	%xmm8,0x00(%rsp)
	vpaddq	0x00(%rbp),%xmm4,%xmm8
	vmovdqa	%xmm9,0x10(%rsp)
	vpaddq	0x20(%rbp),%xmm5,%xmm9
	vmovdqa	%xmm10,0x20(%rsp)
	vpaddq	0x40(%rbp),%xmm6,%xmm10
	vmovdqa	%xmm11,0x30(%rsp)
	vpaddq	0x60(%rbp),%xmm7,%xmm11
	vmovdqa	%xmm8,0x40(%rsp)
	mov	%rax,%r14
	vmovdqa	%xmm9,0x50(%rsp)
	mov	%rbx,%rdi
	vmovdqa	%xmm10,0x60(%rsp)
	xor	%rcx,%rdi			# magic
	vmovdqa	%xmm11,0x70(%rsp)
	mov	%r8,%r13
	jmp	.Lxop_00_47

.align	16
.Lxop_00_47:
	add	$256,%rbp
	vpalignr	$8,%xmm0,%xmm1,%xmm8
	ror	$23,%r13
	mov	%r14,%rax
	vpalignr	$8,%xmm4,%xmm5,%xmm11
	mov	%r9,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%r8,%r13
	xor	%r10,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%rax,%r14
	vpaddq	%xmm11,%xmm0,%xmm0
	and	%r8,%r12
	xor	%r8,%r13
	add	0(%rsp),%r11
	mov	%rax,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%r10,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%rbx,%r15
	add	%r12,%r11
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm7,%xmm11
	xor	%rax,%r14
	add	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rbx,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm7,%xmm10
	add	%r11,%rdx
	add	%rdi,%r11
	vpaddq	%xmm8,%xmm0,%xmm0
	mov	%rdx,%r13
	add	%r11,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%r11
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%r8,%r12
	ror	$5,%r14
	xor	%rdx,%r13
	xor	%r9,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%r11,%r14
	and	%rdx,%r12
	xor	%rdx,%r13
	vpaddq	%xmm11,%xmm0,%xmm0
	add	8(%rsp),%r10
	mov	%r11,%rdi
	xor	%r9,%r12
	ror	$6,%r14
	vpaddq	-128(%rbp),%xmm0,%xmm10
	xor	%rax,%rdi
	add	%r12,%r10
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r11,%r14
	add	%r13,%r10
	xor	%rax,%r15
	ror	$28,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	vmovdqa	%xmm10,0(%rsp)
	vpalignr	$8,%xmm1,%xmm2,%xmm8
	ror	$23,%r13
	mov	%r14,%r10
	vpalignr	$8,%xmm5,%xmm6,%xmm11
	mov	%rdx,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%rcx,%r13
	xor	%r8,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%r10,%r14
	vpaddq	%xmm11,%xmm1,%xmm1
	and	%rcx,%r12
	xor	%rcx,%r13
	add	16(%rsp),%r9
	mov	%r10,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%r8,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%r11,%r15
	add	%r12,%r9
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm0,%xmm11
	xor	%r10,%r14
	add	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r11,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm0,%xmm10
	add	%r9,%rbx
	add	%rdi,%r9
	vpaddq	%xmm8,%xmm1,%xmm1
	mov	%rbx,%r13
	add	%r9,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%r9
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%rcx,%r12
	ror	$5,%r14
	xor	%rbx,%r13
	xor	%rdx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%r9,%r14
	and	%rbx,%r12
	xor	%rbx,%r13
	vpaddq	%xmm11,%xmm1,%xmm1
	add	24(%rsp),%r8
	mov	%r9,%rdi
	xor	%rdx,%r12
	ror	$6,%r14
	vpaddq	-96(%rbp),%xmm1,%xmm10
	xor	%r10,%rdi
	add	%r12,%r8
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r9,%r14
	add	%r13,%r8
	xor	%r10,%r15
	ror	$28,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	vmovdqa	%xmm10,16(%rsp)
	vpalignr	$8,%xmm2,%xmm3,%xmm8
	ror	$23,%r13
	mov	%r14,%r8
	vpalignr	$8,%xmm6,%xmm7,%xmm11
	mov	%rbx,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%rax,%r13
	xor	%rcx,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%r8,%r14
	vpaddq	%xmm11,%xmm2,%xmm2
	and	%rax,%r12
	xor	%rax,%r13
	add	32(%rsp),%rdx
	mov	%r8,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%rcx,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%r9,%r15
	add	%r12,%rdx
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm1,%xmm11
	xor	%r8,%r14
	add	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r9,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm1,%xmm10
	add	%rdx,%r11
	add	%rdi,%rdx
	vpaddq	%xmm8,%xmm2,%xmm2
	mov	%r11,%r13
	add	%rdx,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%rdx
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%rax,%r12
	ror	$5,%r14
	xor	%r11,%r13
	xor	%rbx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%rdx,%r14
	and	%r11,%r12
	xor	%r11,%r13
	vpaddq	%xmm11,%xmm2,%xmm2
	add	40(%rsp),%rcx
	mov	%rdx,%rdi
	xor	%rbx,%r12
	ror	$6,%r14
	vpaddq	-64(%rbp),%xmm2,%xmm10
	xor	%r8,%rdi
	add	%r12,%rcx
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rdx,%r14
	add	%r13,%rcx
	xor	%r8,%r15
	ror	$28,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	vmovdqa	%xmm10,32(%rsp)
	vpalignr	$8,%xmm3,%xmm4,%xmm8
	ror	$23,%r13
	mov	%r14,%rcx
	vpalignr	$8,%xmm7,%xmm0,%xmm11
	mov	%r11,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%r10,%r13
	xor	%rax,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%rcx,%r14
	vpaddq	%xmm11,%xmm3,%xmm3
	and	%r10,%r12
	xor	%r10,%r13
	add	48(%rsp),%rbx
	mov	%rcx,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%rax,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%rdx,%r15
	add	%r12,%rbx
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm2,%xmm11
	xor	%rcx,%r14
	add	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rdx,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm2,%xmm10
	add	%rbx,%r9
	add	%rdi,%rbx
	vpaddq	%xmm8,%xmm3,%xmm3
	mov	%r9,%r13
	add	%rbx,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%rbx
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%r10,%r12
	ror	$5,%r14
	xor	%r9,%r13
	xor	%r11,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%rbx,%r14
	and	%r9,%r12
	xor	%r9,%r13
	vpaddq	%xmm11,%xmm3,%xmm3
	add	56(%rsp),%rax
	mov	%rbx,%rdi
	xor	%r11,%r12
	ror	$6,%r14
	vpaddq	-32(%rbp),%xmm3,%xmm10
	xor	%rcx,%rdi
	add	%r12,%rax
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rbx,%r14
	add	%r13,%rax
	xor	%rcx,%r15
	ror	$28,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	vmovdqa	%xmm10,48(%rsp)
	vpalignr	$8,%xmm4,%xmm5,%xmm8
	ror	$23,%r13
	mov	%r14,%rax
	vpalignr	$8,%xmm0,%xmm1,%xmm11
	mov	%r9,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%r8,%r13
	xor	%r10,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%rax,%r14
	vpaddq	%xmm11,%xmm4,%xmm4
	and	%r8,%r12
	xor	%r8,%r13
	add	64(%rsp),%r11
	mov	%rax,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%r10,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%rbx,%r15
	add	%r12,%r11
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm3,%xmm11
	xor	%rax,%r14
	add	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rbx,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm3,%xmm10
	add	%r11,%rdx
	add	%rdi,%r11
	vpaddq	%xmm8,%xmm4,%xmm4
	mov	%rdx,%r13
	add	%r11,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%r11
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%r8,%r12
	ror	$5,%r14
	xor	%rdx,%r13
	xor	%r9,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%r11,%r14
	and	%rdx,%r12
	xor	%rdx,%r13
	vpaddq	%xmm11,%xmm4,%xmm4
	add	72(%rsp),%r10
	mov	%r11,%rdi
	xor	%r9,%r12
	ror	$6,%r14
	vpaddq	0(%rbp),%xmm4,%xmm10
	xor	%rax,%rdi
	add	%r12,%r10
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r11,%r14
	add	%r13,%r10
	xor	%rax,%r15
	ror	$28,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	vmovdqa	%xmm10,64(%rsp)
	vpalignr	$8,%xmm5,%xmm6,%xmm8
	ror	$23,%r13
	mov	%r14,%r10
	vpalignr	$8,%xmm1,%xmm2,%xmm11
	mov	%rdx,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%rcx,%r13
	xor	%r8,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%r10,%r14
	vpaddq	%xmm11,%xmm5,%xmm5
	and	%rcx,%r12
	xor	%rcx,%r13
	add	80(%rsp),%r9
	mov	%r10,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%r8,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%r11,%r15
	add	%r12,%r9
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm4,%xmm11
	xor	%r10,%r14
	add	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r11,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm4,%xmm10
	add	%r9,%rbx
	add	%rdi,%r9
	vpaddq	%xmm8,%xmm5,%xmm5
	mov	%rbx,%r13
	add	%r9,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%r9
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%rcx,%r12
	ror	$5,%r14
	xor	%rbx,%r13
	xor	%rdx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%r9,%r14
	and	%rbx,%r12
	xor	%rbx,%r13
	vpaddq	%xmm11,%xmm5,%xmm5
	add	88(%rsp),%r8
	mov	%r9,%rdi
	xor	%rdx,%r12
	ror	$6,%r14
	vpaddq	32(%rbp),%xmm5,%xmm10
	xor	%r10,%rdi
	add	%r12,%r8
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r9,%r14
	add	%r13,%r8
	xor	%r10,%r15
	ror	$28,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	vmovdqa	%xmm10,80(%rsp)
	vpalignr	$8,%xmm6,%xmm7,%xmm8
	ror	$23,%r13
	mov	%r14,%r8
	vpalignr	$8,%xmm2,%xmm3,%xmm11
	mov	%rbx,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%rax,%r13
	xor	%rcx,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%r8,%r14
	vpaddq	%xmm11,%xmm6,%xmm6
	and	%rax,%r12
	xor	%rax,%r13
	add	96(%rsp),%rdx
	mov	%r8,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%rcx,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%r9,%r15
	add	%r12,%rdx
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm5,%xmm11
	xor	%r8,%r14
	add	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r9,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm5,%xmm10
	add	%rdx,%r11
	add	%rdi,%rdx
	vpaddq	%xmm8,%xmm6,%xmm6
	mov	%r11,%r13
	add	%rdx,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%rdx
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%rax,%r12
	ror	$5,%r14
	xor	%r11,%r13
	xor	%rbx,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%rdx,%r14
	and	%r11,%r12
	xor	%r11,%r13
	vpaddq	%xmm11,%xmm6,%xmm6
	add	104(%rsp),%rcx
	mov	%rdx,%rdi
	xor	%rbx,%r12
	ror	$6,%r14
	vpaddq	64(%rbp),%xmm6,%xmm10
	xor	%r8,%rdi
	add	%r12,%rcx
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rdx,%r14
	add	%r13,%rcx
	xor	%r8,%r15
	ror	$28,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	vmovdqa	%xmm10,96(%rsp)
	vpalignr	$8,%xmm7,%xmm0,%xmm8
	ror	$23,%r13
	mov	%r14,%rcx
	vpalignr	$8,%xmm3,%xmm4,%xmm11
	mov	%r11,%r12
	ror	$5,%r14
	vprotq	$56,%xmm8,%xmm9
	xor	%r10,%r13
	xor	%rax,%r12
	vpsrlq	$7,%xmm8,%xmm8
	ror	$4,%r13
	xor	%rcx,%r14
	vpaddq	%xmm11,%xmm7,%xmm7
	and	%r10,%r12
	xor	%r10,%r13
	add	112(%rsp),%rbx
	mov	%rcx,%r15
	vprotq	$7,%xmm9,%xmm10
	xor	%rax,%r12
	ror	$6,%r14
	vpxor	%xmm9,%xmm8,%xmm8
	xor	%rdx,%r15
	add	%r12,%rbx
	ror	$14,%r13
	and	%r15,%rdi
	vprotq	$3,%xmm6,%xmm11
	xor	%rcx,%r14
	add	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rdx,%rdi
	ror	$28,%r14
	vpsrlq	$6,%xmm6,%xmm10
	add	%rbx,%r9
	add	%rdi,%rbx
	vpaddq	%xmm8,%xmm7,%xmm7
	mov	%r9,%r13
	add	%rbx,%r14
	vprotq	$42,%xmm11,%xmm9
	ror	$23,%r13
	mov	%r14,%rbx
	vpxor	%xmm10,%xmm11,%xmm11
	mov	%r10,%r12
	ror	$5,%r14
	xor	%r9,%r13
	xor	%r11,%r12
	vpxor	%xmm9,%xmm11,%xmm11
	ror	$4,%r13
	xor	%rbx,%r14
	and	%r9,%r12
	xor	%r9,%r13
	vpaddq	%xmm11,%xmm7,%xmm7
	add	120(%rsp),%rax
	mov	%rbx,%rdi
	xor	%r11,%r12
	ror	$6,%r14
	vpaddq	96(%rbp),%xmm7,%xmm10
	xor	%rcx,%rdi
	add	%r12,%rax
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rbx,%r14
	add	%r13,%rax
	xor	%rcx,%r15
	ror	$28,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	vmovdqa	%xmm10,112(%rsp)
	cmpb	$0,135(%rbp)
	jne	.Lxop_00_47
	ror	$23,%r13
	mov	%r14,%rax
	mov	%r9,%r12
	ror	$5,%r14
	xor	%r8,%r13
	xor	%r10,%r12
	ror	$4,%r13
	xor	%rax,%r14
	and	%r8,%r12
	xor	%r8,%r13
	add	0(%rsp),%r11
	mov	%rax,%r15
	xor	%r10,%r12
	ror	$6,%r14
	xor	%rbx,%r15
	add	%r12,%r11
	ror	$14,%r13
	and	%r15,%rdi
	xor	%rax,%r14
	add	%r13,%r11
	xor	%rbx,%rdi
	ror	$28,%r14
	add	%r11,%rdx
	add	%rdi,%r11
	mov	%rdx,%r13
	add	%r11,%r14
	ror	$23,%r13
	mov	%r14,%r11
	mov	%r8,%r12
	ror	$5,%r14
	xor	%rdx,%r13
	xor	%r9,%r12
	ror	$4,%r13
	xor	%r11,%r14
	and	%rdx,%r12
	xor	%rdx,%r13
	add	8(%rsp),%r10
	mov	%r11,%rdi
	xor	%r9,%r12
	ror	$6,%r14
	xor	%rax,%rdi
	add	%r12,%r10
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r11,%r14
	add	%r13,%r10
	xor	%rax,%r15
	ror	$28,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	ror	$23,%r13
	mov	%r14,%r10
	mov	%rdx,%r12
	ror	$5,%r14
	xor	%rcx,%r13
	xor	%r8,%r12
	ror	$4,%r13
	xor	%r10,%r14
	and	%rcx,%r12
	xor	%rcx,%r13
	add	16(%rsp),%r9
	mov	%r10,%r15
	xor	%r8,%r12
	ror	$6,%r14
	xor	%r11,%r15
	add	%r12,%r9
	ror	$14,%r13
	and	%r15,%rdi
	xor	%r10,%r14
	add	%r13,%r9
	xor	%r11,%rdi
	ror	$28,%r14
	add	%r9,%rbx
	add	%rdi,%r9
	mov	%rbx,%r13
	add	%r9,%r14
	ror	$23,%r13
	mov	%r14,%r9
	mov	%rcx,%r12
	ror	$5,%r14
	xor	%rbx,%r13
	xor	%rdx,%r12
	ror	$4,%r13
	xor	%r9,%r14
	and	%rbx,%r12
	xor	%rbx,%r13
	add	24(%rsp),%r8
	mov	%r9,%rdi
	xor	%rdx,%r12
	ror	$6,%r14
	xor	%r10,%rdi
	add	%r12,%r8
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r9,%r14
	add	%r13,%r8
	xor	%r10,%r15
	ror	$28,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	ror	$23,%r13
	mov	%r14,%r8
	mov	%rbx,%r12
	ror	$5,%r14
	xor	%rax,%r13
	xor	%rcx,%r12
	ror	$4,%r13
	xor	%r8,%r14
	and	%rax,%r12
	xor	%rax,%r13
	add	32(%rsp),%rdx
	mov	%r8,%r15
	xor	%rcx,%r12
	ror	$6,%r14
	xor	%r9,%r15
	add	%r12,%rdx
	ror	$14,%r13
	and	%r15,%rdi
	xor	%r8,%r14
	add	%r13,%rdx
	xor	%r9,%rdi
	ror	$28,%r14
	add	%rdx,%r11
	add	%rdi,%rdx
	mov	%r11,%r13
	add	%rdx,%r14
	ror	$23,%r13
	mov	%r14,%rdx
	mov	%rax,%r12
	ror	$5,%r14
	xor	%r11,%r13
	xor	%rbx,%r12
	ror	$4,%r13
	xor	%rdx,%r14
	and	%r11,%r12
	xor	%r11,%r13
	add	40(%rsp),%rcx
	mov	%rdx,%rdi
	xor	%rbx,%r12
	ror	$6,%r14
	xor	%r8,%rdi
	add	%r12,%rcx
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rdx,%r14
	add	%r13,%rcx
	xor	%r8,%r15
	ror	$28,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	ror	$23,%r13
	mov	%r14,%rcx
	mov	%r11,%r12
	ror	$5,%r14
	xor	%r10,%r13
	xor	%rax,%r12
	ror	$4,%r13
	xor	%rcx,%r14
	and	%r10,%r12
	xor	%r10,%r13
	add	48(%rsp),%rbx
	mov	%rcx,%r15
	xor	%rax,%r12
	ror	$6,%r14
	xor	%rdx,%r15
	add	%r12,%rbx
	ror	$14,%r13
	and	%r15,%rdi
	xor	%rcx,%r14
	add	%r13,%rbx
	xor	%rdx,%rdi
	ror	$28,%r14
	add	%rbx,%r9
	add	%rdi,%rbx
	mov	%r9,%r13
	add	%rbx,%r14
	ror	$23,%r13
	mov	%r14,%rbx
	mov	%r10,%r12
	ror	$5,%r14
	xor	%r9,%r13
	xor	%r11,%r12
	ror	$4,%r13
	xor	%rbx,%r14
	and	%r9,%r12
	xor	%r9,%r13
	add	56(%rsp),%rax
	mov	%rbx,%rdi
	xor	%r11,%r12
	ror	$6,%r14
	xor	%rcx,%rdi
	add	%r12,%rax
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rbx,%r14
	add	%r13,%rax
	xor	%rcx,%r15
	ror	$28,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	ror	$23,%r13
	mov	%r14,%rax
	mov	%r9,%r12
	ror	$5,%r14
	xor	%r8,%r13
	xor	%r10,%r12
	ror	$4,%r13
	xor	%rax,%r14
	and	%r8,%r12
	xor	%r8,%r13
	add	64(%rsp),%r11
	mov	%rax,%r15
	xor	%r10,%r12
	ror	$6,%r14
	xor	%rbx,%r15
	add	%r12,%r11
	ror	$14,%r13
	and	%r15,%rdi
	xor	%rax,%r14
	add	%r13,%r11
	xor	%rbx,%rdi
	ror	$28,%r14
	add	%r11,%rdx
	add	%rdi,%r11
	mov	%rdx,%r13
	add	%r11,%r14
	ror	$23,%r13
	mov	%r14,%r11
	mov	%r8,%r12
	ror	$5,%r14
	xor	%rdx,%r13
	xor	%r9,%r12
	ror	$4,%r13
	xor	%r11,%r14
	and	%rdx,%r12
	xor	%rdx,%r13
	add	72(%rsp),%r10
	mov	%r11,%rdi
	xor	%r9,%r12
	ror	$6,%r14
	xor	%rax,%rdi
	add	%r12,%r10
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r11,%r14
	add	%r13,%r10
	xor	%rax,%r15
	ror	$28,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	ror	$23,%r13
	mov	%r14,%r10
	mov	%rdx,%r12
	ror	$5,%r14
	xor	%rcx,%r13
	xor	%r8,%r12
	ror	$4,%r13
	xor	%r10,%r14
	and	%rcx,%r12
	xor	%rcx,%r13
	add	80(%rsp),%r9
	mov	%r10,%r15
	xor	%r8,%r12
	ror	$6,%r14
	xor	%r11,%r15
	add	%r12,%r9
	ror	$14,%r13
	and	%r15,%rdi
	xor	%r10,%r14
	add	%r13,%r9
	xor	%r11,%rdi
	ror	$28,%r14
	add	%r9,%rbx
	add	%rdi,%r9
	mov	%rbx,%r13
	add	%r9,%r14
	ror	$23,%r13
	mov	%r14,%r9
	mov	%rcx,%r12
	ror	$5,%r14
	xor	%rbx,%r13
	xor	%rdx,%r12
	ror	$4,%r13
	xor	%r9,%r14
	and	%rbx,%r12
	xor	%rbx,%r13
	add	88(%rsp),%r8
	mov	%r9,%rdi
	xor	%rdx,%r12
	ror	$6,%r14
	xor	%r10,%rdi
	add	%r12,%r8
	ror	$14,%r13
	and	%rdi,%r15
	xor	%r9,%r14
	add	%r13,%r8
	xor	%r10,%r15
	ror	$28,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	ror	$23,%r13
	mov	%r14,%r8
	mov	%rbx,%r12
	ror	$5,%r14
	xor	%rax,%r13
	xor	%rcx,%r12
	ror	$4,%r13
	xor	%r8,%r14
	and	%rax,%r12
	xor	%rax,%r13
	add	96(%rsp),%rdx
	mov	%r8,%r15
	xor	%rcx,%r12
	ror	$6,%r14
	xor	%r9,%r15
	add	%r12,%rdx
	ror	$14,%r13
	and	%r15,%rdi
	xor	%r8,%r14
	add	%r13,%rdx
	xor	%r9,%rdi
	ror	$28,%r14
	add	%rdx,%r11
	add	%rdi,%rdx
	mov	%r11,%r13
	add	%rdx,%r14
	ror	$23,%r13
	mov	%r14,%rdx
	mov	%rax,%r12
	ror	$5,%r14
	xor	%r11,%r13
	xor	%rbx,%r12
	ror	$4,%r13
	xor	%rdx,%r14
	and	%r11,%r12
	xor	%r11,%r13
	add	104(%rsp),%rcx
	mov	%rdx,%rdi
	xor	%rbx,%r12
	ror	$6,%r14
	xor	%r8,%rdi
	add	%r12,%rcx
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rdx,%r14
	add	%r13,%rcx
	xor	%r8,%r15
	ror	$28,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	ror	$23,%r13
	mov	%r14,%rcx
	mov	%r11,%r12
	ror	$5,%r14
	xor	%r10,%r13
	xor	%rax,%r12
	ror	$4,%r13
	xor	%rcx,%r14
	and	%r10,%r12
	xor	%r10,%r13
	add	112(%rsp),%rbx
	mov	%rcx,%r15
	xor	%rax,%r12
	ror	$6,%r14
	xor	%rdx,%r15
	add	%r12,%rbx
	ror	$14,%r13
	and	%r15,%rdi
	xor	%rcx,%r14
	add	%r13,%rbx
	xor	%rdx,%rdi
	ror	$28,%r14
	add	%rbx,%r9
	add	%rdi,%rbx
	mov	%r9,%r13
	add	%rbx,%r14
	ror	$23,%r13
	mov	%r14,%rbx
	mov	%r10,%r12
	ror	$5,%r14
	xor	%r9,%r13
	xor	%r11,%r12
	ror	$4,%r13
	xor	%rbx,%r14
	and	%r9,%r12
	xor	%r9,%r13
	add	120(%rsp),%rax
	mov	%rbx,%rdi
	xor	%r11,%r12
	ror	$6,%r14
	xor	%rcx,%rdi
	add	%r12,%rax
	ror	$14,%r13
	and	%rdi,%r15
	xor	%rbx,%r14
	add	%r13,%rax
	xor	%rcx,%r15
	ror	$28,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	mov	16*8+0*8(%rsp),%rdi
	mov	%r14,%rax

	add	8*0(%rdi),%rax
	lea	16*8(%rsi),%rsi
	add	8*1(%rdi),%rbx
	add	8*2(%rdi),%rcx
	add	8*3(%rdi),%rdx
	add	8*4(%rdi),%r8
	add	8*5(%rdi),%r9
	add	8*6(%rdi),%r10
	add	8*7(%rdi),%r11

	cmp	16*8+2*8(%rsp),%rsi

	mov	%rax,8*0(%rdi)
	mov	%rbx,8*1(%rdi)
	mov	%rcx,8*2(%rdi)
	mov	%rdx,8*3(%rdi)
	mov	%r8,8*4(%rdi)
	mov	%r9,8*5(%rdi)
	mov	%r10,8*6(%rdi)
	mov	%r11,8*7(%rdi)
	jb	.Lloop_xop

	mov	152(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	vzeroupper
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
.Lepilogue_xop:
	ret
.cfi_endproc
.size	sha512_block_data_order_xop,.-sha512_block_data_order_xop
.type	sha512_block_data_order_avx,@function,3
.align	64
sha512_block_data_order_avx:
.cfi_startproc
.Lavx_shortcut:
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
	sub	$160,%rsp
	lea	(%rsi,%rdx,8),%rdx	# inp+num*16*8
	and	$-64,%rsp		# align stack frame
	mov	%rdi,16*8+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*8+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*8+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,152(%rsp)		# save copy of %rsp
.cfi_cfa_expression	152(%rsp),deref,+8
.Lprologue_avx:

	vzeroupper
	mov	8*0(%rdi),%rax
	mov	8*1(%rdi),%rbx
	mov	8*2(%rdi),%rcx
	mov	8*3(%rdi),%rdx
	mov	8*4(%rdi),%r8
	mov	8*5(%rdi),%r9
	mov	8*6(%rdi),%r10
	mov	8*7(%rdi),%r11
	jmp	.Lloop_avx
.align	16
.Lloop_avx:
	vmovdqa	K512+1280(%rip),%xmm11
	vmovdqu	0x00(%rsi),%xmm0
	lea	K512+0x80(%rip),%rbp	# size optimization
	vmovdqu	0x10(%rsi),%xmm1
	vmovdqu	0x20(%rsi),%xmm2
	vpshufb	%xmm11,%xmm0,%xmm0
	vmovdqu	0x30(%rsi),%xmm3
	vpshufb	%xmm11,%xmm1,%xmm1
	vmovdqu	0x40(%rsi),%xmm4
	vpshufb	%xmm11,%xmm2,%xmm2
	vmovdqu	0x50(%rsi),%xmm5
	vpshufb	%xmm11,%xmm3,%xmm3
	vmovdqu	0x60(%rsi),%xmm6
	vpshufb	%xmm11,%xmm4,%xmm4
	vmovdqu	0x70(%rsi),%xmm7
	vpshufb	%xmm11,%xmm5,%xmm5
	vpaddq	-0x80(%rbp),%xmm0,%xmm8
	vpshufb	%xmm11,%xmm6,%xmm6
	vpaddq	-0x60(%rbp),%xmm1,%xmm9
	vpshufb	%xmm11,%xmm7,%xmm7
	vpaddq	-0x40(%rbp),%xmm2,%xmm10
	vpaddq	-0x20(%rbp),%xmm3,%xmm11
	vmovdqa	%xmm8,0x00(%rsp)
	vpaddq	0x00(%rbp),%xmm4,%xmm8
	vmovdqa	%xmm9,0x10(%rsp)
	vpaddq	0x20(%rbp),%xmm5,%xmm9
	vmovdqa	%xmm10,0x20(%rsp)
	vpaddq	0x40(%rbp),%xmm6,%xmm10
	vmovdqa	%xmm11,0x30(%rsp)
	vpaddq	0x60(%rbp),%xmm7,%xmm11
	vmovdqa	%xmm8,0x40(%rsp)
	mov	%rax,%r14
	vmovdqa	%xmm9,0x50(%rsp)
	mov	%rbx,%rdi
	vmovdqa	%xmm10,0x60(%rsp)
	xor	%rcx,%rdi			# magic
	vmovdqa	%xmm11,0x70(%rsp)
	mov	%r8,%r13
	jmp	.Lavx_00_47

.align	16
.Lavx_00_47:
	add	$256,%rbp
	vpalignr	$8,%xmm0,%xmm1,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%rax
	vpalignr	$8,%xmm4,%xmm5,%xmm11
	mov	%r9,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%r8,%r13
	xor	%r10,%r12
	vpaddq	%xmm11,%xmm0,%xmm0
	shrd	$4,%r13,%r13
	xor	%rax,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%r8,%r12
	xor	%r8,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	0(%rsp),%r11
	mov	%rax,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%r10,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%rbx,%r15
	add	%r12,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%rax,%r14
	add	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rbx,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm7,%xmm11
	add	%r11,%rdx
	add	%rdi,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%rdx,%r13
	add	%r11,%r14
	vpsllq	$3,%xmm7,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%r11
	vpaddq	%xmm8,%xmm0,%xmm0
	mov	%r8,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm7,%xmm9
	xor	%rdx,%r13
	xor	%r9,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%r11,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%rdx,%r12
	xor	%rdx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	8(%rsp),%r10
	mov	%r11,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%r9,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%rax,%rdi
	add	%r12,%r10
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm0,%xmm0
	xor	%r11,%r14
	add	%r13,%r10
	vpaddq	-128(%rbp),%xmm0,%xmm10
	xor	%rax,%r15
	shrd	$28,%r14,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	vmovdqa	%xmm10,0(%rsp)
	vpalignr	$8,%xmm1,%xmm2,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%r10
	vpalignr	$8,%xmm5,%xmm6,%xmm11
	mov	%rdx,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%rcx,%r13
	xor	%r8,%r12
	vpaddq	%xmm11,%xmm1,%xmm1
	shrd	$4,%r13,%r13
	xor	%r10,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%rcx,%r12
	xor	%rcx,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	16(%rsp),%r9
	mov	%r10,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%r8,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%r11,%r15
	add	%r12,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%r10,%r14
	add	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r11,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm0,%xmm11
	add	%r9,%rbx
	add	%rdi,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%rbx,%r13
	add	%r9,%r14
	vpsllq	$3,%xmm0,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%r9
	vpaddq	%xmm8,%xmm1,%xmm1
	mov	%rcx,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm0,%xmm9
	xor	%rbx,%r13
	xor	%rdx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%r9,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%rbx,%r12
	xor	%rbx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	24(%rsp),%r8
	mov	%r9,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%rdx,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%r10,%rdi
	add	%r12,%r8
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm1,%xmm1
	xor	%r9,%r14
	add	%r13,%r8
	vpaddq	-96(%rbp),%xmm1,%xmm10
	xor	%r10,%r15
	shrd	$28,%r14,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	vmovdqa	%xmm10,16(%rsp)
	vpalignr	$8,%xmm2,%xmm3,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%r8
	vpalignr	$8,%xmm6,%xmm7,%xmm11
	mov	%rbx,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%rax,%r13
	xor	%rcx,%r12
	vpaddq	%xmm11,%xmm2,%xmm2
	shrd	$4,%r13,%r13
	xor	%r8,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%rax,%r12
	xor	%rax,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	32(%rsp),%rdx
	mov	%r8,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%rcx,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%r9,%r15
	add	%r12,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%r8,%r14
	add	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r9,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm1,%xmm11
	add	%rdx,%r11
	add	%rdi,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%r11,%r13
	add	%rdx,%r14
	vpsllq	$3,%xmm1,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%rdx
	vpaddq	%xmm8,%xmm2,%xmm2
	mov	%rax,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm1,%xmm9
	xor	%r11,%r13
	xor	%rbx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%rdx,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%r11,%r12
	xor	%r11,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	40(%rsp),%rcx
	mov	%rdx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%rbx,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%r8,%rdi
	add	%r12,%rcx
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm2,%xmm2
	xor	%rdx,%r14
	add	%r13,%rcx
	vpaddq	-64(%rbp),%xmm2,%xmm10
	xor	%r8,%r15
	shrd	$28,%r14,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	vmovdqa	%xmm10,32(%rsp)
	vpalignr	$8,%xmm3,%xmm4,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%rcx
	vpalignr	$8,%xmm7,%xmm0,%xmm11
	mov	%r11,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%r10,%r13
	xor	%rax,%r12
	vpaddq	%xmm11,%xmm3,%xmm3
	shrd	$4,%r13,%r13
	xor	%rcx,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%r10,%r12
	xor	%r10,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	48(%rsp),%rbx
	mov	%rcx,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%rax,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%rdx,%r15
	add	%r12,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%rcx,%r14
	add	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rdx,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm2,%xmm11
	add	%rbx,%r9
	add	%rdi,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%r9,%r13
	add	%rbx,%r14
	vpsllq	$3,%xmm2,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%rbx
	vpaddq	%xmm8,%xmm3,%xmm3
	mov	%r10,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm2,%xmm9
	xor	%r9,%r13
	xor	%r11,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%rbx,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%r9,%r12
	xor	%r9,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	56(%rsp),%rax
	mov	%rbx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%r11,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%rcx,%rdi
	add	%r12,%rax
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm3,%xmm3
	xor	%rbx,%r14
	add	%r13,%rax
	vpaddq	-32(%rbp),%xmm3,%xmm10
	xor	%rcx,%r15
	shrd	$28,%r14,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	vmovdqa	%xmm10,48(%rsp)
	vpalignr	$8,%xmm4,%xmm5,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%rax
	vpalignr	$8,%xmm0,%xmm1,%xmm11
	mov	%r9,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%r8,%r13
	xor	%r10,%r12
	vpaddq	%xmm11,%xmm4,%xmm4
	shrd	$4,%r13,%r13
	xor	%rax,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%r8,%r12
	xor	%r8,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	64(%rsp),%r11
	mov	%rax,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%r10,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%rbx,%r15
	add	%r12,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%rax,%r14
	add	%r13,%r11
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rbx,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm3,%xmm11
	add	%r11,%rdx
	add	%rdi,%r11
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%rdx,%r13
	add	%r11,%r14
	vpsllq	$3,%xmm3,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%r11
	vpaddq	%xmm8,%xmm4,%xmm4
	mov	%r8,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm3,%xmm9
	xor	%rdx,%r13
	xor	%r9,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%r11,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%rdx,%r12
	xor	%rdx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	72(%rsp),%r10
	mov	%r11,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%r9,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%rax,%rdi
	add	%r12,%r10
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm4,%xmm4
	xor	%r11,%r14
	add	%r13,%r10
	vpaddq	0(%rbp),%xmm4,%xmm10
	xor	%rax,%r15
	shrd	$28,%r14,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	vmovdqa	%xmm10,64(%rsp)
	vpalignr	$8,%xmm5,%xmm6,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%r10
	vpalignr	$8,%xmm1,%xmm2,%xmm11
	mov	%rdx,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%rcx,%r13
	xor	%r8,%r12
	vpaddq	%xmm11,%xmm5,%xmm5
	shrd	$4,%r13,%r13
	xor	%r10,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%rcx,%r12
	xor	%rcx,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	80(%rsp),%r9
	mov	%r10,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%r8,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%r11,%r15
	add	%r12,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%r10,%r14
	add	%r13,%r9
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r11,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm4,%xmm11
	add	%r9,%rbx
	add	%rdi,%r9
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%rbx,%r13
	add	%r9,%r14
	vpsllq	$3,%xmm4,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%r9
	vpaddq	%xmm8,%xmm5,%xmm5
	mov	%rcx,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm4,%xmm9
	xor	%rbx,%r13
	xor	%rdx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%r9,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%rbx,%r12
	xor	%rbx,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	88(%rsp),%r8
	mov	%r9,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%rdx,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%r10,%rdi
	add	%r12,%r8
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm5,%xmm5
	xor	%r9,%r14
	add	%r13,%r8
	vpaddq	32(%rbp),%xmm5,%xmm10
	xor	%r10,%r15
	shrd	$28,%r14,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	vmovdqa	%xmm10,80(%rsp)
	vpalignr	$8,%xmm6,%xmm7,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%r8
	vpalignr	$8,%xmm2,%xmm3,%xmm11
	mov	%rbx,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%rax,%r13
	xor	%rcx,%r12
	vpaddq	%xmm11,%xmm6,%xmm6
	shrd	$4,%r13,%r13
	xor	%r8,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%rax,%r12
	xor	%rax,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	96(%rsp),%rdx
	mov	%r8,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%rcx,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%r9,%r15
	add	%r12,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%r8,%r14
	add	%r13,%rdx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%r9,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm5,%xmm11
	add	%rdx,%r11
	add	%rdi,%rdx
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%r11,%r13
	add	%rdx,%r14
	vpsllq	$3,%xmm5,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%rdx
	vpaddq	%xmm8,%xmm6,%xmm6
	mov	%rax,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm5,%xmm9
	xor	%r11,%r13
	xor	%rbx,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%rdx,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%r11,%r12
	xor	%r11,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	104(%rsp),%rcx
	mov	%rdx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%rbx,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%r8,%rdi
	add	%r12,%rcx
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm6,%xmm6
	xor	%rdx,%r14
	add	%r13,%rcx
	vpaddq	64(%rbp),%xmm6,%xmm10
	xor	%r8,%r15
	shrd	$28,%r14,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	vmovdqa	%xmm10,96(%rsp)
	vpalignr	$8,%xmm7,%xmm0,%xmm8
	shrd	$23,%r13,%r13
	mov	%r14,%rcx
	vpalignr	$8,%xmm3,%xmm4,%xmm11
	mov	%r11,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$1,%xmm8,%xmm10
	xor	%r10,%r13
	xor	%rax,%r12
	vpaddq	%xmm11,%xmm7,%xmm7
	shrd	$4,%r13,%r13
	xor	%rcx,%r14
	vpsrlq	$7,%xmm8,%xmm11
	and	%r10,%r12
	xor	%r10,%r13
	vpsllq	$56,%xmm8,%xmm9
	add	112(%rsp),%rbx
	mov	%rcx,%r15
	vpxor	%xmm10,%xmm11,%xmm8
	xor	%rax,%r12
	shrd	$6,%r14,%r14
	vpsrlq	$7,%xmm10,%xmm10
	xor	%rdx,%r15
	add	%r12,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	vpsllq	$7,%xmm9,%xmm9
	xor	%rcx,%r14
	add	%r13,%rbx
	vpxor	%xmm10,%xmm8,%xmm8
	xor	%rdx,%rdi
	shrd	$28,%r14,%r14
	vpsrlq	$6,%xmm6,%xmm11
	add	%rbx,%r9
	add	%rdi,%rbx
	vpxor	%xmm9,%xmm8,%xmm8
	mov	%r9,%r13
	add	%rbx,%r14
	vpsllq	$3,%xmm6,%xmm10
	shrd	$23,%r13,%r13
	mov	%r14,%rbx
	vpaddq	%xmm8,%xmm7,%xmm7
	mov	%r10,%r12
	shrd	$5,%r14,%r14
	vpsrlq	$19,%xmm6,%xmm9
	xor	%r9,%r13
	xor	%r11,%r12
	vpxor	%xmm10,%xmm11,%xmm11
	shrd	$4,%r13,%r13
	xor	%rbx,%r14
	vpsllq	$42,%xmm10,%xmm10
	and	%r9,%r12
	xor	%r9,%r13
	vpxor	%xmm9,%xmm11,%xmm11
	add	120(%rsp),%rax
	mov	%rbx,%rdi
	vpsrlq	$42,%xmm9,%xmm9
	xor	%r11,%r12
	shrd	$6,%r14,%r14
	vpxor	%xmm10,%xmm11,%xmm11
	xor	%rcx,%rdi
	add	%r12,%rax
	vpxor	%xmm9,%xmm11,%xmm11
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	vpaddq	%xmm11,%xmm7,%xmm7
	xor	%rbx,%r14
	add	%r13,%rax
	vpaddq	96(%rbp),%xmm7,%xmm10
	xor	%rcx,%r15
	shrd	$28,%r14,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	vmovdqa	%xmm10,112(%rsp)
	cmpb	$0,135(%rbp)
	jne	.Lavx_00_47
	shrd	$23,%r13,%r13
	mov	%r14,%rax
	mov	%r9,%r12
	shrd	$5,%r14,%r14
	xor	%r8,%r13
	xor	%r10,%r12
	shrd	$4,%r13,%r13
	xor	%rax,%r14
	and	%r8,%r12
	xor	%r8,%r13
	add	0(%rsp),%r11
	mov	%rax,%r15
	xor	%r10,%r12
	shrd	$6,%r14,%r14
	xor	%rbx,%r15
	add	%r12,%r11
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%rax,%r14
	add	%r13,%r11
	xor	%rbx,%rdi
	shrd	$28,%r14,%r14
	add	%r11,%rdx
	add	%rdi,%r11
	mov	%rdx,%r13
	add	%r11,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r11
	mov	%r8,%r12
	shrd	$5,%r14,%r14
	xor	%rdx,%r13
	xor	%r9,%r12
	shrd	$4,%r13,%r13
	xor	%r11,%r14
	and	%rdx,%r12
	xor	%rdx,%r13
	add	8(%rsp),%r10
	mov	%r11,%rdi
	xor	%r9,%r12
	shrd	$6,%r14,%r14
	xor	%rax,%rdi
	add	%r12,%r10
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%r11,%r14
	add	%r13,%r10
	xor	%rax,%r15
	shrd	$28,%r14,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r10
	mov	%rdx,%r12
	shrd	$5,%r14,%r14
	xor	%rcx,%r13
	xor	%r8,%r12
	shrd	$4,%r13,%r13
	xor	%r10,%r14
	and	%rcx,%r12
	xor	%rcx,%r13
	add	16(%rsp),%r9
	mov	%r10,%r15
	xor	%r8,%r12
	shrd	$6,%r14,%r14
	xor	%r11,%r15
	add	%r12,%r9
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%r10,%r14
	add	%r13,%r9
	xor	%r11,%rdi
	shrd	$28,%r14,%r14
	add	%r9,%rbx
	add	%rdi,%r9
	mov	%rbx,%r13
	add	%r9,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r9
	mov	%rcx,%r12
	shrd	$5,%r14,%r14
	xor	%rbx,%r13
	xor	%rdx,%r12
	shrd	$4,%r13,%r13
	xor	%r9,%r14
	and	%rbx,%r12
	xor	%rbx,%r13
	add	24(%rsp),%r8
	mov	%r9,%rdi
	xor	%rdx,%r12
	shrd	$6,%r14,%r14
	xor	%r10,%rdi
	add	%r12,%r8
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%r9,%r14
	add	%r13,%r8
	xor	%r10,%r15
	shrd	$28,%r14,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r8
	mov	%rbx,%r12
	shrd	$5,%r14,%r14
	xor	%rax,%r13
	xor	%rcx,%r12
	shrd	$4,%r13,%r13
	xor	%r8,%r14
	and	%rax,%r12
	xor	%rax,%r13
	add	32(%rsp),%rdx
	mov	%r8,%r15
	xor	%rcx,%r12
	shrd	$6,%r14,%r14
	xor	%r9,%r15
	add	%r12,%rdx
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%r8,%r14
	add	%r13,%rdx
	xor	%r9,%rdi
	shrd	$28,%r14,%r14
	add	%rdx,%r11
	add	%rdi,%rdx
	mov	%r11,%r13
	add	%rdx,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%rdx
	mov	%rax,%r12
	shrd	$5,%r14,%r14
	xor	%r11,%r13
	xor	%rbx,%r12
	shrd	$4,%r13,%r13
	xor	%rdx,%r14
	and	%r11,%r12
	xor	%r11,%r13
	add	40(%rsp),%rcx
	mov	%rdx,%rdi
	xor	%rbx,%r12
	shrd	$6,%r14,%r14
	xor	%r8,%rdi
	add	%r12,%rcx
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%rdx,%r14
	add	%r13,%rcx
	xor	%r8,%r15
	shrd	$28,%r14,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%rcx
	mov	%r11,%r12
	shrd	$5,%r14,%r14
	xor	%r10,%r13
	xor	%rax,%r12
	shrd	$4,%r13,%r13
	xor	%rcx,%r14
	and	%r10,%r12
	xor	%r10,%r13
	add	48(%rsp),%rbx
	mov	%rcx,%r15
	xor	%rax,%r12
	shrd	$6,%r14,%r14
	xor	%rdx,%r15
	add	%r12,%rbx
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%rcx,%r14
	add	%r13,%rbx
	xor	%rdx,%rdi
	shrd	$28,%r14,%r14
	add	%rbx,%r9
	add	%rdi,%rbx
	mov	%r9,%r13
	add	%rbx,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%rbx
	mov	%r10,%r12
	shrd	$5,%r14,%r14
	xor	%r9,%r13
	xor	%r11,%r12
	shrd	$4,%r13,%r13
	xor	%rbx,%r14
	and	%r9,%r12
	xor	%r9,%r13
	add	56(%rsp),%rax
	mov	%rbx,%rdi
	xor	%r11,%r12
	shrd	$6,%r14,%r14
	xor	%rcx,%rdi
	add	%r12,%rax
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%rbx,%r14
	add	%r13,%rax
	xor	%rcx,%r15
	shrd	$28,%r14,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%rax
	mov	%r9,%r12
	shrd	$5,%r14,%r14
	xor	%r8,%r13
	xor	%r10,%r12
	shrd	$4,%r13,%r13
	xor	%rax,%r14
	and	%r8,%r12
	xor	%r8,%r13
	add	64(%rsp),%r11
	mov	%rax,%r15
	xor	%r10,%r12
	shrd	$6,%r14,%r14
	xor	%rbx,%r15
	add	%r12,%r11
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%rax,%r14
	add	%r13,%r11
	xor	%rbx,%rdi
	shrd	$28,%r14,%r14
	add	%r11,%rdx
	add	%rdi,%r11
	mov	%rdx,%r13
	add	%r11,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r11
	mov	%r8,%r12
	shrd	$5,%r14,%r14
	xor	%rdx,%r13
	xor	%r9,%r12
	shrd	$4,%r13,%r13
	xor	%r11,%r14
	and	%rdx,%r12
	xor	%rdx,%r13
	add	72(%rsp),%r10
	mov	%r11,%rdi
	xor	%r9,%r12
	shrd	$6,%r14,%r14
	xor	%rax,%rdi
	add	%r12,%r10
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%r11,%r14
	add	%r13,%r10
	xor	%rax,%r15
	shrd	$28,%r14,%r14
	add	%r10,%rcx
	add	%r15,%r10
	mov	%rcx,%r13
	add	%r10,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r10
	mov	%rdx,%r12
	shrd	$5,%r14,%r14
	xor	%rcx,%r13
	xor	%r8,%r12
	shrd	$4,%r13,%r13
	xor	%r10,%r14
	and	%rcx,%r12
	xor	%rcx,%r13
	add	80(%rsp),%r9
	mov	%r10,%r15
	xor	%r8,%r12
	shrd	$6,%r14,%r14
	xor	%r11,%r15
	add	%r12,%r9
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%r10,%r14
	add	%r13,%r9
	xor	%r11,%rdi
	shrd	$28,%r14,%r14
	add	%r9,%rbx
	add	%rdi,%r9
	mov	%rbx,%r13
	add	%r9,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r9
	mov	%rcx,%r12
	shrd	$5,%r14,%r14
	xor	%rbx,%r13
	xor	%rdx,%r12
	shrd	$4,%r13,%r13
	xor	%r9,%r14
	and	%rbx,%r12
	xor	%rbx,%r13
	add	88(%rsp),%r8
	mov	%r9,%rdi
	xor	%rdx,%r12
	shrd	$6,%r14,%r14
	xor	%r10,%rdi
	add	%r12,%r8
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%r9,%r14
	add	%r13,%r8
	xor	%r10,%r15
	shrd	$28,%r14,%r14
	add	%r8,%rax
	add	%r15,%r8
	mov	%rax,%r13
	add	%r8,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%r8
	mov	%rbx,%r12
	shrd	$5,%r14,%r14
	xor	%rax,%r13
	xor	%rcx,%r12
	shrd	$4,%r13,%r13
	xor	%r8,%r14
	and	%rax,%r12
	xor	%rax,%r13
	add	96(%rsp),%rdx
	mov	%r8,%r15
	xor	%rcx,%r12
	shrd	$6,%r14,%r14
	xor	%r9,%r15
	add	%r12,%rdx
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%r8,%r14
	add	%r13,%rdx
	xor	%r9,%rdi
	shrd	$28,%r14,%r14
	add	%rdx,%r11
	add	%rdi,%rdx
	mov	%r11,%r13
	add	%rdx,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%rdx
	mov	%rax,%r12
	shrd	$5,%r14,%r14
	xor	%r11,%r13
	xor	%rbx,%r12
	shrd	$4,%r13,%r13
	xor	%rdx,%r14
	and	%r11,%r12
	xor	%r11,%r13
	add	104(%rsp),%rcx
	mov	%rdx,%rdi
	xor	%rbx,%r12
	shrd	$6,%r14,%r14
	xor	%r8,%rdi
	add	%r12,%rcx
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%rdx,%r14
	add	%r13,%rcx
	xor	%r8,%r15
	shrd	$28,%r14,%r14
	add	%rcx,%r10
	add	%r15,%rcx
	mov	%r10,%r13
	add	%rcx,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%rcx
	mov	%r11,%r12
	shrd	$5,%r14,%r14
	xor	%r10,%r13
	xor	%rax,%r12
	shrd	$4,%r13,%r13
	xor	%rcx,%r14
	and	%r10,%r12
	xor	%r10,%r13
	add	112(%rsp),%rbx
	mov	%rcx,%r15
	xor	%rax,%r12
	shrd	$6,%r14,%r14
	xor	%rdx,%r15
	add	%r12,%rbx
	shrd	$14,%r13,%r13
	and	%r15,%rdi
	xor	%rcx,%r14
	add	%r13,%rbx
	xor	%rdx,%rdi
	shrd	$28,%r14,%r14
	add	%rbx,%r9
	add	%rdi,%rbx
	mov	%r9,%r13
	add	%rbx,%r14
	shrd	$23,%r13,%r13
	mov	%r14,%rbx
	mov	%r10,%r12
	shrd	$5,%r14,%r14
	xor	%r9,%r13
	xor	%r11,%r12
	shrd	$4,%r13,%r13
	xor	%rbx,%r14
	and	%r9,%r12
	xor	%r9,%r13
	add	120(%rsp),%rax
	mov	%rbx,%rdi
	xor	%r11,%r12
	shrd	$6,%r14,%r14
	xor	%rcx,%rdi
	add	%r12,%rax
	shrd	$14,%r13,%r13
	and	%rdi,%r15
	xor	%rbx,%r14
	add	%r13,%rax
	xor	%rcx,%r15
	shrd	$28,%r14,%r14
	add	%rax,%r8
	add	%r15,%rax
	mov	%r8,%r13
	add	%rax,%r14
	mov	16*8+0*8(%rsp),%rdi
	mov	%r14,%rax

	add	8*0(%rdi),%rax
	lea	16*8(%rsi),%rsi
	add	8*1(%rdi),%rbx
	add	8*2(%rdi),%rcx
	add	8*3(%rdi),%rdx
	add	8*4(%rdi),%r8
	add	8*5(%rdi),%r9
	add	8*6(%rdi),%r10
	add	8*7(%rdi),%r11

	cmp	16*8+2*8(%rsp),%rsi

	mov	%rax,8*0(%rdi)
	mov	%rbx,8*1(%rdi)
	mov	%rcx,8*2(%rdi)
	mov	%rdx,8*3(%rdi)
	mov	%r8,8*4(%rdi)
	mov	%r9,8*5(%rdi)
	mov	%r10,8*6(%rdi)
	mov	%r11,8*7(%rdi)
	jb	.Lloop_avx

	mov	152(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	vzeroupper
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
.Lepilogue_avx:
	ret
.cfi_endproc
.size	sha512_block_data_order_avx,.-sha512_block_data_order_avx
.type	sha512_block_data_order_avx2,@function,3
.align	64
sha512_block_data_order_avx2:
.cfi_startproc
.Lavx2_shortcut:
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
	sub	$1312,%rsp
	shl	$4,%rdx		# num*16
	and	$-256*8,%rsp		# align stack frame
	lea	(%rsi,%rdx,8),%rdx	# inp+num*16*8
	add	$1152,%rsp
	mov	%rdi,16*8+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*8+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*8+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,152(%rsp)		# save copy of %rsp
.cfi_cfa_expression	152(%rsp),deref,+8
.Lprologue_avx2:

	vzeroupper
	sub	$-16*8,%rsi		# inp++, size optimization
	mov	8*0(%rdi),%rax
	mov	%rsi,%r12		# borrow %r12
	mov	8*1(%rdi),%rbx
	cmp	%rdx,%rsi		# 16*8+2*8(%rsp)
	mov	8*2(%rdi),%rcx
	cmove	%rsp,%r12		# next block or random data
	mov	8*3(%rdi),%rdx
	mov	8*4(%rdi),%r8
	mov	8*5(%rdi),%r9
	mov	8*6(%rdi),%r10
	mov	8*7(%rdi),%r11
	jmp	.Loop_avx2
.align	16
.Loop_avx2:
	vmovdqu	-16*8(%rsi),%xmm0
	vmovdqu	-16*8+16(%rsi),%xmm1
	vmovdqu	-16*8+32(%rsi),%xmm2
	lea	K512+0x80(%rip),%rbp	# size optimization
	vmovdqu	-16*8+48(%rsi),%xmm3
	vmovdqu	-16*8+64(%rsi),%xmm4
	vmovdqu	-16*8+80(%rsi),%xmm5
	vmovdqu	-16*8+96(%rsi),%xmm6
	vmovdqu	-16*8+112(%rsi),%xmm7
	#mov	%rsi,16*8+1*8(%rsp)	# offload %rsi
	vmovdqa	1152(%rbp),%ymm10
	vinserti128	$1,(%r12),%ymm0,%ymm0
	vinserti128	$1,16(%r12),%ymm1,%ymm1
	 vpshufb	%ymm10,%ymm0,%ymm0
	vinserti128	$1,32(%r12),%ymm2,%ymm2
	 vpshufb	%ymm10,%ymm1,%ymm1
	vinserti128	$1,48(%r12),%ymm3,%ymm3
	 vpshufb	%ymm10,%ymm2,%ymm2
	vinserti128	$1,64(%r12),%ymm4,%ymm4
	 vpshufb	%ymm10,%ymm3,%ymm3
	vinserti128	$1,80(%r12),%ymm5,%ymm5
	 vpshufb	%ymm10,%ymm4,%ymm4
	vinserti128	$1,96(%r12),%ymm6,%ymm6
	 vpshufb	%ymm10,%ymm5,%ymm5
	vinserti128	$1,112(%r12),%ymm7,%ymm7

	vpaddq	-0x80(%rbp),%ymm0,%ymm8
	vpshufb	%ymm10,%ymm6,%ymm6
	vpaddq	-0x60(%rbp),%ymm1,%ymm9
	vpshufb	%ymm10,%ymm7,%ymm7
	vpaddq	-0x40(%rbp),%ymm2,%ymm10
	vpaddq	-0x20(%rbp),%ymm3,%ymm11
	vmovdqa	%ymm8,0x00(%rsp)
	vpaddq	0x00(%rbp),%ymm4,%ymm8
	vmovdqa	%ymm9,0x20(%rsp)
	vpaddq	0x20(%rbp),%ymm5,%ymm9
	vmovdqa	%ymm10,0x40(%rsp)
	vpaddq	0x40(%rbp),%ymm6,%ymm10
	vmovdqa	%ymm11,0x60(%rsp)
# temporarily use %rdi as frame pointer
	mov	152(%rsp),%rdi
.cfi_def_cfa	%rdi,8
	lea	-128(%rsp),%rsp
# the frame info is at 152(%rsp), but the stack is moving...
# so a second frame pointer is saved at -8(%rsp)
# that is in the red zone
	mov	%rdi,-8(%rsp)
.cfi_cfa_expression	%rsp-8,deref,+8
	vpaddq	0x60(%rbp),%ymm7,%ymm11
	vmovdqa	%ymm8,0x00(%rsp)
	xor	%r14,%r14
	vmovdqa	%ymm9,0x20(%rsp)
	mov	%rbx,%rdi
	vmovdqa	%ymm10,0x40(%rsp)
	xor	%rcx,%rdi			# magic
	vmovdqa	%ymm11,0x60(%rsp)
	mov	%r9,%r12
	add	$16*2*8,%rbp
	jmp	.Lavx2_00_47

.align	16
.Lavx2_00_47:
	lea	-128(%rsp),%rsp
.cfi_cfa_expression	%rsp+120,deref,+8
# copy secondary frame pointer to new location again at -8(%rsp)
	pushq	128-8(%rsp)
.cfi_cfa_expression	%rsp,deref,+8
	lea	8(%rsp),%rsp
.cfi_cfa_expression	%rsp-8,deref,+8
	vpalignr	$8,%ymm0,%ymm1,%ymm8
	add	0+2*128(%rsp),%r11
	and	%r8,%r12
	rorx	$41,%r8,%r13
	vpalignr	$8,%ymm4,%ymm5,%ymm11
	rorx	$18,%r8,%r15
	lea	(%rax,%r14),%rax
	lea	(%r11,%r12),%r11
	vpsrlq	$1,%ymm8,%ymm10
	andn	%r10,%r8,%r12
	xor	%r15,%r13
	rorx	$14,%r8,%r14
	vpaddq	%ymm11,%ymm0,%ymm0
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%r11,%r12),%r11
	xor	%r14,%r13
	mov	%rax,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%rax,%r12
	lea	(%r11,%r13),%r11
	xor	%rbx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%rax,%r14
	rorx	$28,%rax,%r13
	lea	(%rdx,%r11),%rdx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rbx,%rdi
	vpsrlq	$6,%ymm7,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%r11,%rdi),%r11
	mov	%r8,%r12
	vpsllq	$3,%ymm7,%ymm10
	vpaddq	%ymm8,%ymm0,%ymm0
	add	8+2*128(%rsp),%r10
	and	%rdx,%r12
	rorx	$41,%rdx,%r13
	vpsrlq	$19,%ymm7,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%rdx,%rdi
	lea	(%r11,%r14),%r11
	lea	(%r10,%r12),%r10
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%r9,%rdx,%r12
	xor	%rdi,%r13
	rorx	$14,%rdx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%r10,%r12),%r10
	xor	%r14,%r13
	mov	%r11,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%r11,%r12
	lea	(%r10,%r13),%r10
	xor	%rax,%rdi
	vpaddq	%ymm11,%ymm0,%ymm0
	rorx	$34,%r11,%r14
	rorx	$28,%r11,%r13
	lea	(%rcx,%r10),%rcx
	vpaddq	-128(%rbp),%ymm0,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rax,%r15
	xor	%r13,%r14
	lea	(%r10,%r15),%r10
	mov	%rdx,%r12
	vmovdqa	%ymm10,0(%rsp)
	vpalignr	$8,%ymm1,%ymm2,%ymm8
	add	32+2*128(%rsp),%r9
	and	%rcx,%r12
	rorx	$41,%rcx,%r13
	vpalignr	$8,%ymm5,%ymm6,%ymm11
	rorx	$18,%rcx,%r15
	lea	(%r10,%r14),%r10
	lea	(%r9,%r12),%r9
	vpsrlq	$1,%ymm8,%ymm10
	andn	%r8,%rcx,%r12
	xor	%r15,%r13
	rorx	$14,%rcx,%r14
	vpaddq	%ymm11,%ymm1,%ymm1
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%r9,%r12),%r9
	xor	%r14,%r13
	mov	%r10,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%r10,%r12
	lea	(%r9,%r13),%r9
	xor	%r11,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%r10,%r14
	rorx	$28,%r10,%r13
	lea	(%rbx,%r9),%rbx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r11,%rdi
	vpsrlq	$6,%ymm0,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%r9,%rdi),%r9
	mov	%rcx,%r12
	vpsllq	$3,%ymm0,%ymm10
	vpaddq	%ymm8,%ymm1,%ymm1
	add	40+2*128(%rsp),%r8
	and	%rbx,%r12
	rorx	$41,%rbx,%r13
	vpsrlq	$19,%ymm0,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%rbx,%rdi
	lea	(%r9,%r14),%r9
	lea	(%r8,%r12),%r8
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%rdx,%rbx,%r12
	xor	%rdi,%r13
	rorx	$14,%rbx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%r8,%r12),%r8
	xor	%r14,%r13
	mov	%r9,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%r9,%r12
	lea	(%r8,%r13),%r8
	xor	%r10,%rdi
	vpaddq	%ymm11,%ymm1,%ymm1
	rorx	$34,%r9,%r14
	rorx	$28,%r9,%r13
	lea	(%rax,%r8),%rax
	vpaddq	-96(%rbp),%ymm1,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r10,%r15
	xor	%r13,%r14
	lea	(%r8,%r15),%r8
	mov	%rbx,%r12
	vmovdqa	%ymm10,32(%rsp)
	vpalignr	$8,%ymm2,%ymm3,%ymm8
	add	64+2*128(%rsp),%rdx
	and	%rax,%r12
	rorx	$41,%rax,%r13
	vpalignr	$8,%ymm6,%ymm7,%ymm11
	rorx	$18,%rax,%r15
	lea	(%r8,%r14),%r8
	lea	(%rdx,%r12),%rdx
	vpsrlq	$1,%ymm8,%ymm10
	andn	%rcx,%rax,%r12
	xor	%r15,%r13
	rorx	$14,%rax,%r14
	vpaddq	%ymm11,%ymm2,%ymm2
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%rdx,%r12),%rdx
	xor	%r14,%r13
	mov	%r8,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%r8,%r12
	lea	(%rdx,%r13),%rdx
	xor	%r9,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%r8,%r14
	rorx	$28,%r8,%r13
	lea	(%r11,%rdx),%r11
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r9,%rdi
	vpsrlq	$6,%ymm1,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%rdx,%rdi),%rdx
	mov	%rax,%r12
	vpsllq	$3,%ymm1,%ymm10
	vpaddq	%ymm8,%ymm2,%ymm2
	add	72+2*128(%rsp),%rcx
	and	%r11,%r12
	rorx	$41,%r11,%r13
	vpsrlq	$19,%ymm1,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%r11,%rdi
	lea	(%rdx,%r14),%rdx
	lea	(%rcx,%r12),%rcx
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%rbx,%r11,%r12
	xor	%rdi,%r13
	rorx	$14,%r11,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%rcx,%r12),%rcx
	xor	%r14,%r13
	mov	%rdx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%rdx,%r12
	lea	(%rcx,%r13),%rcx
	xor	%r8,%rdi
	vpaddq	%ymm11,%ymm2,%ymm2
	rorx	$34,%rdx,%r14
	rorx	$28,%rdx,%r13
	lea	(%r10,%rcx),%r10
	vpaddq	-64(%rbp),%ymm2,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r8,%r15
	xor	%r13,%r14
	lea	(%rcx,%r15),%rcx
	mov	%r11,%r12
	vmovdqa	%ymm10,64(%rsp)
	vpalignr	$8,%ymm3,%ymm4,%ymm8
	add	96+2*128(%rsp),%rbx
	and	%r10,%r12
	rorx	$41,%r10,%r13
	vpalignr	$8,%ymm7,%ymm0,%ymm11
	rorx	$18,%r10,%r15
	lea	(%rcx,%r14),%rcx
	lea	(%rbx,%r12),%rbx
	vpsrlq	$1,%ymm8,%ymm10
	andn	%rax,%r10,%r12
	xor	%r15,%r13
	rorx	$14,%r10,%r14
	vpaddq	%ymm11,%ymm3,%ymm3
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%rbx,%r12),%rbx
	xor	%r14,%r13
	mov	%rcx,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%rcx,%r12
	lea	(%rbx,%r13),%rbx
	xor	%rdx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%rcx,%r14
	rorx	$28,%rcx,%r13
	lea	(%r9,%rbx),%r9
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rdx,%rdi
	vpsrlq	$6,%ymm2,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%rbx,%rdi),%rbx
	mov	%r10,%r12
	vpsllq	$3,%ymm2,%ymm10
	vpaddq	%ymm8,%ymm3,%ymm3
	add	104+2*128(%rsp),%rax
	and	%r9,%r12
	rorx	$41,%r9,%r13
	vpsrlq	$19,%ymm2,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%r9,%rdi
	lea	(%rbx,%r14),%rbx
	lea	(%rax,%r12),%rax
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%r11,%r9,%r12
	xor	%rdi,%r13
	rorx	$14,%r9,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%rax,%r12),%rax
	xor	%r14,%r13
	mov	%rbx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%rbx,%r12
	lea	(%rax,%r13),%rax
	xor	%rcx,%rdi
	vpaddq	%ymm11,%ymm3,%ymm3
	rorx	$34,%rbx,%r14
	rorx	$28,%rbx,%r13
	lea	(%r8,%rax),%r8
	vpaddq	-32(%rbp),%ymm3,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rcx,%r15
	xor	%r13,%r14
	lea	(%rax,%r15),%rax
	mov	%r9,%r12
	vmovdqa	%ymm10,96(%rsp)
	lea	-128(%rsp),%rsp
.cfi_cfa_expression	%rsp+120,deref,+8
# copy secondary frame pointer to new location again at -8(%rsp)
	pushq	128-8(%rsp)
.cfi_cfa_expression	%rsp,deref,+8
	lea	8(%rsp),%rsp
.cfi_cfa_expression	%rsp-8,deref,+8
	vpalignr	$8,%ymm4,%ymm5,%ymm8
	add	0+2*128(%rsp),%r11
	and	%r8,%r12
	rorx	$41,%r8,%r13
	vpalignr	$8,%ymm0,%ymm1,%ymm11
	rorx	$18,%r8,%r15
	lea	(%rax,%r14),%rax
	lea	(%r11,%r12),%r11
	vpsrlq	$1,%ymm8,%ymm10
	andn	%r10,%r8,%r12
	xor	%r15,%r13
	rorx	$14,%r8,%r14
	vpaddq	%ymm11,%ymm4,%ymm4
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%r11,%r12),%r11
	xor	%r14,%r13
	mov	%rax,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%rax,%r12
	lea	(%r11,%r13),%r11
	xor	%rbx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%rax,%r14
	rorx	$28,%rax,%r13
	lea	(%rdx,%r11),%rdx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rbx,%rdi
	vpsrlq	$6,%ymm3,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%r11,%rdi),%r11
	mov	%r8,%r12
	vpsllq	$3,%ymm3,%ymm10
	vpaddq	%ymm8,%ymm4,%ymm4
	add	8+2*128(%rsp),%r10
	and	%rdx,%r12
	rorx	$41,%rdx,%r13
	vpsrlq	$19,%ymm3,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%rdx,%rdi
	lea	(%r11,%r14),%r11
	lea	(%r10,%r12),%r10
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%r9,%rdx,%r12
	xor	%rdi,%r13
	rorx	$14,%rdx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%r10,%r12),%r10
	xor	%r14,%r13
	mov	%r11,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%r11,%r12
	lea	(%r10,%r13),%r10
	xor	%rax,%rdi
	vpaddq	%ymm11,%ymm4,%ymm4
	rorx	$34,%r11,%r14
	rorx	$28,%r11,%r13
	lea	(%rcx,%r10),%rcx
	vpaddq	0(%rbp),%ymm4,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rax,%r15
	xor	%r13,%r14
	lea	(%r10,%r15),%r10
	mov	%rdx,%r12
	vmovdqa	%ymm10,0(%rsp)
	vpalignr	$8,%ymm5,%ymm6,%ymm8
	add	32+2*128(%rsp),%r9
	and	%rcx,%r12
	rorx	$41,%rcx,%r13
	vpalignr	$8,%ymm1,%ymm2,%ymm11
	rorx	$18,%rcx,%r15
	lea	(%r10,%r14),%r10
	lea	(%r9,%r12),%r9
	vpsrlq	$1,%ymm8,%ymm10
	andn	%r8,%rcx,%r12
	xor	%r15,%r13
	rorx	$14,%rcx,%r14
	vpaddq	%ymm11,%ymm5,%ymm5
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%r9,%r12),%r9
	xor	%r14,%r13
	mov	%r10,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%r10,%r12
	lea	(%r9,%r13),%r9
	xor	%r11,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%r10,%r14
	rorx	$28,%r10,%r13
	lea	(%rbx,%r9),%rbx
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r11,%rdi
	vpsrlq	$6,%ymm4,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%r9,%rdi),%r9
	mov	%rcx,%r12
	vpsllq	$3,%ymm4,%ymm10
	vpaddq	%ymm8,%ymm5,%ymm5
	add	40+2*128(%rsp),%r8
	and	%rbx,%r12
	rorx	$41,%rbx,%r13
	vpsrlq	$19,%ymm4,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%rbx,%rdi
	lea	(%r9,%r14),%r9
	lea	(%r8,%r12),%r8
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%rdx,%rbx,%r12
	xor	%rdi,%r13
	rorx	$14,%rbx,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%r8,%r12),%r8
	xor	%r14,%r13
	mov	%r9,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%r9,%r12
	lea	(%r8,%r13),%r8
	xor	%r10,%rdi
	vpaddq	%ymm11,%ymm5,%ymm5
	rorx	$34,%r9,%r14
	rorx	$28,%r9,%r13
	lea	(%rax,%r8),%rax
	vpaddq	32(%rbp),%ymm5,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r10,%r15
	xor	%r13,%r14
	lea	(%r8,%r15),%r8
	mov	%rbx,%r12
	vmovdqa	%ymm10,32(%rsp)
	vpalignr	$8,%ymm6,%ymm7,%ymm8
	add	64+2*128(%rsp),%rdx
	and	%rax,%r12
	rorx	$41,%rax,%r13
	vpalignr	$8,%ymm2,%ymm3,%ymm11
	rorx	$18,%rax,%r15
	lea	(%r8,%r14),%r8
	lea	(%rdx,%r12),%rdx
	vpsrlq	$1,%ymm8,%ymm10
	andn	%rcx,%rax,%r12
	xor	%r15,%r13
	rorx	$14,%rax,%r14
	vpaddq	%ymm11,%ymm6,%ymm6
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%rdx,%r12),%rdx
	xor	%r14,%r13
	mov	%r8,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%r8,%r12
	lea	(%rdx,%r13),%rdx
	xor	%r9,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%r8,%r14
	rorx	$28,%r8,%r13
	lea	(%r11,%rdx),%r11
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r9,%rdi
	vpsrlq	$6,%ymm5,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%rdx,%rdi),%rdx
	mov	%rax,%r12
	vpsllq	$3,%ymm5,%ymm10
	vpaddq	%ymm8,%ymm6,%ymm6
	add	72+2*128(%rsp),%rcx
	and	%r11,%r12
	rorx	$41,%r11,%r13
	vpsrlq	$19,%ymm5,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%r11,%rdi
	lea	(%rdx,%r14),%rdx
	lea	(%rcx,%r12),%rcx
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%rbx,%r11,%r12
	xor	%rdi,%r13
	rorx	$14,%r11,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%rcx,%r12),%rcx
	xor	%r14,%r13
	mov	%rdx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%rdx,%r12
	lea	(%rcx,%r13),%rcx
	xor	%r8,%rdi
	vpaddq	%ymm11,%ymm6,%ymm6
	rorx	$34,%rdx,%r14
	rorx	$28,%rdx,%r13
	lea	(%r10,%rcx),%r10
	vpaddq	64(%rbp),%ymm6,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r8,%r15
	xor	%r13,%r14
	lea	(%rcx,%r15),%rcx
	mov	%r11,%r12
	vmovdqa	%ymm10,64(%rsp)
	vpalignr	$8,%ymm7,%ymm0,%ymm8
	add	96+2*128(%rsp),%rbx
	and	%r10,%r12
	rorx	$41,%r10,%r13
	vpalignr	$8,%ymm3,%ymm4,%ymm11
	rorx	$18,%r10,%r15
	lea	(%rcx,%r14),%rcx
	lea	(%rbx,%r12),%rbx
	vpsrlq	$1,%ymm8,%ymm10
	andn	%rax,%r10,%r12
	xor	%r15,%r13
	rorx	$14,%r10,%r14
	vpaddq	%ymm11,%ymm7,%ymm7
	vpsrlq	$7,%ymm8,%ymm11
	lea	(%rbx,%r12),%rbx
	xor	%r14,%r13
	mov	%rcx,%r15
	vpsllq	$56,%ymm8,%ymm9
	vpxor	%ymm10,%ymm11,%ymm8
	rorx	$39,%rcx,%r12
	lea	(%rbx,%r13),%rbx
	xor	%rdx,%r15
	vpsrlq	$7,%ymm10,%ymm10
	vpxor	%ymm9,%ymm8,%ymm8
	rorx	$34,%rcx,%r14
	rorx	$28,%rcx,%r13
	lea	(%r9,%rbx),%r9
	vpsllq	$7,%ymm9,%ymm9
	vpxor	%ymm10,%ymm8,%ymm8
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rdx,%rdi
	vpsrlq	$6,%ymm6,%ymm11
	vpxor	%ymm9,%ymm8,%ymm8
	xor	%r13,%r14
	lea	(%rbx,%rdi),%rbx
	mov	%r10,%r12
	vpsllq	$3,%ymm6,%ymm10
	vpaddq	%ymm8,%ymm7,%ymm7
	add	104+2*128(%rsp),%rax
	and	%r9,%r12
	rorx	$41,%r9,%r13
	vpsrlq	$19,%ymm6,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	rorx	$18,%r9,%rdi
	lea	(%rbx,%r14),%rbx
	lea	(%rax,%r12),%rax
	vpsllq	$42,%ymm10,%ymm10
	vpxor	%ymm9,%ymm11,%ymm11
	andn	%r11,%r9,%r12
	xor	%rdi,%r13
	rorx	$14,%r9,%r14
	vpsrlq	$42,%ymm9,%ymm9
	vpxor	%ymm10,%ymm11,%ymm11
	lea	(%rax,%r12),%rax
	xor	%r14,%r13
	mov	%rbx,%rdi
	vpxor	%ymm9,%ymm11,%ymm11
	rorx	$39,%rbx,%r12
	lea	(%rax,%r13),%rax
	xor	%rcx,%rdi
	vpaddq	%ymm11,%ymm7,%ymm7
	rorx	$34,%rbx,%r14
	rorx	$28,%rbx,%r13
	lea	(%r8,%rax),%r8
	vpaddq	96(%rbp),%ymm7,%ymm10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rcx,%r15
	xor	%r13,%r14
	lea	(%rax,%r15),%rax
	mov	%r9,%r12
	vmovdqa	%ymm10,96(%rsp)
	lea	256(%rbp),%rbp
	cmpb	$0,-121(%rbp)
	jne	.Lavx2_00_47
	add	0+128(%rsp),%r11
	and	%r8,%r12
	rorx	$41,%r8,%r13
	rorx	$18,%r8,%r15
	lea	(%rax,%r14),%rax
	lea	(%r11,%r12),%r11
	andn	%r10,%r8,%r12
	xor	%r15,%r13
	rorx	$14,%r8,%r14
	lea	(%r11,%r12),%r11
	xor	%r14,%r13
	mov	%rax,%r15
	rorx	$39,%rax,%r12
	lea	(%r11,%r13),%r11
	xor	%rbx,%r15
	rorx	$34,%rax,%r14
	rorx	$28,%rax,%r13
	lea	(%rdx,%r11),%rdx
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rbx,%rdi
	xor	%r13,%r14
	lea	(%r11,%rdi),%r11
	mov	%r8,%r12
	add	8+128(%rsp),%r10
	and	%rdx,%r12
	rorx	$41,%rdx,%r13
	rorx	$18,%rdx,%rdi
	lea	(%r11,%r14),%r11
	lea	(%r10,%r12),%r10
	andn	%r9,%rdx,%r12
	xor	%rdi,%r13
	rorx	$14,%rdx,%r14
	lea	(%r10,%r12),%r10
	xor	%r14,%r13
	mov	%r11,%rdi
	rorx	$39,%r11,%r12
	lea	(%r10,%r13),%r10
	xor	%rax,%rdi
	rorx	$34,%r11,%r14
	rorx	$28,%r11,%r13
	lea	(%rcx,%r10),%rcx
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rax,%r15
	xor	%r13,%r14
	lea	(%r10,%r15),%r10
	mov	%rdx,%r12
	add	32+128(%rsp),%r9
	and	%rcx,%r12
	rorx	$41,%rcx,%r13
	rorx	$18,%rcx,%r15
	lea	(%r10,%r14),%r10
	lea	(%r9,%r12),%r9
	andn	%r8,%rcx,%r12
	xor	%r15,%r13
	rorx	$14,%rcx,%r14
	lea	(%r9,%r12),%r9
	xor	%r14,%r13
	mov	%r10,%r15
	rorx	$39,%r10,%r12
	lea	(%r9,%r13),%r9
	xor	%r11,%r15
	rorx	$34,%r10,%r14
	rorx	$28,%r10,%r13
	lea	(%rbx,%r9),%rbx
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r11,%rdi
	xor	%r13,%r14
	lea	(%r9,%rdi),%r9
	mov	%rcx,%r12
	add	40+128(%rsp),%r8
	and	%rbx,%r12
	rorx	$41,%rbx,%r13
	rorx	$18,%rbx,%rdi
	lea	(%r9,%r14),%r9
	lea	(%r8,%r12),%r8
	andn	%rdx,%rbx,%r12
	xor	%rdi,%r13
	rorx	$14,%rbx,%r14
	lea	(%r8,%r12),%r8
	xor	%r14,%r13
	mov	%r9,%rdi
	rorx	$39,%r9,%r12
	lea	(%r8,%r13),%r8
	xor	%r10,%rdi
	rorx	$34,%r9,%r14
	rorx	$28,%r9,%r13
	lea	(%rax,%r8),%rax
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r10,%r15
	xor	%r13,%r14
	lea	(%r8,%r15),%r8
	mov	%rbx,%r12
	add	64+128(%rsp),%rdx
	and	%rax,%r12
	rorx	$41,%rax,%r13
	rorx	$18,%rax,%r15
	lea	(%r8,%r14),%r8
	lea	(%rdx,%r12),%rdx
	andn	%rcx,%rax,%r12
	xor	%r15,%r13
	rorx	$14,%rax,%r14
	lea	(%rdx,%r12),%rdx
	xor	%r14,%r13
	mov	%r8,%r15
	rorx	$39,%r8,%r12
	lea	(%rdx,%r13),%rdx
	xor	%r9,%r15
	rorx	$34,%r8,%r14
	rorx	$28,%r8,%r13
	lea	(%r11,%rdx),%r11
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r9,%rdi
	xor	%r13,%r14
	lea	(%rdx,%rdi),%rdx
	mov	%rax,%r12
	add	72+128(%rsp),%rcx
	and	%r11,%r12
	rorx	$41,%r11,%r13
	rorx	$18,%r11,%rdi
	lea	(%rdx,%r14),%rdx
	lea	(%rcx,%r12),%rcx
	andn	%rbx,%r11,%r12
	xor	%rdi,%r13
	rorx	$14,%r11,%r14
	lea	(%rcx,%r12),%rcx
	xor	%r14,%r13
	mov	%rdx,%rdi
	rorx	$39,%rdx,%r12
	lea	(%rcx,%r13),%rcx
	xor	%r8,%rdi
	rorx	$34,%rdx,%r14
	rorx	$28,%rdx,%r13
	lea	(%r10,%rcx),%r10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r8,%r15
	xor	%r13,%r14
	lea	(%rcx,%r15),%rcx
	mov	%r11,%r12
	add	96+128(%rsp),%rbx
	and	%r10,%r12
	rorx	$41,%r10,%r13
	rorx	$18,%r10,%r15
	lea	(%rcx,%r14),%rcx
	lea	(%rbx,%r12),%rbx
	andn	%rax,%r10,%r12
	xor	%r15,%r13
	rorx	$14,%r10,%r14
	lea	(%rbx,%r12),%rbx
	xor	%r14,%r13
	mov	%rcx,%r15
	rorx	$39,%rcx,%r12
	lea	(%rbx,%r13),%rbx
	xor	%rdx,%r15
	rorx	$34,%rcx,%r14
	rorx	$28,%rcx,%r13
	lea	(%r9,%rbx),%r9
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rdx,%rdi
	xor	%r13,%r14
	lea	(%rbx,%rdi),%rbx
	mov	%r10,%r12
	add	104+128(%rsp),%rax
	and	%r9,%r12
	rorx	$41,%r9,%r13
	rorx	$18,%r9,%rdi
	lea	(%rbx,%r14),%rbx
	lea	(%rax,%r12),%rax
	andn	%r11,%r9,%r12
	xor	%rdi,%r13
	rorx	$14,%r9,%r14
	lea	(%rax,%r12),%rax
	xor	%r14,%r13
	mov	%rbx,%rdi
	rorx	$39,%rbx,%r12
	lea	(%rax,%r13),%rax
	xor	%rcx,%rdi
	rorx	$34,%rbx,%r14
	rorx	$28,%rbx,%r13
	lea	(%r8,%rax),%r8
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rcx,%r15
	xor	%r13,%r14
	lea	(%rax,%r15),%rax
	mov	%r9,%r12
	add	0(%rsp),%r11
	and	%r8,%r12
	rorx	$41,%r8,%r13
	rorx	$18,%r8,%r15
	lea	(%rax,%r14),%rax
	lea	(%r11,%r12),%r11
	andn	%r10,%r8,%r12
	xor	%r15,%r13
	rorx	$14,%r8,%r14
	lea	(%r11,%r12),%r11
	xor	%r14,%r13
	mov	%rax,%r15
	rorx	$39,%rax,%r12
	lea	(%r11,%r13),%r11
	xor	%rbx,%r15
	rorx	$34,%rax,%r14
	rorx	$28,%rax,%r13
	lea	(%rdx,%r11),%rdx
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rbx,%rdi
	xor	%r13,%r14
	lea	(%r11,%rdi),%r11
	mov	%r8,%r12
	add	8(%rsp),%r10
	and	%rdx,%r12
	rorx	$41,%rdx,%r13
	rorx	$18,%rdx,%rdi
	lea	(%r11,%r14),%r11
	lea	(%r10,%r12),%r10
	andn	%r9,%rdx,%r12
	xor	%rdi,%r13
	rorx	$14,%rdx,%r14
	lea	(%r10,%r12),%r10
	xor	%r14,%r13
	mov	%r11,%rdi
	rorx	$39,%r11,%r12
	lea	(%r10,%r13),%r10
	xor	%rax,%rdi
	rorx	$34,%r11,%r14
	rorx	$28,%r11,%r13
	lea	(%rcx,%r10),%rcx
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rax,%r15
	xor	%r13,%r14
	lea	(%r10,%r15),%r10
	mov	%rdx,%r12
	add	32(%rsp),%r9
	and	%rcx,%r12
	rorx	$41,%rcx,%r13
	rorx	$18,%rcx,%r15
	lea	(%r10,%r14),%r10
	lea	(%r9,%r12),%r9
	andn	%r8,%rcx,%r12
	xor	%r15,%r13
	rorx	$14,%rcx,%r14
	lea	(%r9,%r12),%r9
	xor	%r14,%r13
	mov	%r10,%r15
	rorx	$39,%r10,%r12
	lea	(%r9,%r13),%r9
	xor	%r11,%r15
	rorx	$34,%r10,%r14
	rorx	$28,%r10,%r13
	lea	(%rbx,%r9),%rbx
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r11,%rdi
	xor	%r13,%r14
	lea	(%r9,%rdi),%r9
	mov	%rcx,%r12
	add	40(%rsp),%r8
	and	%rbx,%r12
	rorx	$41,%rbx,%r13
	rorx	$18,%rbx,%rdi
	lea	(%r9,%r14),%r9
	lea	(%r8,%r12),%r8
	andn	%rdx,%rbx,%r12
	xor	%rdi,%r13
	rorx	$14,%rbx,%r14
	lea	(%r8,%r12),%r8
	xor	%r14,%r13
	mov	%r9,%rdi
	rorx	$39,%r9,%r12
	lea	(%r8,%r13),%r8
	xor	%r10,%rdi
	rorx	$34,%r9,%r14
	rorx	$28,%r9,%r13
	lea	(%rax,%r8),%rax
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r10,%r15
	xor	%r13,%r14
	lea	(%r8,%r15),%r8
	mov	%rbx,%r12
	add	64(%rsp),%rdx
	and	%rax,%r12
	rorx	$41,%rax,%r13
	rorx	$18,%rax,%r15
	lea	(%r8,%r14),%r8
	lea	(%rdx,%r12),%rdx
	andn	%rcx,%rax,%r12
	xor	%r15,%r13
	rorx	$14,%rax,%r14
	lea	(%rdx,%r12),%rdx
	xor	%r14,%r13
	mov	%r8,%r15
	rorx	$39,%r8,%r12
	lea	(%rdx,%r13),%rdx
	xor	%r9,%r15
	rorx	$34,%r8,%r14
	rorx	$28,%r8,%r13
	lea	(%r11,%rdx),%r11
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r9,%rdi
	xor	%r13,%r14
	lea	(%rdx,%rdi),%rdx
	mov	%rax,%r12
	add	72(%rsp),%rcx
	and	%r11,%r12
	rorx	$41,%r11,%r13
	rorx	$18,%r11,%rdi
	lea	(%rdx,%r14),%rdx
	lea	(%rcx,%r12),%rcx
	andn	%rbx,%r11,%r12
	xor	%rdi,%r13
	rorx	$14,%r11,%r14
	lea	(%rcx,%r12),%rcx
	xor	%r14,%r13
	mov	%rdx,%rdi
	rorx	$39,%rdx,%r12
	lea	(%rcx,%r13),%rcx
	xor	%r8,%rdi
	rorx	$34,%rdx,%r14
	rorx	$28,%rdx,%r13
	lea	(%r10,%rcx),%r10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r8,%r15
	xor	%r13,%r14
	lea	(%rcx,%r15),%rcx
	mov	%r11,%r12
	add	96(%rsp),%rbx
	and	%r10,%r12
	rorx	$41,%r10,%r13
	rorx	$18,%r10,%r15
	lea	(%rcx,%r14),%rcx
	lea	(%rbx,%r12),%rbx
	andn	%rax,%r10,%r12
	xor	%r15,%r13
	rorx	$14,%r10,%r14
	lea	(%rbx,%r12),%rbx
	xor	%r14,%r13
	mov	%rcx,%r15
	rorx	$39,%rcx,%r12
	lea	(%rbx,%r13),%rbx
	xor	%rdx,%r15
	rorx	$34,%rcx,%r14
	rorx	$28,%rcx,%r13
	lea	(%r9,%rbx),%r9
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rdx,%rdi
	xor	%r13,%r14
	lea	(%rbx,%rdi),%rbx
	mov	%r10,%r12
	add	104(%rsp),%rax
	and	%r9,%r12
	rorx	$41,%r9,%r13
	rorx	$18,%r9,%rdi
	lea	(%rbx,%r14),%rbx
	lea	(%rax,%r12),%rax
	andn	%r11,%r9,%r12
	xor	%rdi,%r13
	rorx	$14,%r9,%r14
	lea	(%rax,%r12),%rax
	xor	%r14,%r13
	mov	%rbx,%rdi
	rorx	$39,%rbx,%r12
	lea	(%rax,%r13),%rax
	xor	%rcx,%rdi
	rorx	$34,%rbx,%r14
	rorx	$28,%rbx,%r13
	lea	(%r8,%rax),%r8
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rcx,%r15
	xor	%r13,%r14
	lea	(%rax,%r15),%rax
	mov	%r9,%r12
	mov	1280(%rsp),%rdi	# 16*8+0*8(%rsp)
	add	%r14,%rax
	#mov	1288(%rsp),%rsi	# 16*8+1*8(%rsp)
	lea	1152(%rsp),%rbp

	add	8*0(%rdi),%rax
	add	8*1(%rdi),%rbx
	add	8*2(%rdi),%rcx
	add	8*3(%rdi),%rdx
	add	8*4(%rdi),%r8
	add	8*5(%rdi),%r9
	add	8*6(%rdi),%r10
	add	8*7(%rdi),%r11

	mov	%rax,8*0(%rdi)
	mov	%rbx,8*1(%rdi)
	mov	%rcx,8*2(%rdi)
	mov	%rdx,8*3(%rdi)
	mov	%r8,8*4(%rdi)
	mov	%r9,8*5(%rdi)
	mov	%r10,8*6(%rdi)
	mov	%r11,8*7(%rdi)

	cmp	144(%rbp),%rsi	# 16*8+2*8(%rsp)
	je	.Ldone_avx2

	xor	%r14,%r14
	mov	%rbx,%rdi
	xor	%rcx,%rdi			# magic
	mov	%r9,%r12
	jmp	.Lower_avx2
.align	16
.Lower_avx2:
	add	0+16(%rbp),%r11
	and	%r8,%r12
	rorx	$41,%r8,%r13
	rorx	$18,%r8,%r15
	lea	(%rax,%r14),%rax
	lea	(%r11,%r12),%r11
	andn	%r10,%r8,%r12
	xor	%r15,%r13
	rorx	$14,%r8,%r14
	lea	(%r11,%r12),%r11
	xor	%r14,%r13
	mov	%rax,%r15
	rorx	$39,%rax,%r12
	lea	(%r11,%r13),%r11
	xor	%rbx,%r15
	rorx	$34,%rax,%r14
	rorx	$28,%rax,%r13
	lea	(%rdx,%r11),%rdx
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rbx,%rdi
	xor	%r13,%r14
	lea	(%r11,%rdi),%r11
	mov	%r8,%r12
	add	8+16(%rbp),%r10
	and	%rdx,%r12
	rorx	$41,%rdx,%r13
	rorx	$18,%rdx,%rdi
	lea	(%r11,%r14),%r11
	lea	(%r10,%r12),%r10
	andn	%r9,%rdx,%r12
	xor	%rdi,%r13
	rorx	$14,%rdx,%r14
	lea	(%r10,%r12),%r10
	xor	%r14,%r13
	mov	%r11,%rdi
	rorx	$39,%r11,%r12
	lea	(%r10,%r13),%r10
	xor	%rax,%rdi
	rorx	$34,%r11,%r14
	rorx	$28,%r11,%r13
	lea	(%rcx,%r10),%rcx
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rax,%r15
	xor	%r13,%r14
	lea	(%r10,%r15),%r10
	mov	%rdx,%r12
	add	32+16(%rbp),%r9
	and	%rcx,%r12
	rorx	$41,%rcx,%r13
	rorx	$18,%rcx,%r15
	lea	(%r10,%r14),%r10
	lea	(%r9,%r12),%r9
	andn	%r8,%rcx,%r12
	xor	%r15,%r13
	rorx	$14,%rcx,%r14
	lea	(%r9,%r12),%r9
	xor	%r14,%r13
	mov	%r10,%r15
	rorx	$39,%r10,%r12
	lea	(%r9,%r13),%r9
	xor	%r11,%r15
	rorx	$34,%r10,%r14
	rorx	$28,%r10,%r13
	lea	(%rbx,%r9),%rbx
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r11,%rdi
	xor	%r13,%r14
	lea	(%r9,%rdi),%r9
	mov	%rcx,%r12
	add	40+16(%rbp),%r8
	and	%rbx,%r12
	rorx	$41,%rbx,%r13
	rorx	$18,%rbx,%rdi
	lea	(%r9,%r14),%r9
	lea	(%r8,%r12),%r8
	andn	%rdx,%rbx,%r12
	xor	%rdi,%r13
	rorx	$14,%rbx,%r14
	lea	(%r8,%r12),%r8
	xor	%r14,%r13
	mov	%r9,%rdi
	rorx	$39,%r9,%r12
	lea	(%r8,%r13),%r8
	xor	%r10,%rdi
	rorx	$34,%r9,%r14
	rorx	$28,%r9,%r13
	lea	(%rax,%r8),%rax
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r10,%r15
	xor	%r13,%r14
	lea	(%r8,%r15),%r8
	mov	%rbx,%r12
	add	64+16(%rbp),%rdx
	and	%rax,%r12
	rorx	$41,%rax,%r13
	rorx	$18,%rax,%r15
	lea	(%r8,%r14),%r8
	lea	(%rdx,%r12),%rdx
	andn	%rcx,%rax,%r12
	xor	%r15,%r13
	rorx	$14,%rax,%r14
	lea	(%rdx,%r12),%rdx
	xor	%r14,%r13
	mov	%r8,%r15
	rorx	$39,%r8,%r12
	lea	(%rdx,%r13),%rdx
	xor	%r9,%r15
	rorx	$34,%r8,%r14
	rorx	$28,%r8,%r13
	lea	(%r11,%rdx),%r11
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%r9,%rdi
	xor	%r13,%r14
	lea	(%rdx,%rdi),%rdx
	mov	%rax,%r12
	add	72+16(%rbp),%rcx
	and	%r11,%r12
	rorx	$41,%r11,%r13
	rorx	$18,%r11,%rdi
	lea	(%rdx,%r14),%rdx
	lea	(%rcx,%r12),%rcx
	andn	%rbx,%r11,%r12
	xor	%rdi,%r13
	rorx	$14,%r11,%r14
	lea	(%rcx,%r12),%rcx
	xor	%r14,%r13
	mov	%rdx,%rdi
	rorx	$39,%rdx,%r12
	lea	(%rcx,%r13),%rcx
	xor	%r8,%rdi
	rorx	$34,%rdx,%r14
	rorx	$28,%rdx,%r13
	lea	(%r10,%rcx),%r10
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%r8,%r15
	xor	%r13,%r14
	lea	(%rcx,%r15),%rcx
	mov	%r11,%r12
	add	96+16(%rbp),%rbx
	and	%r10,%r12
	rorx	$41,%r10,%r13
	rorx	$18,%r10,%r15
	lea	(%rcx,%r14),%rcx
	lea	(%rbx,%r12),%rbx
	andn	%rax,%r10,%r12
	xor	%r15,%r13
	rorx	$14,%r10,%r14
	lea	(%rbx,%r12),%rbx
	xor	%r14,%r13
	mov	%rcx,%r15
	rorx	$39,%rcx,%r12
	lea	(%rbx,%r13),%rbx
	xor	%rdx,%r15
	rorx	$34,%rcx,%r14
	rorx	$28,%rcx,%r13
	lea	(%r9,%rbx),%r9
	and	%r15,%rdi
	xor	%r12,%r14
	xor	%rdx,%rdi
	xor	%r13,%r14
	lea	(%rbx,%rdi),%rbx
	mov	%r10,%r12
	add	104+16(%rbp),%rax
	and	%r9,%r12
	rorx	$41,%r9,%r13
	rorx	$18,%r9,%rdi
	lea	(%rbx,%r14),%rbx
	lea	(%rax,%r12),%rax
	andn	%r11,%r9,%r12
	xor	%rdi,%r13
	rorx	$14,%r9,%r14
	lea	(%rax,%r12),%rax
	xor	%r14,%r13
	mov	%rbx,%rdi
	rorx	$39,%rbx,%r12
	lea	(%rax,%r13),%rax
	xor	%rcx,%rdi
	rorx	$34,%rbx,%r14
	rorx	$28,%rbx,%r13
	lea	(%r8,%rax),%r8
	and	%rdi,%r15
	xor	%r12,%r14
	xor	%rcx,%r15
	xor	%r13,%r14
	lea	(%rax,%r15),%rax
	mov	%r9,%r12
	lea	-128(%rbp),%rbp
	cmp	%rsp,%rbp
	jae	.Lower_avx2

	mov	1280(%rsp),%rdi	# 16*8+0*8(%rsp)
	add	%r14,%rax
	#mov	1288(%rsp),%rsi	# 16*8+1*8(%rsp)
	lea	1152(%rsp),%rsp
# restore frame pointer to original location at 152(%rsp)
.cfi_cfa_expression	152(%rsp),deref,+8

	add	8*0(%rdi),%rax
	add	8*1(%rdi),%rbx
	add	8*2(%rdi),%rcx
	add	8*3(%rdi),%rdx
	add	8*4(%rdi),%r8
	add	8*5(%rdi),%r9
	lea	256(%rsi),%rsi	# inp+=2
	add	8*6(%rdi),%r10
	mov	%rsi,%r12
	add	8*7(%rdi),%r11
	cmp	16*8+2*8(%rsp),%rsi

	mov	%rax,8*0(%rdi)
	cmove	%rsp,%r12		# next block or stale data
	mov	%rbx,8*1(%rdi)
	mov	%rcx,8*2(%rdi)
	mov	%rdx,8*3(%rdi)
	mov	%r8,8*4(%rdi)
	mov	%r9,8*5(%rdi)
	mov	%r10,8*6(%rdi)
	mov	%r11,8*7(%rdi)

	jbe	.Loop_avx2
	lea	(%rsp),%rbp
# temporarily use %rbp as index to 152(%rsp)
# this avoids the need to save a secondary frame pointer at -8(%rsp)
.cfi_cfa_expression	%rbp+152,deref,+8

.Ldone_avx2:
	mov	152(%rbp),%rsi
.cfi_def_cfa	%rsi,8
	vzeroupper
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
.Lepilogue_avx2:
	ret
.cfi_endproc
.size	sha512_block_data_order_avx2,.-sha512_block_data_order_avx2
`;

export default translateAssembly(code);
