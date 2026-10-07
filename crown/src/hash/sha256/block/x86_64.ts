/**
 * sha256_block_data_order for x86_64.
 *
 * TypeScript port of the $SZ==4 branch of OpenSSL
 * crypto/sha/asm/sha512-x86_64.pl (selected by an output name without
 * "512").
 * Copyright 2004-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the full x86_64 configuration of a stock OpenSSL build: with
 * GNU as >= 2.25 the perl emits the IALU, SSSE3, SHA-NI and AVX/AVX2
 * bodies and `sha256_block_data_order` dispatches between them at run
 * time from OPENSSL_ia32cap_P.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text

.extern	OPENSSL_ia32cap_P
.globl	sha256_block_data_order
.type	sha256_block_data_order,@function,3
.align	16
sha256_block_data_order:
.cfi_startproc
	lea	OPENSSL_ia32cap_P(%rip),%r11
	mov	0(%r11),%r9d
	mov	4(%r11),%r10d
	mov	8(%r11),%r11d
	test	$536870912,%r11d		# check for SHA
	jnz	_shaext_shortcut
	and	$296,%r11d	# check for BMI2+AVX2+BMI1
	cmp	$296,%r11d
	je	.Lavx2_shortcut
	and	$1073741824,%r9d		# mask "Intel CPU" bit
	and	$268435968,%r10d	# mask AVX and SSSE3 bits
	or	%r9d,%r10d
	cmp	$1342177792,%r10d
	je	.Lavx_shortcut
	test	$512,%r10d
	jnz	.Lssse3_shortcut
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
	sub	$16*4+4*8,%rsp
	lea	(%rsi,%rdx,4),%rdx	# inp+num*16*4
	and	$-64,%rsp		# align stack frame
	mov	%rdi,16*4+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*4+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*4+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,88(%rsp)		# save copy of %rsp
.cfi_cfa_expression	88(%rsp),deref,+8
.Lprologue:

	mov	4*0(%rdi),%eax
	mov	4*1(%rdi),%ebx
	mov	4*2(%rdi),%ecx
	mov	4*3(%rdi),%edx
	mov	4*4(%rdi),%r8d
	mov	4*5(%rdi),%r9d
	mov	4*6(%rdi),%r10d
	mov	4*7(%rdi),%r11d
	jmp	.Lloop

.align	16
.Lloop:
	mov	%ebx,%edi
	lea	K256(%rip),%rbp
	xor	%ecx,%edi			# magic
	mov	4*0(%rsi),%r12d
	mov	%r8d,%r13d
	mov	%eax,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r9d,%r15d

	xor	%r8d,%r13d
	ror	$9,%r14d
	xor	%r10d,%r15d			# f^g

	mov	%r12d,0(%rsp)
	xor	%eax,%r14d
	and	%r8d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r11d,%r12d			# T1+=h
	xor	%r10d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r8d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%eax,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%eax,%r14d

	xor	%ebx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ebx,%r11d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r11d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%edx			# d+=T1
	add	%r12d,%r11d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%r11d			# h+=Sigma0(a)
	mov	4*1(%rsi),%r12d
	mov	%edx,%r13d
	mov	%r11d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r8d,%edi

	xor	%edx,%r13d
	ror	$9,%r14d
	xor	%r9d,%edi			# f^g

	mov	%r12d,4(%rsp)
	xor	%r11d,%r14d
	and	%edx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r10d,%r12d			# T1+=h
	xor	%r9d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%edx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r11d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r11d,%r14d

	xor	%eax,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%eax,%r10d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r10d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ecx			# d+=T1
	add	%r12d,%r10d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%r10d			# h+=Sigma0(a)
	mov	4*2(%rsi),%r12d
	mov	%ecx,%r13d
	mov	%r10d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%edx,%r15d

	xor	%ecx,%r13d
	ror	$9,%r14d
	xor	%r8d,%r15d			# f^g

	mov	%r12d,8(%rsp)
	xor	%r10d,%r14d
	and	%ecx,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r9d,%r12d			# T1+=h
	xor	%r8d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ecx,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r10d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r10d,%r14d

	xor	%r11d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r11d,%r9d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r9d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ebx			# d+=T1
	add	%r12d,%r9d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%r9d			# h+=Sigma0(a)
	mov	4*3(%rsi),%r12d
	mov	%ebx,%r13d
	mov	%r9d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%ecx,%edi

	xor	%ebx,%r13d
	ror	$9,%r14d
	xor	%edx,%edi			# f^g

	mov	%r12d,12(%rsp)
	xor	%r9d,%r14d
	and	%ebx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r8d,%r12d			# T1+=h
	xor	%edx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ebx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r9d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r9d,%r14d

	xor	%r10d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r10d,%r8d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r8d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%eax			# d+=T1
	add	%r12d,%r8d			# h+=T1

	lea	20(%rbp),%rbp	# round++
	add	%r14d,%r8d			# h+=Sigma0(a)
	mov	4*4(%rsi),%r12d
	mov	%eax,%r13d
	mov	%r8d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%ebx,%r15d

	xor	%eax,%r13d
	ror	$9,%r14d
	xor	%ecx,%r15d			# f^g

	mov	%r12d,16(%rsp)
	xor	%r8d,%r14d
	and	%eax,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%edx,%r12d			# T1+=h
	xor	%ecx,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%eax,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r8d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r8d,%r14d

	xor	%r9d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r9d,%edx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%edx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r11d			# d+=T1
	add	%r12d,%edx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%edx			# h+=Sigma0(a)
	mov	4*5(%rsi),%r12d
	mov	%r11d,%r13d
	mov	%edx,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%eax,%edi

	xor	%r11d,%r13d
	ror	$9,%r14d
	xor	%ebx,%edi			# f^g

	mov	%r12d,20(%rsp)
	xor	%edx,%r14d
	and	%r11d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%ecx,%r12d			# T1+=h
	xor	%ebx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r11d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%edx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%edx,%r14d

	xor	%r8d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r8d,%ecx

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%ecx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r10d			# d+=T1
	add	%r12d,%ecx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%ecx			# h+=Sigma0(a)
	mov	4*6(%rsi),%r12d
	mov	%r10d,%r13d
	mov	%ecx,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r11d,%r15d

	xor	%r10d,%r13d
	ror	$9,%r14d
	xor	%eax,%r15d			# f^g

	mov	%r12d,24(%rsp)
	xor	%ecx,%r14d
	and	%r10d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%ebx,%r12d			# T1+=h
	xor	%eax,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r10d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%ecx,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ecx,%r14d

	xor	%edx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%edx,%ebx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%ebx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r9d			# d+=T1
	add	%r12d,%ebx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%ebx			# h+=Sigma0(a)
	mov	4*7(%rsi),%r12d
	mov	%r9d,%r13d
	mov	%ebx,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r10d,%edi

	xor	%r9d,%r13d
	ror	$9,%r14d
	xor	%r11d,%edi			# f^g

	mov	%r12d,28(%rsp)
	xor	%ebx,%r14d
	and	%r9d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%eax,%r12d			# T1+=h
	xor	%r11d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r9d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%ebx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ebx,%r14d

	xor	%ecx,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ecx,%eax

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%eax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r8d			# d+=T1
	add	%r12d,%eax			# h+=T1

	lea	20(%rbp),%rbp	# round++
	add	%r14d,%eax			# h+=Sigma0(a)
	mov	4*8(%rsi),%r12d
	mov	%r8d,%r13d
	mov	%eax,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r9d,%r15d

	xor	%r8d,%r13d
	ror	$9,%r14d
	xor	%r10d,%r15d			# f^g

	mov	%r12d,32(%rsp)
	xor	%eax,%r14d
	and	%r8d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r11d,%r12d			# T1+=h
	xor	%r10d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r8d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%eax,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%eax,%r14d

	xor	%ebx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ebx,%r11d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r11d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%edx			# d+=T1
	add	%r12d,%r11d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%r11d			# h+=Sigma0(a)
	mov	4*9(%rsi),%r12d
	mov	%edx,%r13d
	mov	%r11d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r8d,%edi

	xor	%edx,%r13d
	ror	$9,%r14d
	xor	%r9d,%edi			# f^g

	mov	%r12d,36(%rsp)
	xor	%r11d,%r14d
	and	%edx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r10d,%r12d			# T1+=h
	xor	%r9d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%edx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r11d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r11d,%r14d

	xor	%eax,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%eax,%r10d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r10d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ecx			# d+=T1
	add	%r12d,%r10d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%r10d			# h+=Sigma0(a)
	mov	4*10(%rsi),%r12d
	mov	%ecx,%r13d
	mov	%r10d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%edx,%r15d

	xor	%ecx,%r13d
	ror	$9,%r14d
	xor	%r8d,%r15d			# f^g

	mov	%r12d,40(%rsp)
	xor	%r10d,%r14d
	and	%ecx,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r9d,%r12d			# T1+=h
	xor	%r8d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ecx,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r10d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r10d,%r14d

	xor	%r11d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r11d,%r9d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r9d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ebx			# d+=T1
	add	%r12d,%r9d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%r9d			# h+=Sigma0(a)
	mov	4*11(%rsi),%r12d
	mov	%ebx,%r13d
	mov	%r9d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%ecx,%edi

	xor	%ebx,%r13d
	ror	$9,%r14d
	xor	%edx,%edi			# f^g

	mov	%r12d,44(%rsp)
	xor	%r9d,%r14d
	and	%ebx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r8d,%r12d			# T1+=h
	xor	%edx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ebx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r9d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r9d,%r14d

	xor	%r10d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r10d,%r8d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r8d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%eax			# d+=T1
	add	%r12d,%r8d			# h+=T1

	lea	20(%rbp),%rbp	# round++
	add	%r14d,%r8d			# h+=Sigma0(a)
	mov	4*12(%rsi),%r12d
	mov	%eax,%r13d
	mov	%r8d,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%ebx,%r15d

	xor	%eax,%r13d
	ror	$9,%r14d
	xor	%ecx,%r15d			# f^g

	mov	%r12d,48(%rsp)
	xor	%r8d,%r14d
	and	%eax,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%edx,%r12d			# T1+=h
	xor	%ecx,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%eax,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r8d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r8d,%r14d

	xor	%r9d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r9d,%edx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%edx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r11d			# d+=T1
	add	%r12d,%edx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%edx			# h+=Sigma0(a)
	mov	4*13(%rsi),%r12d
	mov	%r11d,%r13d
	mov	%edx,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%eax,%edi

	xor	%r11d,%r13d
	ror	$9,%r14d
	xor	%ebx,%edi			# f^g

	mov	%r12d,52(%rsp)
	xor	%edx,%r14d
	and	%r11d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%ecx,%r12d			# T1+=h
	xor	%ebx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r11d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%edx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%edx,%r14d

	xor	%r8d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r8d,%ecx

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%ecx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r10d			# d+=T1
	add	%r12d,%ecx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%ecx			# h+=Sigma0(a)
	mov	4*14(%rsi),%r12d
	mov	%r10d,%r13d
	mov	%ecx,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r11d,%r15d

	xor	%r10d,%r13d
	ror	$9,%r14d
	xor	%eax,%r15d			# f^g

	mov	%r12d,56(%rsp)
	xor	%ecx,%r14d
	and	%r10d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%ebx,%r12d			# T1+=h
	xor	%eax,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r10d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%ecx,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ecx,%r14d

	xor	%edx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%edx,%ebx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%ebx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r9d			# d+=T1
	add	%r12d,%ebx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	add	%r14d,%ebx			# h+=Sigma0(a)
	mov	4*15(%rsi),%r12d
	mov	%r9d,%r13d
	mov	%ebx,%r14d
	bswap	%r12d
	ror	$14,%r13d
	mov	%r10d,%edi

	xor	%r9d,%r13d
	ror	$9,%r14d
	xor	%r11d,%edi			# f^g

	mov	%r12d,60(%rsp)
	xor	%ebx,%r14d
	and	%r9d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%eax,%r12d			# T1+=h
	xor	%r11d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r9d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%ebx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ebx,%r14d

	xor	%ecx,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ecx,%eax

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%eax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r8d			# d+=T1
	add	%r12d,%eax			# h+=T1

	lea	20(%rbp),%rbp	# round++
	jmp	.Lrounds_16_xx
.align	16
.Lrounds_16_xx:
	mov	4(%rsp),%r13d
	mov	56(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%eax			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	36(%rsp),%r12d

	add	0(%rsp),%r12d
	mov	%r8d,%r13d
	add	%r15d,%r12d
	mov	%eax,%r14d
	ror	$14,%r13d
	mov	%r9d,%r15d

	xor	%r8d,%r13d
	ror	$9,%r14d
	xor	%r10d,%r15d			# f^g

	mov	%r12d,0(%rsp)
	xor	%eax,%r14d
	and	%r8d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r11d,%r12d			# T1+=h
	xor	%r10d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r8d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%eax,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%eax,%r14d

	xor	%ebx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ebx,%r11d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r11d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%edx			# d+=T1
	add	%r12d,%r11d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	8(%rsp),%r13d
	mov	60(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r11d			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	40(%rsp),%r12d

	add	4(%rsp),%r12d
	mov	%edx,%r13d
	add	%edi,%r12d
	mov	%r11d,%r14d
	ror	$14,%r13d
	mov	%r8d,%edi

	xor	%edx,%r13d
	ror	$9,%r14d
	xor	%r9d,%edi			# f^g

	mov	%r12d,4(%rsp)
	xor	%r11d,%r14d
	and	%edx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r10d,%r12d			# T1+=h
	xor	%r9d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%edx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r11d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r11d,%r14d

	xor	%eax,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%eax,%r10d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r10d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ecx			# d+=T1
	add	%r12d,%r10d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	12(%rsp),%r13d
	mov	0(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r10d			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	44(%rsp),%r12d

	add	8(%rsp),%r12d
	mov	%ecx,%r13d
	add	%r15d,%r12d
	mov	%r10d,%r14d
	ror	$14,%r13d
	mov	%edx,%r15d

	xor	%ecx,%r13d
	ror	$9,%r14d
	xor	%r8d,%r15d			# f^g

	mov	%r12d,8(%rsp)
	xor	%r10d,%r14d
	and	%ecx,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r9d,%r12d			# T1+=h
	xor	%r8d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ecx,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r10d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r10d,%r14d

	xor	%r11d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r11d,%r9d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r9d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ebx			# d+=T1
	add	%r12d,%r9d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	16(%rsp),%r13d
	mov	4(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r9d			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	48(%rsp),%r12d

	add	12(%rsp),%r12d
	mov	%ebx,%r13d
	add	%edi,%r12d
	mov	%r9d,%r14d
	ror	$14,%r13d
	mov	%ecx,%edi

	xor	%ebx,%r13d
	ror	$9,%r14d
	xor	%edx,%edi			# f^g

	mov	%r12d,12(%rsp)
	xor	%r9d,%r14d
	and	%ebx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r8d,%r12d			# T1+=h
	xor	%edx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ebx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r9d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r9d,%r14d

	xor	%r10d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r10d,%r8d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r8d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%eax			# d+=T1
	add	%r12d,%r8d			# h+=T1

	lea	20(%rbp),%rbp	# round++
	mov	20(%rsp),%r13d
	mov	8(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r8d			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	52(%rsp),%r12d

	add	16(%rsp),%r12d
	mov	%eax,%r13d
	add	%r15d,%r12d
	mov	%r8d,%r14d
	ror	$14,%r13d
	mov	%ebx,%r15d

	xor	%eax,%r13d
	ror	$9,%r14d
	xor	%ecx,%r15d			# f^g

	mov	%r12d,16(%rsp)
	xor	%r8d,%r14d
	and	%eax,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%edx,%r12d			# T1+=h
	xor	%ecx,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%eax,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r8d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r8d,%r14d

	xor	%r9d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r9d,%edx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%edx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r11d			# d+=T1
	add	%r12d,%edx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	24(%rsp),%r13d
	mov	12(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%edx			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	56(%rsp),%r12d

	add	20(%rsp),%r12d
	mov	%r11d,%r13d
	add	%edi,%r12d
	mov	%edx,%r14d
	ror	$14,%r13d
	mov	%eax,%edi

	xor	%r11d,%r13d
	ror	$9,%r14d
	xor	%ebx,%edi			# f^g

	mov	%r12d,20(%rsp)
	xor	%edx,%r14d
	and	%r11d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%ecx,%r12d			# T1+=h
	xor	%ebx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r11d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%edx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%edx,%r14d

	xor	%r8d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r8d,%ecx

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%ecx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r10d			# d+=T1
	add	%r12d,%ecx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	28(%rsp),%r13d
	mov	16(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%ecx			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	60(%rsp),%r12d

	add	24(%rsp),%r12d
	mov	%r10d,%r13d
	add	%r15d,%r12d
	mov	%ecx,%r14d
	ror	$14,%r13d
	mov	%r11d,%r15d

	xor	%r10d,%r13d
	ror	$9,%r14d
	xor	%eax,%r15d			# f^g

	mov	%r12d,24(%rsp)
	xor	%ecx,%r14d
	and	%r10d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%ebx,%r12d			# T1+=h
	xor	%eax,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r10d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%ecx,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ecx,%r14d

	xor	%edx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%edx,%ebx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%ebx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r9d			# d+=T1
	add	%r12d,%ebx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	32(%rsp),%r13d
	mov	20(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%ebx			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	0(%rsp),%r12d

	add	28(%rsp),%r12d
	mov	%r9d,%r13d
	add	%edi,%r12d
	mov	%ebx,%r14d
	ror	$14,%r13d
	mov	%r10d,%edi

	xor	%r9d,%r13d
	ror	$9,%r14d
	xor	%r11d,%edi			# f^g

	mov	%r12d,28(%rsp)
	xor	%ebx,%r14d
	and	%r9d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%eax,%r12d			# T1+=h
	xor	%r11d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r9d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%ebx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ebx,%r14d

	xor	%ecx,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ecx,%eax

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%eax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r8d			# d+=T1
	add	%r12d,%eax			# h+=T1

	lea	20(%rbp),%rbp	# round++
	mov	36(%rsp),%r13d
	mov	24(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%eax			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	4(%rsp),%r12d

	add	32(%rsp),%r12d
	mov	%r8d,%r13d
	add	%r15d,%r12d
	mov	%eax,%r14d
	ror	$14,%r13d
	mov	%r9d,%r15d

	xor	%r8d,%r13d
	ror	$9,%r14d
	xor	%r10d,%r15d			# f^g

	mov	%r12d,32(%rsp)
	xor	%eax,%r14d
	and	%r8d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r11d,%r12d			# T1+=h
	xor	%r10d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r8d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%eax,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%eax,%r14d

	xor	%ebx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ebx,%r11d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r11d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%edx			# d+=T1
	add	%r12d,%r11d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	40(%rsp),%r13d
	mov	28(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r11d			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	8(%rsp),%r12d

	add	36(%rsp),%r12d
	mov	%edx,%r13d
	add	%edi,%r12d
	mov	%r11d,%r14d
	ror	$14,%r13d
	mov	%r8d,%edi

	xor	%edx,%r13d
	ror	$9,%r14d
	xor	%r9d,%edi			# f^g

	mov	%r12d,36(%rsp)
	xor	%r11d,%r14d
	and	%edx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r10d,%r12d			# T1+=h
	xor	%r9d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%edx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r11d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r11d,%r14d

	xor	%eax,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%eax,%r10d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r10d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ecx			# d+=T1
	add	%r12d,%r10d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	44(%rsp),%r13d
	mov	32(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r10d			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	12(%rsp),%r12d

	add	40(%rsp),%r12d
	mov	%ecx,%r13d
	add	%r15d,%r12d
	mov	%r10d,%r14d
	ror	$14,%r13d
	mov	%edx,%r15d

	xor	%ecx,%r13d
	ror	$9,%r14d
	xor	%r8d,%r15d			# f^g

	mov	%r12d,40(%rsp)
	xor	%r10d,%r14d
	and	%ecx,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%r9d,%r12d			# T1+=h
	xor	%r8d,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ecx,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r10d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r10d,%r14d

	xor	%r11d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r11d,%r9d

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%r9d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%ebx			# d+=T1
	add	%r12d,%r9d			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	48(%rsp),%r13d
	mov	36(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r9d			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	16(%rsp),%r12d

	add	44(%rsp),%r12d
	mov	%ebx,%r13d
	add	%edi,%r12d
	mov	%r9d,%r14d
	ror	$14,%r13d
	mov	%ecx,%edi

	xor	%ebx,%r13d
	ror	$9,%r14d
	xor	%edx,%edi			# f^g

	mov	%r12d,44(%rsp)
	xor	%r9d,%r14d
	and	%ebx,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%r8d,%r12d			# T1+=h
	xor	%edx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%ebx,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%r9d,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r9d,%r14d

	xor	%r10d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r10d,%r8d

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%r8d			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%eax			# d+=T1
	add	%r12d,%r8d			# h+=T1

	lea	20(%rbp),%rbp	# round++
	mov	52(%rsp),%r13d
	mov	40(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%r8d			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	20(%rsp),%r12d

	add	48(%rsp),%r12d
	mov	%eax,%r13d
	add	%r15d,%r12d
	mov	%r8d,%r14d
	ror	$14,%r13d
	mov	%ebx,%r15d

	xor	%eax,%r13d
	ror	$9,%r14d
	xor	%ecx,%r15d			# f^g

	mov	%r12d,48(%rsp)
	xor	%r8d,%r14d
	and	%eax,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%edx,%r12d			# T1+=h
	xor	%ecx,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%eax,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%r8d,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%r8d,%r14d

	xor	%r9d,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r9d,%edx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%edx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r11d			# d+=T1
	add	%r12d,%edx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	56(%rsp),%r13d
	mov	44(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%edx			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	24(%rsp),%r12d

	add	52(%rsp),%r12d
	mov	%r11d,%r13d
	add	%edi,%r12d
	mov	%edx,%r14d
	ror	$14,%r13d
	mov	%eax,%edi

	xor	%r11d,%r13d
	ror	$9,%r14d
	xor	%ebx,%edi			# f^g

	mov	%r12d,52(%rsp)
	xor	%edx,%r14d
	and	%r11d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%ecx,%r12d			# T1+=h
	xor	%ebx,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r11d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%edx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%edx,%r14d

	xor	%r8d,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%r8d,%ecx

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%ecx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r10d			# d+=T1
	add	%r12d,%ecx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	60(%rsp),%r13d
	mov	48(%rsp),%r15d

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%ecx			# modulo-scheduled h+=Sigma0(a)
	mov	%r15d,%r14d
	ror	$2,%r15d

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%r15d
	shr	$10,%r14d

	ror	$17,%r15d
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%r15d			# sigma1(X[(i+14)&0xf])
	add	28(%rsp),%r12d

	add	56(%rsp),%r12d
	mov	%r10d,%r13d
	add	%r15d,%r12d
	mov	%ecx,%r14d
	ror	$14,%r13d
	mov	%r11d,%r15d

	xor	%r10d,%r13d
	ror	$9,%r14d
	xor	%eax,%r15d			# f^g

	mov	%r12d,56(%rsp)
	xor	%ecx,%r14d
	and	%r10d,%r15d			# (f^g)&e

	ror	$5,%r13d
	add	%ebx,%r12d			# T1+=h
	xor	%eax,%r15d			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r10d,%r13d
	add	%r15d,%r12d			# T1+=Ch(e,f,g)

	mov	%ecx,%r15d
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ecx,%r14d

	xor	%edx,%r15d			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%edx,%ebx

	and	%r15d,%edi
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%edi,%ebx			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r9d			# d+=T1
	add	%r12d,%ebx			# h+=T1

	lea	4(%rbp),%rbp	# round++
	mov	0(%rsp),%r13d
	mov	52(%rsp),%edi

	mov	%r13d,%r12d
	ror	$11,%r13d
	add	%r14d,%ebx			# modulo-scheduled h+=Sigma0(a)
	mov	%edi,%r14d
	ror	$2,%edi

	xor	%r12d,%r13d
	shr	$3,%r12d
	ror	$7,%r13d
	xor	%r14d,%edi
	shr	$10,%r14d

	ror	$17,%edi
	xor	%r13d,%r12d			# sigma0(X[(i+1)&0xf])
	xor	%r14d,%edi			# sigma1(X[(i+14)&0xf])
	add	32(%rsp),%r12d

	add	60(%rsp),%r12d
	mov	%r9d,%r13d
	add	%edi,%r12d
	mov	%ebx,%r14d
	ror	$14,%r13d
	mov	%r10d,%edi

	xor	%r9d,%r13d
	ror	$9,%r14d
	xor	%r11d,%edi			# f^g

	mov	%r12d,60(%rsp)
	xor	%ebx,%r14d
	and	%r9d,%edi			# (f^g)&e

	ror	$5,%r13d
	add	%eax,%r12d			# T1+=h
	xor	%r11d,%edi			# Ch(e,f,g)=((f^g)&e)^g

	ror	$11,%r14d
	xor	%r9d,%r13d
	add	%edi,%r12d			# T1+=Ch(e,f,g)

	mov	%ebx,%edi
	add	(%rbp),%r12d		# T1+=K[round]
	xor	%ebx,%r14d

	xor	%ecx,%edi			# a^b, b^c in next round
	ror	$6,%r13d	# Sigma1(e)
	mov	%ecx,%eax

	and	%edi,%r15d
	ror	$2,%r14d	# Sigma0(a)
	add	%r13d,%r12d			# T1+=Sigma1(e)

	xor	%r15d,%eax			# h=Maj(a,b,c)=Ch(a^b,c,b)
	add	%r12d,%r8d			# d+=T1
	add	%r12d,%eax			# h+=T1

	lea	20(%rbp),%rbp	# round++
	cmpb	$0,3(%rbp)
	jnz	.Lrounds_16_xx

	mov	16*4+0*8(%rsp),%rdi
	add	%r14d,%eax			# modulo-scheduled h+=Sigma0(a)
	lea	16*4(%rsi),%rsi

	add	4*0(%rdi),%eax
	add	4*1(%rdi),%ebx
	add	4*2(%rdi),%ecx
	add	4*3(%rdi),%edx
	add	4*4(%rdi),%r8d
	add	4*5(%rdi),%r9d
	add	4*6(%rdi),%r10d
	add	4*7(%rdi),%r11d

	cmp	16*4+2*8(%rsp),%rsi

	mov	%eax,4*0(%rdi)
	mov	%ebx,4*1(%rdi)
	mov	%ecx,4*2(%rdi)
	mov	%edx,4*3(%rdi)
	mov	%r8d,4*4(%rdi)
	mov	%r9d,4*5(%rdi)
	mov	%r10d,4*6(%rdi)
	mov	%r11d,4*7(%rdi)
	jb	.Lloop

	mov	88(%rsp),%rsi
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
.size	sha256_block_data_order,.-sha256_block_data_order
.section .rodata align=64
.align	64
.type	K256,@object
K256:
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
	.asciz	"SHA256 block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>"
.previous
.type	sha256_block_data_order_shaext,@function,3
.align	64
sha256_block_data_order_shaext:
_shaext_shortcut:
.cfi_startproc
	lea		K256+0x80(%rip),%rcx
	movdqu		(%rdi),%xmm1		# DCBA
	movdqu		16(%rdi),%xmm2		# HGFE
	movdqa		0x200-0x80(%rcx),%xmm7	# byte swap mask

	pshufd		$0x1b,%xmm1,%xmm0	# ABCD
	pshufd		$0xb1,%xmm1,%xmm1	# CDAB
	pshufd		$0x1b,%xmm2,%xmm2	# EFGH
	movdqa		%xmm7,%xmm8		# offload
	palignr		$8,%xmm2,%xmm1		# ABEF
	punpcklqdq	%xmm0,%xmm2		# CDGH
	jmp		.Loop_shaext

.align	16
.Loop_shaext:
	movdqu		(%rsi),%xmm3
	movdqu		0x10(%rsi),%xmm4
	movdqu		0x20(%rsi),%xmm5
	pshufb		%xmm7,%xmm3
	movdqu		0x30(%rsi),%xmm6

	movdqa		0*32-0x80(%rcx),%xmm0
	paddd		%xmm3,%xmm0
	pshufb		%xmm7,%xmm4
	movdqa		%xmm2,%xmm10	# offload
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	nop
	movdqa		%xmm1,%xmm9	# offload
	.byte	15,56,203,202

	movdqa		1*32-0x80(%rcx),%xmm0
	paddd		%xmm4,%xmm0
	pshufb		%xmm7,%xmm5
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	lea		0x40(%rsi),%rsi
	.byte	15,56,204,220
	.byte	15,56,203,202

	movdqa		2*32-0x80(%rcx),%xmm0
	paddd		%xmm5,%xmm0
	pshufb		%xmm7,%xmm6
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm6,%xmm7
	palignr		$4,%xmm5,%xmm7
	nop
	paddd		%xmm7,%xmm3
	.byte	15,56,204,229
	.byte	15,56,203,202

	movdqa		3*32-0x80(%rcx),%xmm0
	paddd		%xmm6,%xmm0
	.byte	15,56,205,222
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm3,%xmm7
	palignr		$4,%xmm6,%xmm7
	nop
	paddd		%xmm7,%xmm4
	.byte	15,56,204,238
	.byte	15,56,203,202
	movdqa		4*32-0x80(%rcx),%xmm0
	paddd		%xmm3,%xmm0
	.byte	15,56,205,227
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm4,%xmm7
	palignr		$4,%xmm3,%xmm7
	nop
	paddd		%xmm7,%xmm5
	.byte	15,56,204,243
	.byte	15,56,203,202
	movdqa		5*32-0x80(%rcx),%xmm0
	paddd		%xmm4,%xmm0
	.byte	15,56,205,236
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm5,%xmm7
	palignr		$4,%xmm4,%xmm7
	nop
	paddd		%xmm7,%xmm6
	.byte	15,56,204,220
	.byte	15,56,203,202
	movdqa		6*32-0x80(%rcx),%xmm0
	paddd		%xmm5,%xmm0
	.byte	15,56,205,245
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm6,%xmm7
	palignr		$4,%xmm5,%xmm7
	nop
	paddd		%xmm7,%xmm3
	.byte	15,56,204,229
	.byte	15,56,203,202
	movdqa		7*32-0x80(%rcx),%xmm0
	paddd		%xmm6,%xmm0
	.byte	15,56,205,222
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm3,%xmm7
	palignr		$4,%xmm6,%xmm7
	nop
	paddd		%xmm7,%xmm4
	.byte	15,56,204,238
	.byte	15,56,203,202
	movdqa		8*32-0x80(%rcx),%xmm0
	paddd		%xmm3,%xmm0
	.byte	15,56,205,227
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm4,%xmm7
	palignr		$4,%xmm3,%xmm7
	nop
	paddd		%xmm7,%xmm5
	.byte	15,56,204,243
	.byte	15,56,203,202
	movdqa		9*32-0x80(%rcx),%xmm0
	paddd		%xmm4,%xmm0
	.byte	15,56,205,236
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm5,%xmm7
	palignr		$4,%xmm4,%xmm7
	nop
	paddd		%xmm7,%xmm6
	.byte	15,56,204,220
	.byte	15,56,203,202
	movdqa		10*32-0x80(%rcx),%xmm0
	paddd		%xmm5,%xmm0
	.byte	15,56,205,245
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm6,%xmm7
	palignr		$4,%xmm5,%xmm7
	nop
	paddd		%xmm7,%xmm3
	.byte	15,56,204,229
	.byte	15,56,203,202
	movdqa		11*32-0x80(%rcx),%xmm0
	paddd		%xmm6,%xmm0
	.byte	15,56,205,222
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm3,%xmm7
	palignr		$4,%xmm6,%xmm7
	nop
	paddd		%xmm7,%xmm4
	.byte	15,56,204,238
	.byte	15,56,203,202
	movdqa		12*32-0x80(%rcx),%xmm0
	paddd		%xmm3,%xmm0
	.byte	15,56,205,227
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm4,%xmm7
	palignr		$4,%xmm3,%xmm7
	nop
	paddd		%xmm7,%xmm5
	.byte	15,56,204,243
	.byte	15,56,203,202
	movdqa		13*32-0x80(%rcx),%xmm0
	paddd		%xmm4,%xmm0
	.byte	15,56,205,236
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	movdqa		%xmm5,%xmm7
	palignr		$4,%xmm4,%xmm7
	.byte	15,56,203,202
	paddd		%xmm7,%xmm6

	movdqa		14*32-0x80(%rcx),%xmm0
	paddd		%xmm5,%xmm0
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	.byte	15,56,205,245
	movdqa		%xmm8,%xmm7
	.byte	15,56,203,202

	movdqa		15*32-0x80(%rcx),%xmm0
	paddd		%xmm6,%xmm0
	nop
	.byte	15,56,203,209
	pshufd		$0x0e,%xmm0,%xmm0
	dec		%rdx
	nop
	.byte	15,56,203,202

	paddd		%xmm10,%xmm2
	paddd		%xmm9,%xmm1
	jnz		.Loop_shaext

	pshufd		$0xb1,%xmm2,%xmm2	# DCHG
	pshufd		$0x1b,%xmm1,%xmm7	# FEBA
	pshufd		$0xb1,%xmm1,%xmm1	# BAFE
	punpckhqdq	%xmm2,%xmm1		# DCBA
	palignr		$8,%xmm7,%xmm2		# HGFE

	movdqu	%xmm1,(%rdi)
	movdqu	%xmm2,16(%rdi)
	ret
.cfi_endproc
.size	sha256_block_data_order_shaext,.-sha256_block_data_order_shaext
.type	sha256_block_data_order_ssse3,@function,3
.align	64
sha256_block_data_order_ssse3:
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
	sub	$96,%rsp
	lea	(%rsi,%rdx,4),%rdx	# inp+num*16*4
	and	$-64,%rsp		# align stack frame
	mov	%rdi,16*4+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*4+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*4+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,88(%rsp)		# save copy of %rsp
.cfi_cfa_expression	88(%rsp),deref,+8
.Lprologue_ssse3:

	mov	4*0(%rdi),%eax
	mov	4*1(%rdi),%ebx
	mov	4*2(%rdi),%ecx
	mov	4*3(%rdi),%edx
	mov	4*4(%rdi),%r8d
	mov	4*5(%rdi),%r9d
	mov	4*6(%rdi),%r10d
	mov	4*7(%rdi),%r11d
	#movdqa	K256+512+32(%rip),%xmm8
	#movdqa	K256+512+64(%rip),%xmm9
	jmp	.Lloop_ssse3
.align	16
.Lloop_ssse3:
	movdqa	K256+512(%rip),%xmm7
	movdqu	0x00(%rsi),%xmm0
	movdqu	0x10(%rsi),%xmm1
	movdqu	0x20(%rsi),%xmm2
	pshufb	%xmm7,%xmm0
	movdqu	0x30(%rsi),%xmm3
	lea	K256(%rip),%rbp
	pshufb	%xmm7,%xmm1
	movdqa	0x00(%rbp),%xmm4
	movdqa	0x20(%rbp),%xmm5
	pshufb	%xmm7,%xmm2
	paddd	%xmm0,%xmm4
	movdqa	0x40(%rbp),%xmm6
	pshufb	%xmm7,%xmm3
	movdqa	0x60(%rbp),%xmm7
	paddd	%xmm1,%xmm5
	paddd	%xmm2,%xmm6
	paddd	%xmm3,%xmm7
	movdqa	%xmm4,0x00(%rsp)
	mov	%eax,%r14d
	movdqa	%xmm5,0x10(%rsp)
	mov	%ebx,%edi
	movdqa	%xmm6,0x20(%rsp)
	xor	%ecx,%edi			# magic
	movdqa	%xmm7,0x30(%rsp)
	mov	%r8d,%r13d
	jmp	.Lssse3_00_47

.align	16
.Lssse3_00_47:
	sub	$-128,%rbp	# size optimization
	ror	$14,%r13d
	movdqa	%xmm1,%xmm4
	mov	%r14d,%eax
	mov	%r9d,%r12d
	movdqa	%xmm3,%xmm7
	ror	$9,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	ror	$5,%r13d
	xor	%eax,%r14d
	palignr	$4,%xmm0,%xmm4
	and	%r8d,%r12d
	xor	%r8d,%r13d
	palignr	$4,%xmm2,%xmm7
	add	0(%rsp),%r11d
	mov	%eax,%r15d
	xor	%r10d,%r12d
	ror	$11,%r14d
	movdqa	%xmm4,%xmm5
	xor	%ebx,%r15d
	add	%r12d,%r11d
	movdqa	%xmm4,%xmm6
	ror	$6,%r13d
	and	%r15d,%edi
	psrld	$3,%xmm4
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	paddd	%xmm7,%xmm0
	ror	$2,%r14d
	add	%r11d,%edx
	psrld	$7,%xmm6
	add	%edi,%r11d
	mov	%edx,%r13d
	pshufd	$250,%xmm3,%xmm7
	add	%r11d,%r14d
	ror	$14,%r13d
	pslld	$14,%xmm5
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	pxor	%xmm6,%xmm4
	ror	$9,%r14d
	xor	%edx,%r13d
	xor	%r9d,%r12d
	ror	$5,%r13d
	psrld	$11,%xmm6
	xor	%r11d,%r14d
	pxor	%xmm5,%xmm4
	and	%edx,%r12d
	xor	%edx,%r13d
	pslld	$11,%xmm5
	add	4(%rsp),%r10d
	mov	%r11d,%edi
	pxor	%xmm6,%xmm4
	xor	%r9d,%r12d
	ror	$11,%r14d
	movdqa	%xmm7,%xmm6
	xor	%eax,%edi
	add	%r12d,%r10d
	pxor	%xmm5,%xmm4
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	psrld	$10,%xmm7
	add	%r13d,%r10d
	xor	%eax,%r15d
	paddd	%xmm4,%xmm0
	ror	$2,%r14d
	add	%r10d,%ecx
	psrlq	$17,%xmm6
	add	%r15d,%r10d
	mov	%ecx,%r13d
	add	%r10d,%r14d
	pxor	%xmm6,%xmm7
	ror	$14,%r13d
	mov	%r14d,%r10d
	mov	%edx,%r12d
	ror	$9,%r14d
	psrlq	$2,%xmm6
	xor	%ecx,%r13d
	xor	%r8d,%r12d
	pxor	%xmm6,%xmm7
	ror	$5,%r13d
	xor	%r10d,%r14d
	and	%ecx,%r12d
	pshufd	$128,%xmm7,%xmm7
	xor	%ecx,%r13d
	add	8(%rsp),%r9d
	mov	%r10d,%r15d
	psrldq	$8,%xmm7
	xor	%r8d,%r12d
	ror	$11,%r14d
	xor	%r11d,%r15d
	add	%r12d,%r9d
	ror	$6,%r13d
	paddd	%xmm7,%xmm0
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	pshufd	$80,%xmm0,%xmm7
	xor	%r11d,%edi
	ror	$2,%r14d
	add	%r9d,%ebx
	movdqa	%xmm7,%xmm6
	add	%edi,%r9d
	mov	%ebx,%r13d
	psrld	$10,%xmm7
	add	%r9d,%r14d
	ror	$14,%r13d
	psrlq	$17,%xmm6
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	pxor	%xmm6,%xmm7
	ror	$9,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	ror	$5,%r13d
	xor	%r9d,%r14d
	psrlq	$2,%xmm6
	and	%ebx,%r12d
	xor	%ebx,%r13d
	add	12(%rsp),%r8d
	pxor	%xmm6,%xmm7
	mov	%r9d,%edi
	xor	%edx,%r12d
	ror	$11,%r14d
	pshufd	$8,%xmm7,%xmm7
	xor	%r10d,%edi
	add	%r12d,%r8d
	movdqa	0(%rbp),%xmm6
	ror	$6,%r13d
	and	%edi,%r15d
	pslldq	$8,%xmm7
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	paddd	%xmm7,%xmm0
	ror	$2,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	paddd	%xmm0,%xmm6
	mov	%eax,%r13d
	add	%r8d,%r14d
	movdqa	%xmm6,0(%rsp)
	ror	$14,%r13d
	movdqa	%xmm2,%xmm4
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	movdqa	%xmm0,%xmm7
	ror	$9,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	ror	$5,%r13d
	xor	%r8d,%r14d
	palignr	$4,%xmm1,%xmm4
	and	%eax,%r12d
	xor	%eax,%r13d
	palignr	$4,%xmm3,%xmm7
	add	16(%rsp),%edx
	mov	%r8d,%r15d
	xor	%ecx,%r12d
	ror	$11,%r14d
	movdqa	%xmm4,%xmm5
	xor	%r9d,%r15d
	add	%r12d,%edx
	movdqa	%xmm4,%xmm6
	ror	$6,%r13d
	and	%r15d,%edi
	psrld	$3,%xmm4
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	paddd	%xmm7,%xmm1
	ror	$2,%r14d
	add	%edx,%r11d
	psrld	$7,%xmm6
	add	%edi,%edx
	mov	%r11d,%r13d
	pshufd	$250,%xmm0,%xmm7
	add	%edx,%r14d
	ror	$14,%r13d
	pslld	$14,%xmm5
	mov	%r14d,%edx
	mov	%eax,%r12d
	pxor	%xmm6,%xmm4
	ror	$9,%r14d
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	ror	$5,%r13d
	psrld	$11,%xmm6
	xor	%edx,%r14d
	pxor	%xmm5,%xmm4
	and	%r11d,%r12d
	xor	%r11d,%r13d
	pslld	$11,%xmm5
	add	20(%rsp),%ecx
	mov	%edx,%edi
	pxor	%xmm6,%xmm4
	xor	%ebx,%r12d
	ror	$11,%r14d
	movdqa	%xmm7,%xmm6
	xor	%r8d,%edi
	add	%r12d,%ecx
	pxor	%xmm5,%xmm4
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	psrld	$10,%xmm7
	add	%r13d,%ecx
	xor	%r8d,%r15d
	paddd	%xmm4,%xmm1
	ror	$2,%r14d
	add	%ecx,%r10d
	psrlq	$17,%xmm6
	add	%r15d,%ecx
	mov	%r10d,%r13d
	add	%ecx,%r14d
	pxor	%xmm6,%xmm7
	ror	$14,%r13d
	mov	%r14d,%ecx
	mov	%r11d,%r12d
	ror	$9,%r14d
	psrlq	$2,%xmm6
	xor	%r10d,%r13d
	xor	%eax,%r12d
	pxor	%xmm6,%xmm7
	ror	$5,%r13d
	xor	%ecx,%r14d
	and	%r10d,%r12d
	pshufd	$128,%xmm7,%xmm7
	xor	%r10d,%r13d
	add	24(%rsp),%ebx
	mov	%ecx,%r15d
	psrldq	$8,%xmm7
	xor	%eax,%r12d
	ror	$11,%r14d
	xor	%edx,%r15d
	add	%r12d,%ebx
	ror	$6,%r13d
	paddd	%xmm7,%xmm1
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	pshufd	$80,%xmm1,%xmm7
	xor	%edx,%edi
	ror	$2,%r14d
	add	%ebx,%r9d
	movdqa	%xmm7,%xmm6
	add	%edi,%ebx
	mov	%r9d,%r13d
	psrld	$10,%xmm7
	add	%ebx,%r14d
	ror	$14,%r13d
	psrlq	$17,%xmm6
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	pxor	%xmm6,%xmm7
	ror	$9,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	ror	$5,%r13d
	xor	%ebx,%r14d
	psrlq	$2,%xmm6
	and	%r9d,%r12d
	xor	%r9d,%r13d
	add	28(%rsp),%eax
	pxor	%xmm6,%xmm7
	mov	%ebx,%edi
	xor	%r11d,%r12d
	ror	$11,%r14d
	pshufd	$8,%xmm7,%xmm7
	xor	%ecx,%edi
	add	%r12d,%eax
	movdqa	32(%rbp),%xmm6
	ror	$6,%r13d
	and	%edi,%r15d
	pslldq	$8,%xmm7
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	paddd	%xmm7,%xmm1
	ror	$2,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	paddd	%xmm1,%xmm6
	mov	%r8d,%r13d
	add	%eax,%r14d
	movdqa	%xmm6,16(%rsp)
	ror	$14,%r13d
	movdqa	%xmm3,%xmm4
	mov	%r14d,%eax
	mov	%r9d,%r12d
	movdqa	%xmm1,%xmm7
	ror	$9,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	ror	$5,%r13d
	xor	%eax,%r14d
	palignr	$4,%xmm2,%xmm4
	and	%r8d,%r12d
	xor	%r8d,%r13d
	palignr	$4,%xmm0,%xmm7
	add	32(%rsp),%r11d
	mov	%eax,%r15d
	xor	%r10d,%r12d
	ror	$11,%r14d
	movdqa	%xmm4,%xmm5
	xor	%ebx,%r15d
	add	%r12d,%r11d
	movdqa	%xmm4,%xmm6
	ror	$6,%r13d
	and	%r15d,%edi
	psrld	$3,%xmm4
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	paddd	%xmm7,%xmm2
	ror	$2,%r14d
	add	%r11d,%edx
	psrld	$7,%xmm6
	add	%edi,%r11d
	mov	%edx,%r13d
	pshufd	$250,%xmm1,%xmm7
	add	%r11d,%r14d
	ror	$14,%r13d
	pslld	$14,%xmm5
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	pxor	%xmm6,%xmm4
	ror	$9,%r14d
	xor	%edx,%r13d
	xor	%r9d,%r12d
	ror	$5,%r13d
	psrld	$11,%xmm6
	xor	%r11d,%r14d
	pxor	%xmm5,%xmm4
	and	%edx,%r12d
	xor	%edx,%r13d
	pslld	$11,%xmm5
	add	36(%rsp),%r10d
	mov	%r11d,%edi
	pxor	%xmm6,%xmm4
	xor	%r9d,%r12d
	ror	$11,%r14d
	movdqa	%xmm7,%xmm6
	xor	%eax,%edi
	add	%r12d,%r10d
	pxor	%xmm5,%xmm4
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	psrld	$10,%xmm7
	add	%r13d,%r10d
	xor	%eax,%r15d
	paddd	%xmm4,%xmm2
	ror	$2,%r14d
	add	%r10d,%ecx
	psrlq	$17,%xmm6
	add	%r15d,%r10d
	mov	%ecx,%r13d
	add	%r10d,%r14d
	pxor	%xmm6,%xmm7
	ror	$14,%r13d
	mov	%r14d,%r10d
	mov	%edx,%r12d
	ror	$9,%r14d
	psrlq	$2,%xmm6
	xor	%ecx,%r13d
	xor	%r8d,%r12d
	pxor	%xmm6,%xmm7
	ror	$5,%r13d
	xor	%r10d,%r14d
	and	%ecx,%r12d
	pshufd	$128,%xmm7,%xmm7
	xor	%ecx,%r13d
	add	40(%rsp),%r9d
	mov	%r10d,%r15d
	psrldq	$8,%xmm7
	xor	%r8d,%r12d
	ror	$11,%r14d
	xor	%r11d,%r15d
	add	%r12d,%r9d
	ror	$6,%r13d
	paddd	%xmm7,%xmm2
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	pshufd	$80,%xmm2,%xmm7
	xor	%r11d,%edi
	ror	$2,%r14d
	add	%r9d,%ebx
	movdqa	%xmm7,%xmm6
	add	%edi,%r9d
	mov	%ebx,%r13d
	psrld	$10,%xmm7
	add	%r9d,%r14d
	ror	$14,%r13d
	psrlq	$17,%xmm6
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	pxor	%xmm6,%xmm7
	ror	$9,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	ror	$5,%r13d
	xor	%r9d,%r14d
	psrlq	$2,%xmm6
	and	%ebx,%r12d
	xor	%ebx,%r13d
	add	44(%rsp),%r8d
	pxor	%xmm6,%xmm7
	mov	%r9d,%edi
	xor	%edx,%r12d
	ror	$11,%r14d
	pshufd	$8,%xmm7,%xmm7
	xor	%r10d,%edi
	add	%r12d,%r8d
	movdqa	64(%rbp),%xmm6
	ror	$6,%r13d
	and	%edi,%r15d
	pslldq	$8,%xmm7
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	paddd	%xmm7,%xmm2
	ror	$2,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	paddd	%xmm2,%xmm6
	mov	%eax,%r13d
	add	%r8d,%r14d
	movdqa	%xmm6,32(%rsp)
	ror	$14,%r13d
	movdqa	%xmm0,%xmm4
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	movdqa	%xmm2,%xmm7
	ror	$9,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	ror	$5,%r13d
	xor	%r8d,%r14d
	palignr	$4,%xmm3,%xmm4
	and	%eax,%r12d
	xor	%eax,%r13d
	palignr	$4,%xmm1,%xmm7
	add	48(%rsp),%edx
	mov	%r8d,%r15d
	xor	%ecx,%r12d
	ror	$11,%r14d
	movdqa	%xmm4,%xmm5
	xor	%r9d,%r15d
	add	%r12d,%edx
	movdqa	%xmm4,%xmm6
	ror	$6,%r13d
	and	%r15d,%edi
	psrld	$3,%xmm4
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	paddd	%xmm7,%xmm3
	ror	$2,%r14d
	add	%edx,%r11d
	psrld	$7,%xmm6
	add	%edi,%edx
	mov	%r11d,%r13d
	pshufd	$250,%xmm2,%xmm7
	add	%edx,%r14d
	ror	$14,%r13d
	pslld	$14,%xmm5
	mov	%r14d,%edx
	mov	%eax,%r12d
	pxor	%xmm6,%xmm4
	ror	$9,%r14d
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	ror	$5,%r13d
	psrld	$11,%xmm6
	xor	%edx,%r14d
	pxor	%xmm5,%xmm4
	and	%r11d,%r12d
	xor	%r11d,%r13d
	pslld	$11,%xmm5
	add	52(%rsp),%ecx
	mov	%edx,%edi
	pxor	%xmm6,%xmm4
	xor	%ebx,%r12d
	ror	$11,%r14d
	movdqa	%xmm7,%xmm6
	xor	%r8d,%edi
	add	%r12d,%ecx
	pxor	%xmm5,%xmm4
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	psrld	$10,%xmm7
	add	%r13d,%ecx
	xor	%r8d,%r15d
	paddd	%xmm4,%xmm3
	ror	$2,%r14d
	add	%ecx,%r10d
	psrlq	$17,%xmm6
	add	%r15d,%ecx
	mov	%r10d,%r13d
	add	%ecx,%r14d
	pxor	%xmm6,%xmm7
	ror	$14,%r13d
	mov	%r14d,%ecx
	mov	%r11d,%r12d
	ror	$9,%r14d
	psrlq	$2,%xmm6
	xor	%r10d,%r13d
	xor	%eax,%r12d
	pxor	%xmm6,%xmm7
	ror	$5,%r13d
	xor	%ecx,%r14d
	and	%r10d,%r12d
	pshufd	$128,%xmm7,%xmm7
	xor	%r10d,%r13d
	add	56(%rsp),%ebx
	mov	%ecx,%r15d
	psrldq	$8,%xmm7
	xor	%eax,%r12d
	ror	$11,%r14d
	xor	%edx,%r15d
	add	%r12d,%ebx
	ror	$6,%r13d
	paddd	%xmm7,%xmm3
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	pshufd	$80,%xmm3,%xmm7
	xor	%edx,%edi
	ror	$2,%r14d
	add	%ebx,%r9d
	movdqa	%xmm7,%xmm6
	add	%edi,%ebx
	mov	%r9d,%r13d
	psrld	$10,%xmm7
	add	%ebx,%r14d
	ror	$14,%r13d
	psrlq	$17,%xmm6
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	pxor	%xmm6,%xmm7
	ror	$9,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	ror	$5,%r13d
	xor	%ebx,%r14d
	psrlq	$2,%xmm6
	and	%r9d,%r12d
	xor	%r9d,%r13d
	add	60(%rsp),%eax
	pxor	%xmm6,%xmm7
	mov	%ebx,%edi
	xor	%r11d,%r12d
	ror	$11,%r14d
	pshufd	$8,%xmm7,%xmm7
	xor	%ecx,%edi
	add	%r12d,%eax
	movdqa	96(%rbp),%xmm6
	ror	$6,%r13d
	and	%edi,%r15d
	pslldq	$8,%xmm7
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	paddd	%xmm7,%xmm3
	ror	$2,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	paddd	%xmm3,%xmm6
	mov	%r8d,%r13d
	add	%eax,%r14d
	movdqa	%xmm6,48(%rsp)
	cmpb	$0,131(%rbp)
	jne	.Lssse3_00_47
	ror	$14,%r13d
	mov	%r14d,%eax
	mov	%r9d,%r12d
	ror	$9,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	ror	$5,%r13d
	xor	%eax,%r14d
	and	%r8d,%r12d
	xor	%r8d,%r13d
	add	0(%rsp),%r11d
	mov	%eax,%r15d
	xor	%r10d,%r12d
	ror	$11,%r14d
	xor	%ebx,%r15d
	add	%r12d,%r11d
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	ror	$2,%r14d
	add	%r11d,%edx
	add	%edi,%r11d
	mov	%edx,%r13d
	add	%r11d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	ror	$9,%r14d
	xor	%edx,%r13d
	xor	%r9d,%r12d
	ror	$5,%r13d
	xor	%r11d,%r14d
	and	%edx,%r12d
	xor	%edx,%r13d
	add	4(%rsp),%r10d
	mov	%r11d,%edi
	xor	%r9d,%r12d
	ror	$11,%r14d
	xor	%eax,%edi
	add	%r12d,%r10d
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	add	%r13d,%r10d
	xor	%eax,%r15d
	ror	$2,%r14d
	add	%r10d,%ecx
	add	%r15d,%r10d
	mov	%ecx,%r13d
	add	%r10d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r10d
	mov	%edx,%r12d
	ror	$9,%r14d
	xor	%ecx,%r13d
	xor	%r8d,%r12d
	ror	$5,%r13d
	xor	%r10d,%r14d
	and	%ecx,%r12d
	xor	%ecx,%r13d
	add	8(%rsp),%r9d
	mov	%r10d,%r15d
	xor	%r8d,%r12d
	ror	$11,%r14d
	xor	%r11d,%r15d
	add	%r12d,%r9d
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	xor	%r11d,%edi
	ror	$2,%r14d
	add	%r9d,%ebx
	add	%edi,%r9d
	mov	%ebx,%r13d
	add	%r9d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	ror	$9,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	ror	$5,%r13d
	xor	%r9d,%r14d
	and	%ebx,%r12d
	xor	%ebx,%r13d
	add	12(%rsp),%r8d
	mov	%r9d,%edi
	xor	%edx,%r12d
	ror	$11,%r14d
	xor	%r10d,%edi
	add	%r12d,%r8d
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	ror	$2,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	mov	%eax,%r13d
	add	%r8d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	ror	$9,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	ror	$5,%r13d
	xor	%r8d,%r14d
	and	%eax,%r12d
	xor	%eax,%r13d
	add	16(%rsp),%edx
	mov	%r8d,%r15d
	xor	%ecx,%r12d
	ror	$11,%r14d
	xor	%r9d,%r15d
	add	%r12d,%edx
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	ror	$2,%r14d
	add	%edx,%r11d
	add	%edi,%edx
	mov	%r11d,%r13d
	add	%edx,%r14d
	ror	$14,%r13d
	mov	%r14d,%edx
	mov	%eax,%r12d
	ror	$9,%r14d
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	ror	$5,%r13d
	xor	%edx,%r14d
	and	%r11d,%r12d
	xor	%r11d,%r13d
	add	20(%rsp),%ecx
	mov	%edx,%edi
	xor	%ebx,%r12d
	ror	$11,%r14d
	xor	%r8d,%edi
	add	%r12d,%ecx
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	add	%r13d,%ecx
	xor	%r8d,%r15d
	ror	$2,%r14d
	add	%ecx,%r10d
	add	%r15d,%ecx
	mov	%r10d,%r13d
	add	%ecx,%r14d
	ror	$14,%r13d
	mov	%r14d,%ecx
	mov	%r11d,%r12d
	ror	$9,%r14d
	xor	%r10d,%r13d
	xor	%eax,%r12d
	ror	$5,%r13d
	xor	%ecx,%r14d
	and	%r10d,%r12d
	xor	%r10d,%r13d
	add	24(%rsp),%ebx
	mov	%ecx,%r15d
	xor	%eax,%r12d
	ror	$11,%r14d
	xor	%edx,%r15d
	add	%r12d,%ebx
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	xor	%edx,%edi
	ror	$2,%r14d
	add	%ebx,%r9d
	add	%edi,%ebx
	mov	%r9d,%r13d
	add	%ebx,%r14d
	ror	$14,%r13d
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	ror	$9,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	ror	$5,%r13d
	xor	%ebx,%r14d
	and	%r9d,%r12d
	xor	%r9d,%r13d
	add	28(%rsp),%eax
	mov	%ebx,%edi
	xor	%r11d,%r12d
	ror	$11,%r14d
	xor	%ecx,%edi
	add	%r12d,%eax
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	ror	$2,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	mov	%r8d,%r13d
	add	%eax,%r14d
	ror	$14,%r13d
	mov	%r14d,%eax
	mov	%r9d,%r12d
	ror	$9,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	ror	$5,%r13d
	xor	%eax,%r14d
	and	%r8d,%r12d
	xor	%r8d,%r13d
	add	32(%rsp),%r11d
	mov	%eax,%r15d
	xor	%r10d,%r12d
	ror	$11,%r14d
	xor	%ebx,%r15d
	add	%r12d,%r11d
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	ror	$2,%r14d
	add	%r11d,%edx
	add	%edi,%r11d
	mov	%edx,%r13d
	add	%r11d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	ror	$9,%r14d
	xor	%edx,%r13d
	xor	%r9d,%r12d
	ror	$5,%r13d
	xor	%r11d,%r14d
	and	%edx,%r12d
	xor	%edx,%r13d
	add	36(%rsp),%r10d
	mov	%r11d,%edi
	xor	%r9d,%r12d
	ror	$11,%r14d
	xor	%eax,%edi
	add	%r12d,%r10d
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	add	%r13d,%r10d
	xor	%eax,%r15d
	ror	$2,%r14d
	add	%r10d,%ecx
	add	%r15d,%r10d
	mov	%ecx,%r13d
	add	%r10d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r10d
	mov	%edx,%r12d
	ror	$9,%r14d
	xor	%ecx,%r13d
	xor	%r8d,%r12d
	ror	$5,%r13d
	xor	%r10d,%r14d
	and	%ecx,%r12d
	xor	%ecx,%r13d
	add	40(%rsp),%r9d
	mov	%r10d,%r15d
	xor	%r8d,%r12d
	ror	$11,%r14d
	xor	%r11d,%r15d
	add	%r12d,%r9d
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	xor	%r11d,%edi
	ror	$2,%r14d
	add	%r9d,%ebx
	add	%edi,%r9d
	mov	%ebx,%r13d
	add	%r9d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	ror	$9,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	ror	$5,%r13d
	xor	%r9d,%r14d
	and	%ebx,%r12d
	xor	%ebx,%r13d
	add	44(%rsp),%r8d
	mov	%r9d,%edi
	xor	%edx,%r12d
	ror	$11,%r14d
	xor	%r10d,%edi
	add	%r12d,%r8d
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	ror	$2,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	mov	%eax,%r13d
	add	%r8d,%r14d
	ror	$14,%r13d
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	ror	$9,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	ror	$5,%r13d
	xor	%r8d,%r14d
	and	%eax,%r12d
	xor	%eax,%r13d
	add	48(%rsp),%edx
	mov	%r8d,%r15d
	xor	%ecx,%r12d
	ror	$11,%r14d
	xor	%r9d,%r15d
	add	%r12d,%edx
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	ror	$2,%r14d
	add	%edx,%r11d
	add	%edi,%edx
	mov	%r11d,%r13d
	add	%edx,%r14d
	ror	$14,%r13d
	mov	%r14d,%edx
	mov	%eax,%r12d
	ror	$9,%r14d
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	ror	$5,%r13d
	xor	%edx,%r14d
	and	%r11d,%r12d
	xor	%r11d,%r13d
	add	52(%rsp),%ecx
	mov	%edx,%edi
	xor	%ebx,%r12d
	ror	$11,%r14d
	xor	%r8d,%edi
	add	%r12d,%ecx
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	add	%r13d,%ecx
	xor	%r8d,%r15d
	ror	$2,%r14d
	add	%ecx,%r10d
	add	%r15d,%ecx
	mov	%r10d,%r13d
	add	%ecx,%r14d
	ror	$14,%r13d
	mov	%r14d,%ecx
	mov	%r11d,%r12d
	ror	$9,%r14d
	xor	%r10d,%r13d
	xor	%eax,%r12d
	ror	$5,%r13d
	xor	%ecx,%r14d
	and	%r10d,%r12d
	xor	%r10d,%r13d
	add	56(%rsp),%ebx
	mov	%ecx,%r15d
	xor	%eax,%r12d
	ror	$11,%r14d
	xor	%edx,%r15d
	add	%r12d,%ebx
	ror	$6,%r13d
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	xor	%edx,%edi
	ror	$2,%r14d
	add	%ebx,%r9d
	add	%edi,%ebx
	mov	%r9d,%r13d
	add	%ebx,%r14d
	ror	$14,%r13d
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	ror	$9,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	ror	$5,%r13d
	xor	%ebx,%r14d
	and	%r9d,%r12d
	xor	%r9d,%r13d
	add	60(%rsp),%eax
	mov	%ebx,%edi
	xor	%r11d,%r12d
	ror	$11,%r14d
	xor	%ecx,%edi
	add	%r12d,%eax
	ror	$6,%r13d
	and	%edi,%r15d
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	ror	$2,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	mov	%r8d,%r13d
	add	%eax,%r14d
	mov	16*4+0*8(%rsp),%rdi
	mov	%r14d,%eax

	add	4*0(%rdi),%eax
	lea	16*4(%rsi),%rsi
	add	4*1(%rdi),%ebx
	add	4*2(%rdi),%ecx
	add	4*3(%rdi),%edx
	add	4*4(%rdi),%r8d
	add	4*5(%rdi),%r9d
	add	4*6(%rdi),%r10d
	add	4*7(%rdi),%r11d

	cmp	16*4+2*8(%rsp),%rsi

	mov	%eax,4*0(%rdi)
	mov	%ebx,4*1(%rdi)
	mov	%ecx,4*2(%rdi)
	mov	%edx,4*3(%rdi)
	mov	%r8d,4*4(%rdi)
	mov	%r9d,4*5(%rdi)
	mov	%r10d,4*6(%rdi)
	mov	%r11d,4*7(%rdi)
	jb	.Lloop_ssse3

	mov	88(%rsp),%rsi
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
.size	sha256_block_data_order_ssse3,.-sha256_block_data_order_ssse3
.type	sha256_block_data_order_avx,@function,3
.align	64
sha256_block_data_order_avx:
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
	sub	$96,%rsp
	lea	(%rsi,%rdx,4),%rdx	# inp+num*16*4
	and	$-64,%rsp		# align stack frame
	mov	%rdi,16*4+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*4+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*4+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,88(%rsp)		# save copy of %rsp
.cfi_cfa_expression	88(%rsp),deref,+8
.Lprologue_avx:

	vzeroupper
	mov	4*0(%rdi),%eax
	mov	4*1(%rdi),%ebx
	mov	4*2(%rdi),%ecx
	mov	4*3(%rdi),%edx
	mov	4*4(%rdi),%r8d
	mov	4*5(%rdi),%r9d
	mov	4*6(%rdi),%r10d
	mov	4*7(%rdi),%r11d
	vmovdqa	K256+512+32(%rip),%xmm8
	vmovdqa	K256+512+64(%rip),%xmm9
	jmp	.Lloop_avx
.align	16
.Lloop_avx:
	vmovdqa	K256+512(%rip),%xmm7
	vmovdqu	0x00(%rsi),%xmm0
	vmovdqu	0x10(%rsi),%xmm1
	vmovdqu	0x20(%rsi),%xmm2
	vmovdqu	0x30(%rsi),%xmm3
	vpshufb	%xmm7,%xmm0,%xmm0
	lea	K256(%rip),%rbp
	vpshufb	%xmm7,%xmm1,%xmm1
	vpshufb	%xmm7,%xmm2,%xmm2
	vpaddd	0x00(%rbp),%xmm0,%xmm4
	vpshufb	%xmm7,%xmm3,%xmm3
	vpaddd	0x20(%rbp),%xmm1,%xmm5
	vpaddd	0x40(%rbp),%xmm2,%xmm6
	vpaddd	0x60(%rbp),%xmm3,%xmm7
	vmovdqa	%xmm4,0x00(%rsp)
	mov	%eax,%r14d
	vmovdqa	%xmm5,0x10(%rsp)
	mov	%ebx,%edi
	vmovdqa	%xmm6,0x20(%rsp)
	xor	%ecx,%edi			# magic
	vmovdqa	%xmm7,0x30(%rsp)
	mov	%r8d,%r13d
	jmp	.Lavx_00_47

.align	16
.Lavx_00_47:
	sub	$-128,%rbp	# size optimization
	vpalignr	$4,%xmm0,%xmm1,%xmm4
	shrd	$14,%r13d,%r13d
	mov	%r14d,%eax
	mov	%r9d,%r12d
	vpalignr	$4,%xmm2,%xmm3,%xmm7
	shrd	$9,%r14d,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	vpsrld	$7,%xmm4,%xmm6
	shrd	$5,%r13d,%r13d
	xor	%eax,%r14d
	and	%r8d,%r12d
	vpaddd	%xmm7,%xmm0,%xmm0
	xor	%r8d,%r13d
	add	0(%rsp),%r11d
	mov	%eax,%r15d
	vpsrld	$3,%xmm4,%xmm7
	xor	%r10d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ebx,%r15d
	vpslld	$14,%xmm4,%xmm5
	add	%r12d,%r11d
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	vpxor	%xmm6,%xmm7,%xmm4
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	vpshufd	$250,%xmm3,%xmm7
	shrd	$2,%r14d,%r14d
	add	%r11d,%edx
	add	%edi,%r11d
	vpsrld	$11,%xmm6,%xmm6
	mov	%edx,%r13d
	add	%r11d,%r14d
	shrd	$14,%r13d,%r13d
	vpxor	%xmm5,%xmm4,%xmm4
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	shrd	$9,%r14d,%r14d
	vpslld	$11,%xmm5,%xmm5
	xor	%edx,%r13d
	xor	%r9d,%r12d
	shrd	$5,%r13d,%r13d
	vpxor	%xmm6,%xmm4,%xmm4
	xor	%r11d,%r14d
	and	%edx,%r12d
	xor	%edx,%r13d
	vpsrld	$10,%xmm7,%xmm6
	add	4(%rsp),%r10d
	mov	%r11d,%edi
	xor	%r9d,%r12d
	vpxor	%xmm5,%xmm4,%xmm4
	shrd	$11,%r14d,%r14d
	xor	%eax,%edi
	add	%r12d,%r10d
	vpsrlq	$17,%xmm7,%xmm7
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	vpaddd	%xmm4,%xmm0,%xmm0
	add	%r13d,%r10d
	xor	%eax,%r15d
	shrd	$2,%r14d,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	add	%r10d,%ecx
	add	%r15d,%r10d
	mov	%ecx,%r13d
	vpsrlq	$2,%xmm7,%xmm7
	add	%r10d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r10d
	vpxor	%xmm7,%xmm6,%xmm6
	mov	%edx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%ecx,%r13d
	vpshufb	%xmm8,%xmm6,%xmm6
	xor	%r8d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r10d,%r14d
	vpaddd	%xmm6,%xmm0,%xmm0
	and	%ecx,%r12d
	xor	%ecx,%r13d
	add	8(%rsp),%r9d
	vpshufd	$80,%xmm0,%xmm7
	mov	%r10d,%r15d
	xor	%r8d,%r12d
	shrd	$11,%r14d,%r14d
	vpsrld	$10,%xmm7,%xmm6
	xor	%r11d,%r15d
	add	%r12d,%r9d
	shrd	$6,%r13d,%r13d
	vpsrlq	$17,%xmm7,%xmm7
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	vpxor	%xmm7,%xmm6,%xmm6
	xor	%r11d,%edi
	shrd	$2,%r14d,%r14d
	add	%r9d,%ebx
	vpsrlq	$2,%xmm7,%xmm7
	add	%edi,%r9d
	mov	%ebx,%r13d
	add	%r9d,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	vpshufb	%xmm9,%xmm6,%xmm6
	shrd	$9,%r14d,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	vpaddd	%xmm6,%xmm0,%xmm0
	shrd	$5,%r13d,%r13d
	xor	%r9d,%r14d
	and	%ebx,%r12d
	vpaddd	0(%rbp),%xmm0,%xmm6
	xor	%ebx,%r13d
	add	12(%rsp),%r8d
	mov	%r9d,%edi
	xor	%edx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r10d,%edi
	add	%r12d,%r8d
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	shrd	$2,%r14d,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	mov	%eax,%r13d
	add	%r8d,%r14d
	vmovdqa	%xmm6,0(%rsp)
	vpalignr	$4,%xmm1,%xmm2,%xmm4
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	vpalignr	$4,%xmm3,%xmm0,%xmm7
	shrd	$9,%r14d,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	vpsrld	$7,%xmm4,%xmm6
	shrd	$5,%r13d,%r13d
	xor	%r8d,%r14d
	and	%eax,%r12d
	vpaddd	%xmm7,%xmm1,%xmm1
	xor	%eax,%r13d
	add	16(%rsp),%edx
	mov	%r8d,%r15d
	vpsrld	$3,%xmm4,%xmm7
	xor	%ecx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r9d,%r15d
	vpslld	$14,%xmm4,%xmm5
	add	%r12d,%edx
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	vpxor	%xmm6,%xmm7,%xmm4
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	vpshufd	$250,%xmm0,%xmm7
	shrd	$2,%r14d,%r14d
	add	%edx,%r11d
	add	%edi,%edx
	vpsrld	$11,%xmm6,%xmm6
	mov	%r11d,%r13d
	add	%edx,%r14d
	shrd	$14,%r13d,%r13d
	vpxor	%xmm5,%xmm4,%xmm4
	mov	%r14d,%edx
	mov	%eax,%r12d
	shrd	$9,%r14d,%r14d
	vpslld	$11,%xmm5,%xmm5
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	shrd	$5,%r13d,%r13d
	vpxor	%xmm6,%xmm4,%xmm4
	xor	%edx,%r14d
	and	%r11d,%r12d
	xor	%r11d,%r13d
	vpsrld	$10,%xmm7,%xmm6
	add	20(%rsp),%ecx
	mov	%edx,%edi
	xor	%ebx,%r12d
	vpxor	%xmm5,%xmm4,%xmm4
	shrd	$11,%r14d,%r14d
	xor	%r8d,%edi
	add	%r12d,%ecx
	vpsrlq	$17,%xmm7,%xmm7
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	vpaddd	%xmm4,%xmm1,%xmm1
	add	%r13d,%ecx
	xor	%r8d,%r15d
	shrd	$2,%r14d,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	add	%ecx,%r10d
	add	%r15d,%ecx
	mov	%r10d,%r13d
	vpsrlq	$2,%xmm7,%xmm7
	add	%ecx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ecx
	vpxor	%xmm7,%xmm6,%xmm6
	mov	%r11d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r10d,%r13d
	vpshufb	%xmm8,%xmm6,%xmm6
	xor	%eax,%r12d
	shrd	$5,%r13d,%r13d
	xor	%ecx,%r14d
	vpaddd	%xmm6,%xmm1,%xmm1
	and	%r10d,%r12d
	xor	%r10d,%r13d
	add	24(%rsp),%ebx
	vpshufd	$80,%xmm1,%xmm7
	mov	%ecx,%r15d
	xor	%eax,%r12d
	shrd	$11,%r14d,%r14d
	vpsrld	$10,%xmm7,%xmm6
	xor	%edx,%r15d
	add	%r12d,%ebx
	shrd	$6,%r13d,%r13d
	vpsrlq	$17,%xmm7,%xmm7
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	vpxor	%xmm7,%xmm6,%xmm6
	xor	%edx,%edi
	shrd	$2,%r14d,%r14d
	add	%ebx,%r9d
	vpsrlq	$2,%xmm7,%xmm7
	add	%edi,%ebx
	mov	%r9d,%r13d
	add	%ebx,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	vpshufb	%xmm9,%xmm6,%xmm6
	shrd	$9,%r14d,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	vpaddd	%xmm6,%xmm1,%xmm1
	shrd	$5,%r13d,%r13d
	xor	%ebx,%r14d
	and	%r9d,%r12d
	vpaddd	32(%rbp),%xmm1,%xmm6
	xor	%r9d,%r13d
	add	28(%rsp),%eax
	mov	%ebx,%edi
	xor	%r11d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ecx,%edi
	add	%r12d,%eax
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	shrd	$2,%r14d,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	mov	%r8d,%r13d
	add	%eax,%r14d
	vmovdqa	%xmm6,16(%rsp)
	vpalignr	$4,%xmm2,%xmm3,%xmm4
	shrd	$14,%r13d,%r13d
	mov	%r14d,%eax
	mov	%r9d,%r12d
	vpalignr	$4,%xmm0,%xmm1,%xmm7
	shrd	$9,%r14d,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	vpsrld	$7,%xmm4,%xmm6
	shrd	$5,%r13d,%r13d
	xor	%eax,%r14d
	and	%r8d,%r12d
	vpaddd	%xmm7,%xmm2,%xmm2
	xor	%r8d,%r13d
	add	32(%rsp),%r11d
	mov	%eax,%r15d
	vpsrld	$3,%xmm4,%xmm7
	xor	%r10d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ebx,%r15d
	vpslld	$14,%xmm4,%xmm5
	add	%r12d,%r11d
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	vpxor	%xmm6,%xmm7,%xmm4
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	vpshufd	$250,%xmm1,%xmm7
	shrd	$2,%r14d,%r14d
	add	%r11d,%edx
	add	%edi,%r11d
	vpsrld	$11,%xmm6,%xmm6
	mov	%edx,%r13d
	add	%r11d,%r14d
	shrd	$14,%r13d,%r13d
	vpxor	%xmm5,%xmm4,%xmm4
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	shrd	$9,%r14d,%r14d
	vpslld	$11,%xmm5,%xmm5
	xor	%edx,%r13d
	xor	%r9d,%r12d
	shrd	$5,%r13d,%r13d
	vpxor	%xmm6,%xmm4,%xmm4
	xor	%r11d,%r14d
	and	%edx,%r12d
	xor	%edx,%r13d
	vpsrld	$10,%xmm7,%xmm6
	add	36(%rsp),%r10d
	mov	%r11d,%edi
	xor	%r9d,%r12d
	vpxor	%xmm5,%xmm4,%xmm4
	shrd	$11,%r14d,%r14d
	xor	%eax,%edi
	add	%r12d,%r10d
	vpsrlq	$17,%xmm7,%xmm7
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	vpaddd	%xmm4,%xmm2,%xmm2
	add	%r13d,%r10d
	xor	%eax,%r15d
	shrd	$2,%r14d,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	add	%r10d,%ecx
	add	%r15d,%r10d
	mov	%ecx,%r13d
	vpsrlq	$2,%xmm7,%xmm7
	add	%r10d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r10d
	vpxor	%xmm7,%xmm6,%xmm6
	mov	%edx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%ecx,%r13d
	vpshufb	%xmm8,%xmm6,%xmm6
	xor	%r8d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r10d,%r14d
	vpaddd	%xmm6,%xmm2,%xmm2
	and	%ecx,%r12d
	xor	%ecx,%r13d
	add	40(%rsp),%r9d
	vpshufd	$80,%xmm2,%xmm7
	mov	%r10d,%r15d
	xor	%r8d,%r12d
	shrd	$11,%r14d,%r14d
	vpsrld	$10,%xmm7,%xmm6
	xor	%r11d,%r15d
	add	%r12d,%r9d
	shrd	$6,%r13d,%r13d
	vpsrlq	$17,%xmm7,%xmm7
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	vpxor	%xmm7,%xmm6,%xmm6
	xor	%r11d,%edi
	shrd	$2,%r14d,%r14d
	add	%r9d,%ebx
	vpsrlq	$2,%xmm7,%xmm7
	add	%edi,%r9d
	mov	%ebx,%r13d
	add	%r9d,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	vpshufb	%xmm9,%xmm6,%xmm6
	shrd	$9,%r14d,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	vpaddd	%xmm6,%xmm2,%xmm2
	shrd	$5,%r13d,%r13d
	xor	%r9d,%r14d
	and	%ebx,%r12d
	vpaddd	64(%rbp),%xmm2,%xmm6
	xor	%ebx,%r13d
	add	44(%rsp),%r8d
	mov	%r9d,%edi
	xor	%edx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r10d,%edi
	add	%r12d,%r8d
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	shrd	$2,%r14d,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	mov	%eax,%r13d
	add	%r8d,%r14d
	vmovdqa	%xmm6,32(%rsp)
	vpalignr	$4,%xmm3,%xmm0,%xmm4
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	vpalignr	$4,%xmm1,%xmm2,%xmm7
	shrd	$9,%r14d,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	vpsrld	$7,%xmm4,%xmm6
	shrd	$5,%r13d,%r13d
	xor	%r8d,%r14d
	and	%eax,%r12d
	vpaddd	%xmm7,%xmm3,%xmm3
	xor	%eax,%r13d
	add	48(%rsp),%edx
	mov	%r8d,%r15d
	vpsrld	$3,%xmm4,%xmm7
	xor	%ecx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r9d,%r15d
	vpslld	$14,%xmm4,%xmm5
	add	%r12d,%edx
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	vpxor	%xmm6,%xmm7,%xmm4
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	vpshufd	$250,%xmm2,%xmm7
	shrd	$2,%r14d,%r14d
	add	%edx,%r11d
	add	%edi,%edx
	vpsrld	$11,%xmm6,%xmm6
	mov	%r11d,%r13d
	add	%edx,%r14d
	shrd	$14,%r13d,%r13d
	vpxor	%xmm5,%xmm4,%xmm4
	mov	%r14d,%edx
	mov	%eax,%r12d
	shrd	$9,%r14d,%r14d
	vpslld	$11,%xmm5,%xmm5
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	shrd	$5,%r13d,%r13d
	vpxor	%xmm6,%xmm4,%xmm4
	xor	%edx,%r14d
	and	%r11d,%r12d
	xor	%r11d,%r13d
	vpsrld	$10,%xmm7,%xmm6
	add	52(%rsp),%ecx
	mov	%edx,%edi
	xor	%ebx,%r12d
	vpxor	%xmm5,%xmm4,%xmm4
	shrd	$11,%r14d,%r14d
	xor	%r8d,%edi
	add	%r12d,%ecx
	vpsrlq	$17,%xmm7,%xmm7
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	vpaddd	%xmm4,%xmm3,%xmm3
	add	%r13d,%ecx
	xor	%r8d,%r15d
	shrd	$2,%r14d,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	add	%ecx,%r10d
	add	%r15d,%ecx
	mov	%r10d,%r13d
	vpsrlq	$2,%xmm7,%xmm7
	add	%ecx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ecx
	vpxor	%xmm7,%xmm6,%xmm6
	mov	%r11d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r10d,%r13d
	vpshufb	%xmm8,%xmm6,%xmm6
	xor	%eax,%r12d
	shrd	$5,%r13d,%r13d
	xor	%ecx,%r14d
	vpaddd	%xmm6,%xmm3,%xmm3
	and	%r10d,%r12d
	xor	%r10d,%r13d
	add	56(%rsp),%ebx
	vpshufd	$80,%xmm3,%xmm7
	mov	%ecx,%r15d
	xor	%eax,%r12d
	shrd	$11,%r14d,%r14d
	vpsrld	$10,%xmm7,%xmm6
	xor	%edx,%r15d
	add	%r12d,%ebx
	shrd	$6,%r13d,%r13d
	vpsrlq	$17,%xmm7,%xmm7
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	vpxor	%xmm7,%xmm6,%xmm6
	xor	%edx,%edi
	shrd	$2,%r14d,%r14d
	add	%ebx,%r9d
	vpsrlq	$2,%xmm7,%xmm7
	add	%edi,%ebx
	mov	%r9d,%r13d
	add	%ebx,%r14d
	vpxor	%xmm7,%xmm6,%xmm6
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	vpshufb	%xmm9,%xmm6,%xmm6
	shrd	$9,%r14d,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	vpaddd	%xmm6,%xmm3,%xmm3
	shrd	$5,%r13d,%r13d
	xor	%ebx,%r14d
	and	%r9d,%r12d
	vpaddd	96(%rbp),%xmm3,%xmm6
	xor	%r9d,%r13d
	add	60(%rsp),%eax
	mov	%ebx,%edi
	xor	%r11d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ecx,%edi
	add	%r12d,%eax
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	shrd	$2,%r14d,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	mov	%r8d,%r13d
	add	%eax,%r14d
	vmovdqa	%xmm6,48(%rsp)
	cmpb	$0,131(%rbp)
	jne	.Lavx_00_47
	shrd	$14,%r13d,%r13d
	mov	%r14d,%eax
	mov	%r9d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%eax,%r14d
	and	%r8d,%r12d
	xor	%r8d,%r13d
	add	0(%rsp),%r11d
	mov	%eax,%r15d
	xor	%r10d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ebx,%r15d
	add	%r12d,%r11d
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	shrd	$2,%r14d,%r14d
	add	%r11d,%edx
	add	%edi,%r11d
	mov	%edx,%r13d
	add	%r11d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%edx,%r13d
	xor	%r9d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r11d,%r14d
	and	%edx,%r12d
	xor	%edx,%r13d
	add	4(%rsp),%r10d
	mov	%r11d,%edi
	xor	%r9d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%eax,%edi
	add	%r12d,%r10d
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	add	%r13d,%r10d
	xor	%eax,%r15d
	shrd	$2,%r14d,%r14d
	add	%r10d,%ecx
	add	%r15d,%r10d
	mov	%ecx,%r13d
	add	%r10d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r10d
	mov	%edx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%ecx,%r13d
	xor	%r8d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r10d,%r14d
	and	%ecx,%r12d
	xor	%ecx,%r13d
	add	8(%rsp),%r9d
	mov	%r10d,%r15d
	xor	%r8d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r11d,%r15d
	add	%r12d,%r9d
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	xor	%r11d,%edi
	shrd	$2,%r14d,%r14d
	add	%r9d,%ebx
	add	%edi,%r9d
	mov	%ebx,%r13d
	add	%r9d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r9d,%r14d
	and	%ebx,%r12d
	xor	%ebx,%r13d
	add	12(%rsp),%r8d
	mov	%r9d,%edi
	xor	%edx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r10d,%edi
	add	%r12d,%r8d
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	shrd	$2,%r14d,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	mov	%eax,%r13d
	add	%r8d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r8d,%r14d
	and	%eax,%r12d
	xor	%eax,%r13d
	add	16(%rsp),%edx
	mov	%r8d,%r15d
	xor	%ecx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r9d,%r15d
	add	%r12d,%edx
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	shrd	$2,%r14d,%r14d
	add	%edx,%r11d
	add	%edi,%edx
	mov	%r11d,%r13d
	add	%edx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%edx
	mov	%eax,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	shrd	$5,%r13d,%r13d
	xor	%edx,%r14d
	and	%r11d,%r12d
	xor	%r11d,%r13d
	add	20(%rsp),%ecx
	mov	%edx,%edi
	xor	%ebx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r8d,%edi
	add	%r12d,%ecx
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	add	%r13d,%ecx
	xor	%r8d,%r15d
	shrd	$2,%r14d,%r14d
	add	%ecx,%r10d
	add	%r15d,%ecx
	mov	%r10d,%r13d
	add	%ecx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ecx
	mov	%r11d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r10d,%r13d
	xor	%eax,%r12d
	shrd	$5,%r13d,%r13d
	xor	%ecx,%r14d
	and	%r10d,%r12d
	xor	%r10d,%r13d
	add	24(%rsp),%ebx
	mov	%ecx,%r15d
	xor	%eax,%r12d
	shrd	$11,%r14d,%r14d
	xor	%edx,%r15d
	add	%r12d,%ebx
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	xor	%edx,%edi
	shrd	$2,%r14d,%r14d
	add	%ebx,%r9d
	add	%edi,%ebx
	mov	%r9d,%r13d
	add	%ebx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%ebx,%r14d
	and	%r9d,%r12d
	xor	%r9d,%r13d
	add	28(%rsp),%eax
	mov	%ebx,%edi
	xor	%r11d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ecx,%edi
	add	%r12d,%eax
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	shrd	$2,%r14d,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	mov	%r8d,%r13d
	add	%eax,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%eax
	mov	%r9d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r8d,%r13d
	xor	%r10d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%eax,%r14d
	and	%r8d,%r12d
	xor	%r8d,%r13d
	add	32(%rsp),%r11d
	mov	%eax,%r15d
	xor	%r10d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ebx,%r15d
	add	%r12d,%r11d
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%eax,%r14d
	add	%r13d,%r11d
	xor	%ebx,%edi
	shrd	$2,%r14d,%r14d
	add	%r11d,%edx
	add	%edi,%r11d
	mov	%edx,%r13d
	add	%r11d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r11d
	mov	%r8d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%edx,%r13d
	xor	%r9d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r11d,%r14d
	and	%edx,%r12d
	xor	%edx,%r13d
	add	36(%rsp),%r10d
	mov	%r11d,%edi
	xor	%r9d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%eax,%edi
	add	%r12d,%r10d
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r11d,%r14d
	add	%r13d,%r10d
	xor	%eax,%r15d
	shrd	$2,%r14d,%r14d
	add	%r10d,%ecx
	add	%r15d,%r10d
	mov	%ecx,%r13d
	add	%r10d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r10d
	mov	%edx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%ecx,%r13d
	xor	%r8d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r10d,%r14d
	and	%ecx,%r12d
	xor	%ecx,%r13d
	add	40(%rsp),%r9d
	mov	%r10d,%r15d
	xor	%r8d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r11d,%r15d
	add	%r12d,%r9d
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%r10d,%r14d
	add	%r13d,%r9d
	xor	%r11d,%edi
	shrd	$2,%r14d,%r14d
	add	%r9d,%ebx
	add	%edi,%r9d
	mov	%ebx,%r13d
	add	%r9d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r9d
	mov	%ecx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%ebx,%r13d
	xor	%edx,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r9d,%r14d
	and	%ebx,%r12d
	xor	%ebx,%r13d
	add	44(%rsp),%r8d
	mov	%r9d,%edi
	xor	%edx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r10d,%edi
	add	%r12d,%r8d
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%r9d,%r14d
	add	%r13d,%r8d
	xor	%r10d,%r15d
	shrd	$2,%r14d,%r14d
	add	%r8d,%eax
	add	%r15d,%r8d
	mov	%eax,%r13d
	add	%r8d,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%r8d
	mov	%ebx,%r12d
	shrd	$9,%r14d,%r14d
	xor	%eax,%r13d
	xor	%ecx,%r12d
	shrd	$5,%r13d,%r13d
	xor	%r8d,%r14d
	and	%eax,%r12d
	xor	%eax,%r13d
	add	48(%rsp),%edx
	mov	%r8d,%r15d
	xor	%ecx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r9d,%r15d
	add	%r12d,%edx
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%r8d,%r14d
	add	%r13d,%edx
	xor	%r9d,%edi
	shrd	$2,%r14d,%r14d
	add	%edx,%r11d
	add	%edi,%edx
	mov	%r11d,%r13d
	add	%edx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%edx
	mov	%eax,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r11d,%r13d
	xor	%ebx,%r12d
	shrd	$5,%r13d,%r13d
	xor	%edx,%r14d
	and	%r11d,%r12d
	xor	%r11d,%r13d
	add	52(%rsp),%ecx
	mov	%edx,%edi
	xor	%ebx,%r12d
	shrd	$11,%r14d,%r14d
	xor	%r8d,%edi
	add	%r12d,%ecx
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%edx,%r14d
	add	%r13d,%ecx
	xor	%r8d,%r15d
	shrd	$2,%r14d,%r14d
	add	%ecx,%r10d
	add	%r15d,%ecx
	mov	%r10d,%r13d
	add	%ecx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ecx
	mov	%r11d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r10d,%r13d
	xor	%eax,%r12d
	shrd	$5,%r13d,%r13d
	xor	%ecx,%r14d
	and	%r10d,%r12d
	xor	%r10d,%r13d
	add	56(%rsp),%ebx
	mov	%ecx,%r15d
	xor	%eax,%r12d
	shrd	$11,%r14d,%r14d
	xor	%edx,%r15d
	add	%r12d,%ebx
	shrd	$6,%r13d,%r13d
	and	%r15d,%edi
	xor	%ecx,%r14d
	add	%r13d,%ebx
	xor	%edx,%edi
	shrd	$2,%r14d,%r14d
	add	%ebx,%r9d
	add	%edi,%ebx
	mov	%r9d,%r13d
	add	%ebx,%r14d
	shrd	$14,%r13d,%r13d
	mov	%r14d,%ebx
	mov	%r10d,%r12d
	shrd	$9,%r14d,%r14d
	xor	%r9d,%r13d
	xor	%r11d,%r12d
	shrd	$5,%r13d,%r13d
	xor	%ebx,%r14d
	and	%r9d,%r12d
	xor	%r9d,%r13d
	add	60(%rsp),%eax
	mov	%ebx,%edi
	xor	%r11d,%r12d
	shrd	$11,%r14d,%r14d
	xor	%ecx,%edi
	add	%r12d,%eax
	shrd	$6,%r13d,%r13d
	and	%edi,%r15d
	xor	%ebx,%r14d
	add	%r13d,%eax
	xor	%ecx,%r15d
	shrd	$2,%r14d,%r14d
	add	%eax,%r8d
	add	%r15d,%eax
	mov	%r8d,%r13d
	add	%eax,%r14d
	mov	16*4+0*8(%rsp),%rdi
	mov	%r14d,%eax

	add	4*0(%rdi),%eax
	lea	16*4(%rsi),%rsi
	add	4*1(%rdi),%ebx
	add	4*2(%rdi),%ecx
	add	4*3(%rdi),%edx
	add	4*4(%rdi),%r8d
	add	4*5(%rdi),%r9d
	add	4*6(%rdi),%r10d
	add	4*7(%rdi),%r11d

	cmp	16*4+2*8(%rsp),%rsi

	mov	%eax,4*0(%rdi)
	mov	%ebx,4*1(%rdi)
	mov	%ecx,4*2(%rdi)
	mov	%edx,4*3(%rdi)
	mov	%r8d,4*4(%rdi)
	mov	%r9d,4*5(%rdi)
	mov	%r10d,4*6(%rdi)
	mov	%r11d,4*7(%rdi)
	jb	.Lloop_avx

	mov	88(%rsp),%rsi
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
.size	sha256_block_data_order_avx,.-sha256_block_data_order_avx
.type	sha256_block_data_order_avx2,@function,3
.align	64
sha256_block_data_order_avx2:
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
	sub	$544,%rsp
	shl	$4,%rdx		# num*16
	and	$-256*4,%rsp		# align stack frame
	lea	(%rsi,%rdx,4),%rdx	# inp+num*16*4
	add	$448,%rsp
	mov	%rdi,16*4+0*8(%rsp)		# save ctx, 1st arg
	mov	%rsi,16*4+1*8(%rsp)		# save inp, 2nd arh
	mov	%rdx,16*4+2*8(%rsp)		# save end pointer, "3rd" arg
	mov	%rax,88(%rsp)		# save copy of %rsp
.cfi_cfa_expression	88(%rsp),deref,+8
.Lprologue_avx2:

	vzeroupper
	sub	$-16*4,%rsi		# inp++, size optimization
	mov	4*0(%rdi),%eax
	mov	%rsi,%r12		# borrow %r12d
	mov	4*1(%rdi),%ebx
	cmp	%rdx,%rsi		# 16*4+2*8(%rsp)
	mov	4*2(%rdi),%ecx
	cmove	%rsp,%r12		# next block or random data
	mov	4*3(%rdi),%edx
	mov	4*4(%rdi),%r8d
	mov	4*5(%rdi),%r9d
	mov	4*6(%rdi),%r10d
	mov	4*7(%rdi),%r11d
	vmovdqa	K256+512+32(%rip),%ymm8
	vmovdqa	K256+512+64(%rip),%ymm9
	jmp	.Loop_avx2
.align	16
.Loop_avx2:
	vmovdqa	K256+512(%rip),%ymm7
	vmovdqu	-16*4+0(%rsi),%xmm0
	vmovdqu	-16*4+16(%rsi),%xmm1
	vmovdqu	-16*4+32(%rsi),%xmm2
	vmovdqu	-16*4+48(%rsi),%xmm3
	#mov		%rsi,16*4+1*8(%rsp)	# offload %rsi
	vinserti128	$1,(%r12),%ymm0,%ymm0
	vinserti128	$1,16(%r12),%ymm1,%ymm1
	vpshufb		%ymm7,%ymm0,%ymm0
	vinserti128	$1,32(%r12),%ymm2,%ymm2
	vpshufb		%ymm7,%ymm1,%ymm1
	vinserti128	$1,48(%r12),%ymm3,%ymm3

	lea	K256(%rip),%rbp
	vpshufb	%ymm7,%ymm2,%ymm2
	vpaddd	0x00(%rbp),%ymm0,%ymm4
	vpshufb	%ymm7,%ymm3,%ymm3
	vpaddd	0x20(%rbp),%ymm1,%ymm5
	vpaddd	0x40(%rbp),%ymm2,%ymm6
	vpaddd	0x60(%rbp),%ymm3,%ymm7
	vmovdqa	%ymm4,0x00(%rsp)
	xor	%r14d,%r14d
	vmovdqa	%ymm5,0x20(%rsp)
# temporarily use %rdi as frame pointer
	mov	88(%rsp),%rdi
.cfi_def_cfa	%rdi,8
	lea	-64(%rsp),%rsp
# the frame info is at 88(%rsp), but the stack is moving...
# so a second frame pointer is saved at -8(%rsp)
# that is in the red zone
	mov	%rdi,-8(%rsp)
.cfi_cfa_expression	%rsp-8,deref,+8
	mov	%ebx,%edi
	vmovdqa	%ymm6,0x00(%rsp)
	xor	%ecx,%edi			# magic
	vmovdqa	%ymm7,0x20(%rsp)
	mov	%r9d,%r12d
	sub	$-16*2*4,%rbp	# size optimization
	jmp	.Lavx2_00_47

.align	16
.Lavx2_00_47:
	lea	-64(%rsp),%rsp
.cfi_cfa_expression	%rsp+56,deref,+8
# copy secondary frame pointer to new location again at -8(%rsp)
	pushq	64-8(%rsp)
.cfi_cfa_expression	%rsp,deref,+8
	lea	8(%rsp),%rsp
.cfi_cfa_expression	%rsp-8,deref,+8
	vpalignr	$4,%ymm0,%ymm1,%ymm4
	add	0+2*64(%rsp),%r11d
	and	%r8d,%r12d
	rorx	$25,%r8d,%r13d
	vpalignr	$4,%ymm2,%ymm3,%ymm7
	rorx	$11,%r8d,%r15d
	lea	(%eax,%r14d),%eax
	lea	(%r11d,%r12d),%r11d
	vpsrld	$7,%ymm4,%ymm6
	andn	%r10d,%r8d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r8d,%r14d
	vpaddd	%ymm7,%ymm0,%ymm0
	lea	(%r11d,%r12d),%r11d
	xor	%r14d,%r13d
	mov	%eax,%r15d
	vpsrld	$3,%ymm4,%ymm7
	rorx	$22,%eax,%r12d
	lea	(%r11d,%r13d),%r11d
	xor	%ebx,%r15d
	vpslld	$14,%ymm4,%ymm5
	rorx	$13,%eax,%r14d
	rorx	$2,%eax,%r13d
	lea	(%edx,%r11d),%edx
	vpxor	%ymm6,%ymm7,%ymm4
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%ebx,%edi
	vpshufd	$250,%ymm3,%ymm7
	xor	%r13d,%r14d
	lea	(%r11d,%edi),%r11d
	mov	%r8d,%r12d
	vpsrld	$11,%ymm6,%ymm6
	add	4+2*64(%rsp),%r10d
	and	%edx,%r12d
	rorx	$25,%edx,%r13d
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$11,%edx,%edi
	lea	(%r11d,%r14d),%r11d
	lea	(%r10d,%r12d),%r10d
	vpslld	$11,%ymm5,%ymm5
	andn	%r9d,%edx,%r12d
	xor	%edi,%r13d
	rorx	$6,%edx,%r14d
	vpxor	%ymm6,%ymm4,%ymm4
	lea	(%r10d,%r12d),%r10d
	xor	%r14d,%r13d
	mov	%r11d,%edi
	vpsrld	$10,%ymm7,%ymm6
	rorx	$22,%r11d,%r12d
	lea	(%r10d,%r13d),%r10d
	xor	%eax,%edi
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$13,%r11d,%r14d
	rorx	$2,%r11d,%r13d
	lea	(%ecx,%r10d),%ecx
	vpsrlq	$17,%ymm7,%ymm7
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%eax,%r15d
	vpaddd	%ymm4,%ymm0,%ymm0
	xor	%r13d,%r14d
	lea	(%r10d,%r15d),%r10d
	mov	%edx,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	8+2*64(%rsp),%r9d
	and	%ecx,%r12d
	rorx	$25,%ecx,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%ecx,%r15d
	lea	(%r10d,%r14d),%r10d
	lea	(%r9d,%r12d),%r9d
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%r8d,%ecx,%r12d
	xor	%r15d,%r13d
	rorx	$6,%ecx,%r14d
	vpshufb	%ymm8,%ymm6,%ymm6
	lea	(%r9d,%r12d),%r9d
	xor	%r14d,%r13d
	mov	%r10d,%r15d
	vpaddd	%ymm6,%ymm0,%ymm0
	rorx	$22,%r10d,%r12d
	lea	(%r9d,%r13d),%r9d
	xor	%r11d,%r15d
	vpshufd	$80,%ymm0,%ymm7
	rorx	$13,%r10d,%r14d
	rorx	$2,%r10d,%r13d
	lea	(%ebx,%r9d),%ebx
	vpsrld	$10,%ymm7,%ymm6
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r11d,%edi
	vpsrlq	$17,%ymm7,%ymm7
	xor	%r13d,%r14d
	lea	(%r9d,%edi),%r9d
	mov	%ecx,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	12+2*64(%rsp),%r8d
	and	%ebx,%r12d
	rorx	$25,%ebx,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%ebx,%edi
	lea	(%r9d,%r14d),%r9d
	lea	(%r8d,%r12d),%r8d
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%edx,%ebx,%r12d
	xor	%edi,%r13d
	rorx	$6,%ebx,%r14d
	vpshufb	%ymm9,%ymm6,%ymm6
	lea	(%r8d,%r12d),%r8d
	xor	%r14d,%r13d
	mov	%r9d,%edi
	vpaddd	%ymm6,%ymm0,%ymm0
	rorx	$22,%r9d,%r12d
	lea	(%r8d,%r13d),%r8d
	xor	%r10d,%edi
	vpaddd	0(%rbp),%ymm0,%ymm6
	rorx	$13,%r9d,%r14d
	rorx	$2,%r9d,%r13d
	lea	(%eax,%r8d),%eax
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r10d,%r15d
	xor	%r13d,%r14d
	lea	(%r8d,%r15d),%r8d
	mov	%ebx,%r12d
	vmovdqa	%ymm6,0(%rsp)
	vpalignr	$4,%ymm1,%ymm2,%ymm4
	add	32+2*64(%rsp),%edx
	and	%eax,%r12d
	rorx	$25,%eax,%r13d
	vpalignr	$4,%ymm3,%ymm0,%ymm7
	rorx	$11,%eax,%r15d
	lea	(%r8d,%r14d),%r8d
	lea	(%edx,%r12d),%edx
	vpsrld	$7,%ymm4,%ymm6
	andn	%ecx,%eax,%r12d
	xor	%r15d,%r13d
	rorx	$6,%eax,%r14d
	vpaddd	%ymm7,%ymm1,%ymm1
	lea	(%edx,%r12d),%edx
	xor	%r14d,%r13d
	mov	%r8d,%r15d
	vpsrld	$3,%ymm4,%ymm7
	rorx	$22,%r8d,%r12d
	lea	(%edx,%r13d),%edx
	xor	%r9d,%r15d
	vpslld	$14,%ymm4,%ymm5
	rorx	$13,%r8d,%r14d
	rorx	$2,%r8d,%r13d
	lea	(%r11d,%edx),%r11d
	vpxor	%ymm6,%ymm7,%ymm4
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r9d,%edi
	vpshufd	$250,%ymm0,%ymm7
	xor	%r13d,%r14d
	lea	(%edx,%edi),%edx
	mov	%eax,%r12d
	vpsrld	$11,%ymm6,%ymm6
	add	36+2*64(%rsp),%ecx
	and	%r11d,%r12d
	rorx	$25,%r11d,%r13d
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$11,%r11d,%edi
	lea	(%edx,%r14d),%edx
	lea	(%ecx,%r12d),%ecx
	vpslld	$11,%ymm5,%ymm5
	andn	%ebx,%r11d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r11d,%r14d
	vpxor	%ymm6,%ymm4,%ymm4
	lea	(%ecx,%r12d),%ecx
	xor	%r14d,%r13d
	mov	%edx,%edi
	vpsrld	$10,%ymm7,%ymm6
	rorx	$22,%edx,%r12d
	lea	(%ecx,%r13d),%ecx
	xor	%r8d,%edi
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$13,%edx,%r14d
	rorx	$2,%edx,%r13d
	lea	(%r10d,%ecx),%r10d
	vpsrlq	$17,%ymm7,%ymm7
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r8d,%r15d
	vpaddd	%ymm4,%ymm1,%ymm1
	xor	%r13d,%r14d
	lea	(%ecx,%r15d),%ecx
	mov	%r11d,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	40+2*64(%rsp),%ebx
	and	%r10d,%r12d
	rorx	$25,%r10d,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%r10d,%r15d
	lea	(%ecx,%r14d),%ecx
	lea	(%ebx,%r12d),%ebx
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%eax,%r10d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r10d,%r14d
	vpshufb	%ymm8,%ymm6,%ymm6
	lea	(%ebx,%r12d),%ebx
	xor	%r14d,%r13d
	mov	%ecx,%r15d
	vpaddd	%ymm6,%ymm1,%ymm1
	rorx	$22,%ecx,%r12d
	lea	(%ebx,%r13d),%ebx
	xor	%edx,%r15d
	vpshufd	$80,%ymm1,%ymm7
	rorx	$13,%ecx,%r14d
	rorx	$2,%ecx,%r13d
	lea	(%r9d,%ebx),%r9d
	vpsrld	$10,%ymm7,%ymm6
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%edx,%edi
	vpsrlq	$17,%ymm7,%ymm7
	xor	%r13d,%r14d
	lea	(%ebx,%edi),%ebx
	mov	%r10d,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	44+2*64(%rsp),%eax
	and	%r9d,%r12d
	rorx	$25,%r9d,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%r9d,%edi
	lea	(%ebx,%r14d),%ebx
	lea	(%eax,%r12d),%eax
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%r11d,%r9d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r9d,%r14d
	vpshufb	%ymm9,%ymm6,%ymm6
	lea	(%eax,%r12d),%eax
	xor	%r14d,%r13d
	mov	%ebx,%edi
	vpaddd	%ymm6,%ymm1,%ymm1
	rorx	$22,%ebx,%r12d
	lea	(%eax,%r13d),%eax
	xor	%ecx,%edi
	vpaddd	32(%rbp),%ymm1,%ymm6
	rorx	$13,%ebx,%r14d
	rorx	$2,%ebx,%r13d
	lea	(%r8d,%eax),%r8d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%ecx,%r15d
	xor	%r13d,%r14d
	lea	(%eax,%r15d),%eax
	mov	%r9d,%r12d
	vmovdqa	%ymm6,32(%rsp)
	lea	-64(%rsp),%rsp
.cfi_cfa_expression	%rsp+56,deref,+8
# copy secondary frame pointer to new location again at -8(%rsp)
	pushq	64-8(%rsp)
.cfi_cfa_expression	%rsp,deref,+8
	lea	8(%rsp),%rsp
.cfi_cfa_expression	%rsp-8,deref,+8
	vpalignr	$4,%ymm2,%ymm3,%ymm4
	add	0+2*64(%rsp),%r11d
	and	%r8d,%r12d
	rorx	$25,%r8d,%r13d
	vpalignr	$4,%ymm0,%ymm1,%ymm7
	rorx	$11,%r8d,%r15d
	lea	(%eax,%r14d),%eax
	lea	(%r11d,%r12d),%r11d
	vpsrld	$7,%ymm4,%ymm6
	andn	%r10d,%r8d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r8d,%r14d
	vpaddd	%ymm7,%ymm2,%ymm2
	lea	(%r11d,%r12d),%r11d
	xor	%r14d,%r13d
	mov	%eax,%r15d
	vpsrld	$3,%ymm4,%ymm7
	rorx	$22,%eax,%r12d
	lea	(%r11d,%r13d),%r11d
	xor	%ebx,%r15d
	vpslld	$14,%ymm4,%ymm5
	rorx	$13,%eax,%r14d
	rorx	$2,%eax,%r13d
	lea	(%edx,%r11d),%edx
	vpxor	%ymm6,%ymm7,%ymm4
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%ebx,%edi
	vpshufd	$250,%ymm1,%ymm7
	xor	%r13d,%r14d
	lea	(%r11d,%edi),%r11d
	mov	%r8d,%r12d
	vpsrld	$11,%ymm6,%ymm6
	add	4+2*64(%rsp),%r10d
	and	%edx,%r12d
	rorx	$25,%edx,%r13d
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$11,%edx,%edi
	lea	(%r11d,%r14d),%r11d
	lea	(%r10d,%r12d),%r10d
	vpslld	$11,%ymm5,%ymm5
	andn	%r9d,%edx,%r12d
	xor	%edi,%r13d
	rorx	$6,%edx,%r14d
	vpxor	%ymm6,%ymm4,%ymm4
	lea	(%r10d,%r12d),%r10d
	xor	%r14d,%r13d
	mov	%r11d,%edi
	vpsrld	$10,%ymm7,%ymm6
	rorx	$22,%r11d,%r12d
	lea	(%r10d,%r13d),%r10d
	xor	%eax,%edi
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$13,%r11d,%r14d
	rorx	$2,%r11d,%r13d
	lea	(%ecx,%r10d),%ecx
	vpsrlq	$17,%ymm7,%ymm7
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%eax,%r15d
	vpaddd	%ymm4,%ymm2,%ymm2
	xor	%r13d,%r14d
	lea	(%r10d,%r15d),%r10d
	mov	%edx,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	8+2*64(%rsp),%r9d
	and	%ecx,%r12d
	rorx	$25,%ecx,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%ecx,%r15d
	lea	(%r10d,%r14d),%r10d
	lea	(%r9d,%r12d),%r9d
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%r8d,%ecx,%r12d
	xor	%r15d,%r13d
	rorx	$6,%ecx,%r14d
	vpshufb	%ymm8,%ymm6,%ymm6
	lea	(%r9d,%r12d),%r9d
	xor	%r14d,%r13d
	mov	%r10d,%r15d
	vpaddd	%ymm6,%ymm2,%ymm2
	rorx	$22,%r10d,%r12d
	lea	(%r9d,%r13d),%r9d
	xor	%r11d,%r15d
	vpshufd	$80,%ymm2,%ymm7
	rorx	$13,%r10d,%r14d
	rorx	$2,%r10d,%r13d
	lea	(%ebx,%r9d),%ebx
	vpsrld	$10,%ymm7,%ymm6
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r11d,%edi
	vpsrlq	$17,%ymm7,%ymm7
	xor	%r13d,%r14d
	lea	(%r9d,%edi),%r9d
	mov	%ecx,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	12+2*64(%rsp),%r8d
	and	%ebx,%r12d
	rorx	$25,%ebx,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%ebx,%edi
	lea	(%r9d,%r14d),%r9d
	lea	(%r8d,%r12d),%r8d
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%edx,%ebx,%r12d
	xor	%edi,%r13d
	rorx	$6,%ebx,%r14d
	vpshufb	%ymm9,%ymm6,%ymm6
	lea	(%r8d,%r12d),%r8d
	xor	%r14d,%r13d
	mov	%r9d,%edi
	vpaddd	%ymm6,%ymm2,%ymm2
	rorx	$22,%r9d,%r12d
	lea	(%r8d,%r13d),%r8d
	xor	%r10d,%edi
	vpaddd	64(%rbp),%ymm2,%ymm6
	rorx	$13,%r9d,%r14d
	rorx	$2,%r9d,%r13d
	lea	(%eax,%r8d),%eax
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r10d,%r15d
	xor	%r13d,%r14d
	lea	(%r8d,%r15d),%r8d
	mov	%ebx,%r12d
	vmovdqa	%ymm6,0(%rsp)
	vpalignr	$4,%ymm3,%ymm0,%ymm4
	add	32+2*64(%rsp),%edx
	and	%eax,%r12d
	rorx	$25,%eax,%r13d
	vpalignr	$4,%ymm1,%ymm2,%ymm7
	rorx	$11,%eax,%r15d
	lea	(%r8d,%r14d),%r8d
	lea	(%edx,%r12d),%edx
	vpsrld	$7,%ymm4,%ymm6
	andn	%ecx,%eax,%r12d
	xor	%r15d,%r13d
	rorx	$6,%eax,%r14d
	vpaddd	%ymm7,%ymm3,%ymm3
	lea	(%edx,%r12d),%edx
	xor	%r14d,%r13d
	mov	%r8d,%r15d
	vpsrld	$3,%ymm4,%ymm7
	rorx	$22,%r8d,%r12d
	lea	(%edx,%r13d),%edx
	xor	%r9d,%r15d
	vpslld	$14,%ymm4,%ymm5
	rorx	$13,%r8d,%r14d
	rorx	$2,%r8d,%r13d
	lea	(%r11d,%edx),%r11d
	vpxor	%ymm6,%ymm7,%ymm4
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r9d,%edi
	vpshufd	$250,%ymm2,%ymm7
	xor	%r13d,%r14d
	lea	(%edx,%edi),%edx
	mov	%eax,%r12d
	vpsrld	$11,%ymm6,%ymm6
	add	36+2*64(%rsp),%ecx
	and	%r11d,%r12d
	rorx	$25,%r11d,%r13d
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$11,%r11d,%edi
	lea	(%edx,%r14d),%edx
	lea	(%ecx,%r12d),%ecx
	vpslld	$11,%ymm5,%ymm5
	andn	%ebx,%r11d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r11d,%r14d
	vpxor	%ymm6,%ymm4,%ymm4
	lea	(%ecx,%r12d),%ecx
	xor	%r14d,%r13d
	mov	%edx,%edi
	vpsrld	$10,%ymm7,%ymm6
	rorx	$22,%edx,%r12d
	lea	(%ecx,%r13d),%ecx
	xor	%r8d,%edi
	vpxor	%ymm5,%ymm4,%ymm4
	rorx	$13,%edx,%r14d
	rorx	$2,%edx,%r13d
	lea	(%r10d,%ecx),%r10d
	vpsrlq	$17,%ymm7,%ymm7
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r8d,%r15d
	vpaddd	%ymm4,%ymm3,%ymm3
	xor	%r13d,%r14d
	lea	(%ecx,%r15d),%ecx
	mov	%r11d,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	40+2*64(%rsp),%ebx
	and	%r10d,%r12d
	rorx	$25,%r10d,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%r10d,%r15d
	lea	(%ecx,%r14d),%ecx
	lea	(%ebx,%r12d),%ebx
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%eax,%r10d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r10d,%r14d
	vpshufb	%ymm8,%ymm6,%ymm6
	lea	(%ebx,%r12d),%ebx
	xor	%r14d,%r13d
	mov	%ecx,%r15d
	vpaddd	%ymm6,%ymm3,%ymm3
	rorx	$22,%ecx,%r12d
	lea	(%ebx,%r13d),%ebx
	xor	%edx,%r15d
	vpshufd	$80,%ymm3,%ymm7
	rorx	$13,%ecx,%r14d
	rorx	$2,%ecx,%r13d
	lea	(%r9d,%ebx),%r9d
	vpsrld	$10,%ymm7,%ymm6
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%edx,%edi
	vpsrlq	$17,%ymm7,%ymm7
	xor	%r13d,%r14d
	lea	(%ebx,%edi),%ebx
	mov	%r10d,%r12d
	vpxor	%ymm7,%ymm6,%ymm6
	add	44+2*64(%rsp),%eax
	and	%r9d,%r12d
	rorx	$25,%r9d,%r13d
	vpsrlq	$2,%ymm7,%ymm7
	rorx	$11,%r9d,%edi
	lea	(%ebx,%r14d),%ebx
	lea	(%eax,%r12d),%eax
	vpxor	%ymm7,%ymm6,%ymm6
	andn	%r11d,%r9d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r9d,%r14d
	vpshufb	%ymm9,%ymm6,%ymm6
	lea	(%eax,%r12d),%eax
	xor	%r14d,%r13d
	mov	%ebx,%edi
	vpaddd	%ymm6,%ymm3,%ymm3
	rorx	$22,%ebx,%r12d
	lea	(%eax,%r13d),%eax
	xor	%ecx,%edi
	vpaddd	96(%rbp),%ymm3,%ymm6
	rorx	$13,%ebx,%r14d
	rorx	$2,%ebx,%r13d
	lea	(%r8d,%eax),%r8d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%ecx,%r15d
	xor	%r13d,%r14d
	lea	(%eax,%r15d),%eax
	mov	%r9d,%r12d
	vmovdqa	%ymm6,32(%rsp)
	lea	128(%rbp),%rbp
	cmpb	$0,3(%rbp)
	jne	.Lavx2_00_47
	add	0+64(%rsp),%r11d
	and	%r8d,%r12d
	rorx	$25,%r8d,%r13d
	rorx	$11,%r8d,%r15d
	lea	(%eax,%r14d),%eax
	lea	(%r11d,%r12d),%r11d
	andn	%r10d,%r8d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r8d,%r14d
	lea	(%r11d,%r12d),%r11d
	xor	%r14d,%r13d
	mov	%eax,%r15d
	rorx	$22,%eax,%r12d
	lea	(%r11d,%r13d),%r11d
	xor	%ebx,%r15d
	rorx	$13,%eax,%r14d
	rorx	$2,%eax,%r13d
	lea	(%edx,%r11d),%edx
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%ebx,%edi
	xor	%r13d,%r14d
	lea	(%r11d,%edi),%r11d
	mov	%r8d,%r12d
	add	4+64(%rsp),%r10d
	and	%edx,%r12d
	rorx	$25,%edx,%r13d
	rorx	$11,%edx,%edi
	lea	(%r11d,%r14d),%r11d
	lea	(%r10d,%r12d),%r10d
	andn	%r9d,%edx,%r12d
	xor	%edi,%r13d
	rorx	$6,%edx,%r14d
	lea	(%r10d,%r12d),%r10d
	xor	%r14d,%r13d
	mov	%r11d,%edi
	rorx	$22,%r11d,%r12d
	lea	(%r10d,%r13d),%r10d
	xor	%eax,%edi
	rorx	$13,%r11d,%r14d
	rorx	$2,%r11d,%r13d
	lea	(%ecx,%r10d),%ecx
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%eax,%r15d
	xor	%r13d,%r14d
	lea	(%r10d,%r15d),%r10d
	mov	%edx,%r12d
	add	8+64(%rsp),%r9d
	and	%ecx,%r12d
	rorx	$25,%ecx,%r13d
	rorx	$11,%ecx,%r15d
	lea	(%r10d,%r14d),%r10d
	lea	(%r9d,%r12d),%r9d
	andn	%r8d,%ecx,%r12d
	xor	%r15d,%r13d
	rorx	$6,%ecx,%r14d
	lea	(%r9d,%r12d),%r9d
	xor	%r14d,%r13d
	mov	%r10d,%r15d
	rorx	$22,%r10d,%r12d
	lea	(%r9d,%r13d),%r9d
	xor	%r11d,%r15d
	rorx	$13,%r10d,%r14d
	rorx	$2,%r10d,%r13d
	lea	(%ebx,%r9d),%ebx
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r11d,%edi
	xor	%r13d,%r14d
	lea	(%r9d,%edi),%r9d
	mov	%ecx,%r12d
	add	12+64(%rsp),%r8d
	and	%ebx,%r12d
	rorx	$25,%ebx,%r13d
	rorx	$11,%ebx,%edi
	lea	(%r9d,%r14d),%r9d
	lea	(%r8d,%r12d),%r8d
	andn	%edx,%ebx,%r12d
	xor	%edi,%r13d
	rorx	$6,%ebx,%r14d
	lea	(%r8d,%r12d),%r8d
	xor	%r14d,%r13d
	mov	%r9d,%edi
	rorx	$22,%r9d,%r12d
	lea	(%r8d,%r13d),%r8d
	xor	%r10d,%edi
	rorx	$13,%r9d,%r14d
	rorx	$2,%r9d,%r13d
	lea	(%eax,%r8d),%eax
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r10d,%r15d
	xor	%r13d,%r14d
	lea	(%r8d,%r15d),%r8d
	mov	%ebx,%r12d
	add	32+64(%rsp),%edx
	and	%eax,%r12d
	rorx	$25,%eax,%r13d
	rorx	$11,%eax,%r15d
	lea	(%r8d,%r14d),%r8d
	lea	(%edx,%r12d),%edx
	andn	%ecx,%eax,%r12d
	xor	%r15d,%r13d
	rorx	$6,%eax,%r14d
	lea	(%edx,%r12d),%edx
	xor	%r14d,%r13d
	mov	%r8d,%r15d
	rorx	$22,%r8d,%r12d
	lea	(%edx,%r13d),%edx
	xor	%r9d,%r15d
	rorx	$13,%r8d,%r14d
	rorx	$2,%r8d,%r13d
	lea	(%r11d,%edx),%r11d
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r9d,%edi
	xor	%r13d,%r14d
	lea	(%edx,%edi),%edx
	mov	%eax,%r12d
	add	36+64(%rsp),%ecx
	and	%r11d,%r12d
	rorx	$25,%r11d,%r13d
	rorx	$11,%r11d,%edi
	lea	(%edx,%r14d),%edx
	lea	(%ecx,%r12d),%ecx
	andn	%ebx,%r11d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r11d,%r14d
	lea	(%ecx,%r12d),%ecx
	xor	%r14d,%r13d
	mov	%edx,%edi
	rorx	$22,%edx,%r12d
	lea	(%ecx,%r13d),%ecx
	xor	%r8d,%edi
	rorx	$13,%edx,%r14d
	rorx	$2,%edx,%r13d
	lea	(%r10d,%ecx),%r10d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r8d,%r15d
	xor	%r13d,%r14d
	lea	(%ecx,%r15d),%ecx
	mov	%r11d,%r12d
	add	40+64(%rsp),%ebx
	and	%r10d,%r12d
	rorx	$25,%r10d,%r13d
	rorx	$11,%r10d,%r15d
	lea	(%ecx,%r14d),%ecx
	lea	(%ebx,%r12d),%ebx
	andn	%eax,%r10d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r10d,%r14d
	lea	(%ebx,%r12d),%ebx
	xor	%r14d,%r13d
	mov	%ecx,%r15d
	rorx	$22,%ecx,%r12d
	lea	(%ebx,%r13d),%ebx
	xor	%edx,%r15d
	rorx	$13,%ecx,%r14d
	rorx	$2,%ecx,%r13d
	lea	(%r9d,%ebx),%r9d
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%edx,%edi
	xor	%r13d,%r14d
	lea	(%ebx,%edi),%ebx
	mov	%r10d,%r12d
	add	44+64(%rsp),%eax
	and	%r9d,%r12d
	rorx	$25,%r9d,%r13d
	rorx	$11,%r9d,%edi
	lea	(%ebx,%r14d),%ebx
	lea	(%eax,%r12d),%eax
	andn	%r11d,%r9d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r9d,%r14d
	lea	(%eax,%r12d),%eax
	xor	%r14d,%r13d
	mov	%ebx,%edi
	rorx	$22,%ebx,%r12d
	lea	(%eax,%r13d),%eax
	xor	%ecx,%edi
	rorx	$13,%ebx,%r14d
	rorx	$2,%ebx,%r13d
	lea	(%r8d,%eax),%r8d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%ecx,%r15d
	xor	%r13d,%r14d
	lea	(%eax,%r15d),%eax
	mov	%r9d,%r12d
	add	0(%rsp),%r11d
	and	%r8d,%r12d
	rorx	$25,%r8d,%r13d
	rorx	$11,%r8d,%r15d
	lea	(%eax,%r14d),%eax
	lea	(%r11d,%r12d),%r11d
	andn	%r10d,%r8d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r8d,%r14d
	lea	(%r11d,%r12d),%r11d
	xor	%r14d,%r13d
	mov	%eax,%r15d
	rorx	$22,%eax,%r12d
	lea	(%r11d,%r13d),%r11d
	xor	%ebx,%r15d
	rorx	$13,%eax,%r14d
	rorx	$2,%eax,%r13d
	lea	(%edx,%r11d),%edx
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%ebx,%edi
	xor	%r13d,%r14d
	lea	(%r11d,%edi),%r11d
	mov	%r8d,%r12d
	add	4(%rsp),%r10d
	and	%edx,%r12d
	rorx	$25,%edx,%r13d
	rorx	$11,%edx,%edi
	lea	(%r11d,%r14d),%r11d
	lea	(%r10d,%r12d),%r10d
	andn	%r9d,%edx,%r12d
	xor	%edi,%r13d
	rorx	$6,%edx,%r14d
	lea	(%r10d,%r12d),%r10d
	xor	%r14d,%r13d
	mov	%r11d,%edi
	rorx	$22,%r11d,%r12d
	lea	(%r10d,%r13d),%r10d
	xor	%eax,%edi
	rorx	$13,%r11d,%r14d
	rorx	$2,%r11d,%r13d
	lea	(%ecx,%r10d),%ecx
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%eax,%r15d
	xor	%r13d,%r14d
	lea	(%r10d,%r15d),%r10d
	mov	%edx,%r12d
	add	8(%rsp),%r9d
	and	%ecx,%r12d
	rorx	$25,%ecx,%r13d
	rorx	$11,%ecx,%r15d
	lea	(%r10d,%r14d),%r10d
	lea	(%r9d,%r12d),%r9d
	andn	%r8d,%ecx,%r12d
	xor	%r15d,%r13d
	rorx	$6,%ecx,%r14d
	lea	(%r9d,%r12d),%r9d
	xor	%r14d,%r13d
	mov	%r10d,%r15d
	rorx	$22,%r10d,%r12d
	lea	(%r9d,%r13d),%r9d
	xor	%r11d,%r15d
	rorx	$13,%r10d,%r14d
	rorx	$2,%r10d,%r13d
	lea	(%ebx,%r9d),%ebx
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r11d,%edi
	xor	%r13d,%r14d
	lea	(%r9d,%edi),%r9d
	mov	%ecx,%r12d
	add	12(%rsp),%r8d
	and	%ebx,%r12d
	rorx	$25,%ebx,%r13d
	rorx	$11,%ebx,%edi
	lea	(%r9d,%r14d),%r9d
	lea	(%r8d,%r12d),%r8d
	andn	%edx,%ebx,%r12d
	xor	%edi,%r13d
	rorx	$6,%ebx,%r14d
	lea	(%r8d,%r12d),%r8d
	xor	%r14d,%r13d
	mov	%r9d,%edi
	rorx	$22,%r9d,%r12d
	lea	(%r8d,%r13d),%r8d
	xor	%r10d,%edi
	rorx	$13,%r9d,%r14d
	rorx	$2,%r9d,%r13d
	lea	(%eax,%r8d),%eax
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r10d,%r15d
	xor	%r13d,%r14d
	lea	(%r8d,%r15d),%r8d
	mov	%ebx,%r12d
	add	32(%rsp),%edx
	and	%eax,%r12d
	rorx	$25,%eax,%r13d
	rorx	$11,%eax,%r15d
	lea	(%r8d,%r14d),%r8d
	lea	(%edx,%r12d),%edx
	andn	%ecx,%eax,%r12d
	xor	%r15d,%r13d
	rorx	$6,%eax,%r14d
	lea	(%edx,%r12d),%edx
	xor	%r14d,%r13d
	mov	%r8d,%r15d
	rorx	$22,%r8d,%r12d
	lea	(%edx,%r13d),%edx
	xor	%r9d,%r15d
	rorx	$13,%r8d,%r14d
	rorx	$2,%r8d,%r13d
	lea	(%r11d,%edx),%r11d
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r9d,%edi
	xor	%r13d,%r14d
	lea	(%edx,%edi),%edx
	mov	%eax,%r12d
	add	36(%rsp),%ecx
	and	%r11d,%r12d
	rorx	$25,%r11d,%r13d
	rorx	$11,%r11d,%edi
	lea	(%edx,%r14d),%edx
	lea	(%ecx,%r12d),%ecx
	andn	%ebx,%r11d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r11d,%r14d
	lea	(%ecx,%r12d),%ecx
	xor	%r14d,%r13d
	mov	%edx,%edi
	rorx	$22,%edx,%r12d
	lea	(%ecx,%r13d),%ecx
	xor	%r8d,%edi
	rorx	$13,%edx,%r14d
	rorx	$2,%edx,%r13d
	lea	(%r10d,%ecx),%r10d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r8d,%r15d
	xor	%r13d,%r14d
	lea	(%ecx,%r15d),%ecx
	mov	%r11d,%r12d
	add	40(%rsp),%ebx
	and	%r10d,%r12d
	rorx	$25,%r10d,%r13d
	rorx	$11,%r10d,%r15d
	lea	(%ecx,%r14d),%ecx
	lea	(%ebx,%r12d),%ebx
	andn	%eax,%r10d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r10d,%r14d
	lea	(%ebx,%r12d),%ebx
	xor	%r14d,%r13d
	mov	%ecx,%r15d
	rorx	$22,%ecx,%r12d
	lea	(%ebx,%r13d),%ebx
	xor	%edx,%r15d
	rorx	$13,%ecx,%r14d
	rorx	$2,%ecx,%r13d
	lea	(%r9d,%ebx),%r9d
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%edx,%edi
	xor	%r13d,%r14d
	lea	(%ebx,%edi),%ebx
	mov	%r10d,%r12d
	add	44(%rsp),%eax
	and	%r9d,%r12d
	rorx	$25,%r9d,%r13d
	rorx	$11,%r9d,%edi
	lea	(%ebx,%r14d),%ebx
	lea	(%eax,%r12d),%eax
	andn	%r11d,%r9d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r9d,%r14d
	lea	(%eax,%r12d),%eax
	xor	%r14d,%r13d
	mov	%ebx,%edi
	rorx	$22,%ebx,%r12d
	lea	(%eax,%r13d),%eax
	xor	%ecx,%edi
	rorx	$13,%ebx,%r14d
	rorx	$2,%ebx,%r13d
	lea	(%r8d,%eax),%r8d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%ecx,%r15d
	xor	%r13d,%r14d
	lea	(%eax,%r15d),%eax
	mov	%r9d,%r12d
	mov	512(%rsp),%rdi	# 16*4+0*8(%rsp)
	add	%r14d,%eax
	#mov	520(%rsp),%rsi	# 16*4+1*8(%rsp)
	lea	448(%rsp),%rbp

	add	4*0(%rdi),%eax
	add	4*1(%rdi),%ebx
	add	4*2(%rdi),%ecx
	add	4*3(%rdi),%edx
	add	4*4(%rdi),%r8d
	add	4*5(%rdi),%r9d
	add	4*6(%rdi),%r10d
	add	4*7(%rdi),%r11d

	mov	%eax,4*0(%rdi)
	mov	%ebx,4*1(%rdi)
	mov	%ecx,4*2(%rdi)
	mov	%edx,4*3(%rdi)
	mov	%r8d,4*4(%rdi)
	mov	%r9d,4*5(%rdi)
	mov	%r10d,4*6(%rdi)
	mov	%r11d,4*7(%rdi)

	cmp	80(%rbp),%rsi	# 16*4+2*8(%rsp)
	je	.Ldone_avx2

	xor	%r14d,%r14d
	mov	%ebx,%edi
	xor	%ecx,%edi			# magic
	mov	%r9d,%r12d
	jmp	.Lower_avx2
.align	16
.Lower_avx2:
	add	0+16(%rbp),%r11d
	and	%r8d,%r12d
	rorx	$25,%r8d,%r13d
	rorx	$11,%r8d,%r15d
	lea	(%eax,%r14d),%eax
	lea	(%r11d,%r12d),%r11d
	andn	%r10d,%r8d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r8d,%r14d
	lea	(%r11d,%r12d),%r11d
	xor	%r14d,%r13d
	mov	%eax,%r15d
	rorx	$22,%eax,%r12d
	lea	(%r11d,%r13d),%r11d
	xor	%ebx,%r15d
	rorx	$13,%eax,%r14d
	rorx	$2,%eax,%r13d
	lea	(%edx,%r11d),%edx
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%ebx,%edi
	xor	%r13d,%r14d
	lea	(%r11d,%edi),%r11d
	mov	%r8d,%r12d
	add	4+16(%rbp),%r10d
	and	%edx,%r12d
	rorx	$25,%edx,%r13d
	rorx	$11,%edx,%edi
	lea	(%r11d,%r14d),%r11d
	lea	(%r10d,%r12d),%r10d
	andn	%r9d,%edx,%r12d
	xor	%edi,%r13d
	rorx	$6,%edx,%r14d
	lea	(%r10d,%r12d),%r10d
	xor	%r14d,%r13d
	mov	%r11d,%edi
	rorx	$22,%r11d,%r12d
	lea	(%r10d,%r13d),%r10d
	xor	%eax,%edi
	rorx	$13,%r11d,%r14d
	rorx	$2,%r11d,%r13d
	lea	(%ecx,%r10d),%ecx
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%eax,%r15d
	xor	%r13d,%r14d
	lea	(%r10d,%r15d),%r10d
	mov	%edx,%r12d
	add	8+16(%rbp),%r9d
	and	%ecx,%r12d
	rorx	$25,%ecx,%r13d
	rorx	$11,%ecx,%r15d
	lea	(%r10d,%r14d),%r10d
	lea	(%r9d,%r12d),%r9d
	andn	%r8d,%ecx,%r12d
	xor	%r15d,%r13d
	rorx	$6,%ecx,%r14d
	lea	(%r9d,%r12d),%r9d
	xor	%r14d,%r13d
	mov	%r10d,%r15d
	rorx	$22,%r10d,%r12d
	lea	(%r9d,%r13d),%r9d
	xor	%r11d,%r15d
	rorx	$13,%r10d,%r14d
	rorx	$2,%r10d,%r13d
	lea	(%ebx,%r9d),%ebx
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r11d,%edi
	xor	%r13d,%r14d
	lea	(%r9d,%edi),%r9d
	mov	%ecx,%r12d
	add	12+16(%rbp),%r8d
	and	%ebx,%r12d
	rorx	$25,%ebx,%r13d
	rorx	$11,%ebx,%edi
	lea	(%r9d,%r14d),%r9d
	lea	(%r8d,%r12d),%r8d
	andn	%edx,%ebx,%r12d
	xor	%edi,%r13d
	rorx	$6,%ebx,%r14d
	lea	(%r8d,%r12d),%r8d
	xor	%r14d,%r13d
	mov	%r9d,%edi
	rorx	$22,%r9d,%r12d
	lea	(%r8d,%r13d),%r8d
	xor	%r10d,%edi
	rorx	$13,%r9d,%r14d
	rorx	$2,%r9d,%r13d
	lea	(%eax,%r8d),%eax
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r10d,%r15d
	xor	%r13d,%r14d
	lea	(%r8d,%r15d),%r8d
	mov	%ebx,%r12d
	add	32+16(%rbp),%edx
	and	%eax,%r12d
	rorx	$25,%eax,%r13d
	rorx	$11,%eax,%r15d
	lea	(%r8d,%r14d),%r8d
	lea	(%edx,%r12d),%edx
	andn	%ecx,%eax,%r12d
	xor	%r15d,%r13d
	rorx	$6,%eax,%r14d
	lea	(%edx,%r12d),%edx
	xor	%r14d,%r13d
	mov	%r8d,%r15d
	rorx	$22,%r8d,%r12d
	lea	(%edx,%r13d),%edx
	xor	%r9d,%r15d
	rorx	$13,%r8d,%r14d
	rorx	$2,%r8d,%r13d
	lea	(%r11d,%edx),%r11d
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%r9d,%edi
	xor	%r13d,%r14d
	lea	(%edx,%edi),%edx
	mov	%eax,%r12d
	add	36+16(%rbp),%ecx
	and	%r11d,%r12d
	rorx	$25,%r11d,%r13d
	rorx	$11,%r11d,%edi
	lea	(%edx,%r14d),%edx
	lea	(%ecx,%r12d),%ecx
	andn	%ebx,%r11d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r11d,%r14d
	lea	(%ecx,%r12d),%ecx
	xor	%r14d,%r13d
	mov	%edx,%edi
	rorx	$22,%edx,%r12d
	lea	(%ecx,%r13d),%ecx
	xor	%r8d,%edi
	rorx	$13,%edx,%r14d
	rorx	$2,%edx,%r13d
	lea	(%r10d,%ecx),%r10d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%r8d,%r15d
	xor	%r13d,%r14d
	lea	(%ecx,%r15d),%ecx
	mov	%r11d,%r12d
	add	40+16(%rbp),%ebx
	and	%r10d,%r12d
	rorx	$25,%r10d,%r13d
	rorx	$11,%r10d,%r15d
	lea	(%ecx,%r14d),%ecx
	lea	(%ebx,%r12d),%ebx
	andn	%eax,%r10d,%r12d
	xor	%r15d,%r13d
	rorx	$6,%r10d,%r14d
	lea	(%ebx,%r12d),%ebx
	xor	%r14d,%r13d
	mov	%ecx,%r15d
	rorx	$22,%ecx,%r12d
	lea	(%ebx,%r13d),%ebx
	xor	%edx,%r15d
	rorx	$13,%ecx,%r14d
	rorx	$2,%ecx,%r13d
	lea	(%r9d,%ebx),%r9d
	and	%r15d,%edi
	xor	%r12d,%r14d
	xor	%edx,%edi
	xor	%r13d,%r14d
	lea	(%ebx,%edi),%ebx
	mov	%r10d,%r12d
	add	44+16(%rbp),%eax
	and	%r9d,%r12d
	rorx	$25,%r9d,%r13d
	rorx	$11,%r9d,%edi
	lea	(%ebx,%r14d),%ebx
	lea	(%eax,%r12d),%eax
	andn	%r11d,%r9d,%r12d
	xor	%edi,%r13d
	rorx	$6,%r9d,%r14d
	lea	(%eax,%r12d),%eax
	xor	%r14d,%r13d
	mov	%ebx,%edi
	rorx	$22,%ebx,%r12d
	lea	(%eax,%r13d),%eax
	xor	%ecx,%edi
	rorx	$13,%ebx,%r14d
	rorx	$2,%ebx,%r13d
	lea	(%r8d,%eax),%r8d
	and	%edi,%r15d
	xor	%r12d,%r14d
	xor	%ecx,%r15d
	xor	%r13d,%r14d
	lea	(%eax,%r15d),%eax
	mov	%r9d,%r12d
	lea	-64(%rbp),%rbp
	cmp	%rsp,%rbp
	jae	.Lower_avx2

	mov	512(%rsp),%rdi	# 16*4+0*8(%rsp)
	add	%r14d,%eax
	#mov	520(%rsp),%rsi	# 16*4+1*8(%rsp)
	lea	448(%rsp),%rsp
# restore frame pointer to original location at 88(%rsp)
.cfi_cfa_expression	88(%rsp),deref,+8

	add	4*0(%rdi),%eax
	add	4*1(%rdi),%ebx
	add	4*2(%rdi),%ecx
	add	4*3(%rdi),%edx
	add	4*4(%rdi),%r8d
	add	4*5(%rdi),%r9d
	lea	128(%rsi),%rsi	# inp+=2
	add	4*6(%rdi),%r10d
	mov	%rsi,%r12
	add	4*7(%rdi),%r11d
	cmp	16*4+2*8(%rsp),%rsi

	mov	%eax,4*0(%rdi)
	cmove	%rsp,%r12		# next block or stale data
	mov	%ebx,4*1(%rdi)
	mov	%ecx,4*2(%rdi)
	mov	%edx,4*3(%rdi)
	mov	%r8d,4*4(%rdi)
	mov	%r9d,4*5(%rdi)
	mov	%r10d,4*6(%rdi)
	mov	%r11d,4*7(%rdi)

	jbe	.Loop_avx2
	lea	(%rsp),%rbp
# temporarily use %rbp as index to 88(%rsp)
# this avoids the need to save a secondary frame pointer at -8(%rsp)
.cfi_cfa_expression	%rbp+88,deref,+8

.Ldone_avx2:
	mov	88(%rbp),%rsi
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
.size	sha256_block_data_order_avx2,.-sha256_block_data_order_avx2
`;

export default translateAssembly(code);
