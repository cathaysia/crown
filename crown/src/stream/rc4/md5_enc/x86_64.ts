/**
 * RC4-MD5 for x86_64.
 *
 * TypeScript port of OpenSSL crypto/rc4/asm/rc4-md5-x86_64.pl.
 * Pinned to $win64=0 (unix SysV; Win64 SEH blocks dropped).
 * Exported symbols: rc4_md5_enc
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

const code = `.text
.align 16

.globl	rc4_md5_enc
.type	rc4_md5_enc,@function,6
rc4_md5_enc:
.cfi_startproc
	cmp	$0,%r9
	je	.Labort
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
	sub	$40,%rsp
.cfi_adjust_cfa_offset	40
.Lbody:
	mov	%rcx,%r11		# reassign arguments
	mov	%r9,%r12
	mov	%rsi,%r13
	mov	%rdx,%r14
	mov	%r8,%r15
	xor	%rbp,%rbp
	xor	%rcx,%rcx

	lea	8(%rdi),%rdi
	mov	-8(%rdi),%bpl
	mov	-4(%rdi),%cl

	inc	%bpl
	sub	%r13,%r14
	movl	(%rdi,%rbp,4),%eax
	add	%al,%cl
	lea	(%rdi,%rbp,4),%rsi
	shl	$6,%r12
	add	%r15,%r12		# pointer to the end of input
	mov	%r12,16(%rsp)

	mov	%r11,24(%rsp)		# save pointer to MD5_CTX
	mov	0*4(%r11),%r8d		# load current hash value from MD5_CTX
	mov	1*4(%r11),%r9d
	mov	2*4(%r11),%r10d
	mov	3*4(%r11),%r11d
	jmp	.Loop

.align	16
.Loop:
	mov	%r8d,0*4(%rsp)		# put aside current hash value
	mov	%r9d,1*4(%rsp)
	mov	%r10d,2*4(%rsp)
	mov	%r11d,%r12d		# forward reference
	mov	%r11d,3*4(%rsp)
	pxor	%xmm0,%xmm0
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*0(%r15),%r8d
	add	%dl,%al
	movl	4(%rsi),%ebx
	add	$3614090360,%r8d
	xor	%r11d,%r12d
	movz	%al,%eax
	movl	%edx,4*0(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$7,%r8d
	mov	%r10d,%r12d		# forward reference
	movd	(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	pxor	%xmm1,%xmm1
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*1(%r15),%r11d
	add	%dl,%bl
	movl	8(%rsi),%eax
	add	$3905402710,%r11d
	xor	%r10d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*1(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$12,%r11d
	mov	%r9d,%r12d		# forward reference
	movd	(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*2(%r15),%r10d
	add	%dl,%al
	movl	12(%rsi),%ebx
	add	$606105819,%r10d
	xor	%r9d,%r12d
	movz	%al,%eax
	movl	%edx,4*2(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$17,%r10d
	mov	%r8d,%r12d		# forward reference
	pinsrw	$1,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*3(%r15),%r9d
	add	%dl,%bl
	movl	16(%rsi),%eax
	add	$3250441966,%r9d
	xor	%r8d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*3(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$22,%r9d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$1,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*4(%r15),%r8d
	add	%dl,%al
	movl	20(%rsi),%ebx
	add	$4118548399,%r8d
	xor	%r11d,%r12d
	movz	%al,%eax
	movl	%edx,4*4(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$7,%r8d
	mov	%r10d,%r12d		# forward reference
	pinsrw	$2,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*5(%r15),%r11d
	add	%dl,%bl
	movl	24(%rsi),%eax
	add	$1200080426,%r11d
	xor	%r10d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*5(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$12,%r11d
	mov	%r9d,%r12d		# forward reference
	pinsrw	$2,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*6(%r15),%r10d
	add	%dl,%al
	movl	28(%rsi),%ebx
	add	$2821735955,%r10d
	xor	%r9d,%r12d
	movz	%al,%eax
	movl	%edx,4*6(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$17,%r10d
	mov	%r8d,%r12d		# forward reference
	pinsrw	$3,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*7(%r15),%r9d
	add	%dl,%bl
	movl	32(%rsi),%eax
	add	$4249261313,%r9d
	xor	%r8d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*7(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$22,%r9d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$3,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*8(%r15),%r8d
	add	%dl,%al
	movl	36(%rsi),%ebx
	add	$1770035416,%r8d
	xor	%r11d,%r12d
	movz	%al,%eax
	movl	%edx,4*8(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$7,%r8d
	mov	%r10d,%r12d		# forward reference
	pinsrw	$4,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*9(%r15),%r11d
	add	%dl,%bl
	movl	40(%rsi),%eax
	add	$2336552879,%r11d
	xor	%r10d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*9(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$12,%r11d
	mov	%r9d,%r12d		# forward reference
	pinsrw	$4,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*10(%r15),%r10d
	add	%dl,%al
	movl	44(%rsi),%ebx
	add	$4294925233,%r10d
	xor	%r9d,%r12d
	movz	%al,%eax
	movl	%edx,4*10(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$17,%r10d
	mov	%r8d,%r12d		# forward reference
	pinsrw	$5,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*11(%r15),%r9d
	add	%dl,%bl
	movl	48(%rsi),%eax
	add	$2304563134,%r9d
	xor	%r8d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*11(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$22,%r9d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$5,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*12(%r15),%r8d
	add	%dl,%al
	movl	52(%rsi),%ebx
	add	$1804603682,%r8d
	xor	%r11d,%r12d
	movz	%al,%eax
	movl	%edx,4*12(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$7,%r8d
	mov	%r10d,%r12d		# forward reference
	pinsrw	$6,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*13(%r15),%r11d
	add	%dl,%bl
	movl	56(%rsi),%eax
	add	$4254626195,%r11d
	xor	%r10d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*13(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$12,%r11d
	mov	%r9d,%r12d		# forward reference
	pinsrw	$6,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*14(%r15),%r10d
	add	%dl,%al
	movl	60(%rsi),%ebx
	add	$2792965006,%r10d
	xor	%r9d,%r12d
	movz	%al,%eax
	movl	%edx,4*14(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$17,%r10d
	mov	%r8d,%r12d		# forward reference
	pinsrw	$7,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movdqu	(%r13),%xmm2
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*15(%r15),%r9d
	add	%dl,%bl
	movl	64(%rsi),%eax
	add	$1236535329,%r9d
	xor	%r8d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*15(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$22,%r9d
	mov	%r10d,%r12d		# forward reference
	pinsrw	$7,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	psllq	$8,%xmm1
	pxor	%xmm0,%xmm2
	pxor	%xmm1,%xmm2
	pxor	%xmm0,%xmm0
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*1(%r15),%r8d
	add	%dl,%al
	movl	68(%rsi),%ebx
	add	$4129170786,%r8d
	xor	%r10d,%r12d
	movz	%al,%eax
	movl	%edx,4*16(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$5,%r8d
	mov	%r9d,%r12d		# forward reference
	movd	(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	pxor	%xmm1,%xmm1
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*6(%r15),%r11d
	add	%dl,%bl
	movl	72(%rsi),%eax
	add	$3225465664,%r11d
	xor	%r9d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*17(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$9,%r11d
	mov	%r8d,%r12d		# forward reference
	movd	(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*11(%r15),%r10d
	add	%dl,%al
	movl	76(%rsi),%ebx
	add	$643717713,%r10d
	xor	%r8d,%r12d
	movz	%al,%eax
	movl	%edx,4*18(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$14,%r10d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$1,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*0(%r15),%r9d
	add	%dl,%bl
	movl	80(%rsi),%eax
	add	$3921069994,%r9d
	xor	%r11d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*19(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$20,%r9d
	mov	%r10d,%r12d		# forward reference
	pinsrw	$1,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*5(%r15),%r8d
	add	%dl,%al
	movl	84(%rsi),%ebx
	add	$3593408605,%r8d
	xor	%r10d,%r12d
	movz	%al,%eax
	movl	%edx,4*20(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$5,%r8d
	mov	%r9d,%r12d		# forward reference
	pinsrw	$2,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*10(%r15),%r11d
	add	%dl,%bl
	movl	88(%rsi),%eax
	add	$38016083,%r11d
	xor	%r9d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*21(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$9,%r11d
	mov	%r8d,%r12d		# forward reference
	pinsrw	$2,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*15(%r15),%r10d
	add	%dl,%al
	movl	92(%rsi),%ebx
	add	$3634488961,%r10d
	xor	%r8d,%r12d
	movz	%al,%eax
	movl	%edx,4*22(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$14,%r10d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$3,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*4(%r15),%r9d
	add	%dl,%bl
	movl	96(%rsi),%eax
	add	$3889429448,%r9d
	xor	%r11d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*23(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$20,%r9d
	mov	%r10d,%r12d		# forward reference
	pinsrw	$3,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*9(%r15),%r8d
	add	%dl,%al
	movl	100(%rsi),%ebx
	add	$568446438,%r8d
	xor	%r10d,%r12d
	movz	%al,%eax
	movl	%edx,4*24(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$5,%r8d
	mov	%r9d,%r12d		# forward reference
	pinsrw	$4,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*14(%r15),%r11d
	add	%dl,%bl
	movl	104(%rsi),%eax
	add	$3275163606,%r11d
	xor	%r9d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*25(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$9,%r11d
	mov	%r8d,%r12d		# forward reference
	pinsrw	$4,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*3(%r15),%r10d
	add	%dl,%al
	movl	108(%rsi),%ebx
	add	$4107603335,%r10d
	xor	%r8d,%r12d
	movz	%al,%eax
	movl	%edx,4*26(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$14,%r10d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$5,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*8(%r15),%r9d
	add	%dl,%bl
	movl	112(%rsi),%eax
	add	$1163531501,%r9d
	xor	%r11d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*27(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$20,%r9d
	mov	%r10d,%r12d		# forward reference
	pinsrw	$5,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r11d,%r12d
	add	4*13(%r15),%r8d
	add	%dl,%al
	movl	116(%rsi),%ebx
	add	$2850285829,%r8d
	xor	%r10d,%r12d
	movz	%al,%eax
	movl	%edx,4*28(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$5,%r8d
	mov	%r9d,%r12d		# forward reference
	pinsrw	$6,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r10d,%r12d
	add	4*2(%r15),%r11d
	add	%dl,%bl
	movl	120(%rsi),%eax
	add	$4243563512,%r11d
	xor	%r9d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*29(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$9,%r11d
	mov	%r8d,%r12d		# forward reference
	pinsrw	$6,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	and	%r9d,%r12d
	add	4*7(%r15),%r10d
	add	%dl,%al
	movl	124(%rsi),%ebx
	add	$1735328473,%r10d
	xor	%r8d,%r12d
	movz	%al,%eax
	movl	%edx,4*30(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$14,%r10d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$7,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movdqu	16(%r13),%xmm3
	add	$32,%bpl
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	and	%r8d,%r12d
	add	4*12(%r15),%r9d
	add	%dl,%bl
	movl	0(%rdi,%rbp,4),%eax
	add	$2368359562,%r9d
	xor	%r11d,%r12d
	movz	%bl,%ebx
	movl	%edx,4*31(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$20,%r9d
	mov	%r11d,%r12d		# forward reference
	pinsrw	$7,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	mov	%rcx,%rsi
	xor	%rcx,%rcx				# keyword to partial register
	mov	%sil,%cl
	lea	(%rdi,%rbp,4),%rsi
	psllq	$8,%xmm1
	pxor	%xmm0,%xmm3
	pxor	%xmm1,%xmm3
	pxor	%xmm0,%xmm0
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r9d,%r12d
	add	4*5(%r15),%r8d
	add	%dl,%al
	movl	4(%rsi),%ebx
	add	$4294588738,%r8d
	movz	%al,%eax
	add	%r12d,%r8d
	movl	%edx,4*0(%rsi)
	add	%bl,%cl
	rol	$4,%r8d
	mov	%r10d,%r12d	# forward reference
	movd	(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	pxor	%xmm1,%xmm1
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r8d,%r12d
	add	4*8(%r15),%r11d
	add	%dl,%bl
	movl	8(%rsi),%eax
	add	$2272392833,%r11d
	movz	%bl,%ebx
	add	%r12d,%r11d
	movl	%edx,4*1(%rsi)
	add	%al,%cl
	rol	$11,%r11d
	mov	%r9d,%r12d	# forward reference
	movd	(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r11d,%r12d
	add	4*11(%r15),%r10d
	add	%dl,%al
	movl	12(%rsi),%ebx
	add	$1839030562,%r10d
	movz	%al,%eax
	add	%r12d,%r10d
	movl	%edx,4*2(%rsi)
	add	%bl,%cl
	rol	$16,%r10d
	mov	%r8d,%r12d	# forward reference
	pinsrw	$1,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r10d,%r12d
	add	4*14(%r15),%r9d
	add	%dl,%bl
	movl	16(%rsi),%eax
	add	$4259657740,%r9d
	movz	%bl,%ebx
	add	%r12d,%r9d
	movl	%edx,4*3(%rsi)
	add	%al,%cl
	rol	$23,%r9d
	mov	%r11d,%r12d	# forward reference
	pinsrw	$1,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r9d,%r12d
	add	4*1(%r15),%r8d
	add	%dl,%al
	movl	20(%rsi),%ebx
	add	$2763975236,%r8d
	movz	%al,%eax
	add	%r12d,%r8d
	movl	%edx,4*4(%rsi)
	add	%bl,%cl
	rol	$4,%r8d
	mov	%r10d,%r12d	# forward reference
	pinsrw	$2,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r8d,%r12d
	add	4*4(%r15),%r11d
	add	%dl,%bl
	movl	24(%rsi),%eax
	add	$1272893353,%r11d
	movz	%bl,%ebx
	add	%r12d,%r11d
	movl	%edx,4*5(%rsi)
	add	%al,%cl
	rol	$11,%r11d
	mov	%r9d,%r12d	# forward reference
	pinsrw	$2,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r11d,%r12d
	add	4*7(%r15),%r10d
	add	%dl,%al
	movl	28(%rsi),%ebx
	add	$4139469664,%r10d
	movz	%al,%eax
	add	%r12d,%r10d
	movl	%edx,4*6(%rsi)
	add	%bl,%cl
	rol	$16,%r10d
	mov	%r8d,%r12d	# forward reference
	pinsrw	$3,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r10d,%r12d
	add	4*10(%r15),%r9d
	add	%dl,%bl
	movl	32(%rsi),%eax
	add	$3200236656,%r9d
	movz	%bl,%ebx
	add	%r12d,%r9d
	movl	%edx,4*7(%rsi)
	add	%al,%cl
	rol	$23,%r9d
	mov	%r11d,%r12d	# forward reference
	pinsrw	$3,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r9d,%r12d
	add	4*13(%r15),%r8d
	add	%dl,%al
	movl	36(%rsi),%ebx
	add	$681279174,%r8d
	movz	%al,%eax
	add	%r12d,%r8d
	movl	%edx,4*8(%rsi)
	add	%bl,%cl
	rol	$4,%r8d
	mov	%r10d,%r12d	# forward reference
	pinsrw	$4,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r8d,%r12d
	add	4*0(%r15),%r11d
	add	%dl,%bl
	movl	40(%rsi),%eax
	add	$3936430074,%r11d
	movz	%bl,%ebx
	add	%r12d,%r11d
	movl	%edx,4*9(%rsi)
	add	%al,%cl
	rol	$11,%r11d
	mov	%r9d,%r12d	# forward reference
	pinsrw	$4,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r11d,%r12d
	add	4*3(%r15),%r10d
	add	%dl,%al
	movl	44(%rsi),%ebx
	add	$3572445317,%r10d
	movz	%al,%eax
	add	%r12d,%r10d
	movl	%edx,4*10(%rsi)
	add	%bl,%cl
	rol	$16,%r10d
	mov	%r8d,%r12d	# forward reference
	pinsrw	$5,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r10d,%r12d
	add	4*6(%r15),%r9d
	add	%dl,%bl
	movl	48(%rsi),%eax
	add	$76029189,%r9d
	movz	%bl,%ebx
	add	%r12d,%r9d
	movl	%edx,4*11(%rsi)
	add	%al,%cl
	rol	$23,%r9d
	mov	%r11d,%r12d	# forward reference
	pinsrw	$5,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r9d,%r12d
	add	4*9(%r15),%r8d
	add	%dl,%al
	movl	52(%rsi),%ebx
	add	$3654602809,%r8d
	movz	%al,%eax
	add	%r12d,%r8d
	movl	%edx,4*12(%rsi)
	add	%bl,%cl
	rol	$4,%r8d
	mov	%r10d,%r12d	# forward reference
	pinsrw	$6,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r8d,%r12d
	add	4*12(%r15),%r11d
	add	%dl,%bl
	movl	56(%rsi),%eax
	add	$3873151461,%r11d
	movz	%bl,%ebx
	add	%r12d,%r11d
	movl	%edx,4*13(%rsi)
	add	%al,%cl
	rol	$11,%r11d
	mov	%r9d,%r12d	# forward reference
	pinsrw	$6,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	xor	%r11d,%r12d
	add	4*15(%r15),%r10d
	add	%dl,%al
	movl	60(%rsi),%ebx
	add	$530742520,%r10d
	movz	%al,%eax
	add	%r12d,%r10d
	movl	%edx,4*14(%rsi)
	add	%bl,%cl
	rol	$16,%r10d
	mov	%r8d,%r12d	# forward reference
	pinsrw	$7,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movdqu	32(%r13),%xmm4
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	xor	%r10d,%r12d
	add	4*2(%r15),%r9d
	add	%dl,%bl
	movl	64(%rsi),%eax
	add	$3299628645,%r9d
	movz	%bl,%ebx
	add	%r12d,%r9d
	movl	%edx,4*15(%rsi)
	add	%al,%cl
	rol	$23,%r9d
	mov	$-1,%r12d	# forward reference
	pinsrw	$7,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	psllq	$8,%xmm1
	pxor	%xmm0,%xmm4
	pxor	%xmm1,%xmm4
	pxor	%xmm0,%xmm0
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r9d,%r12d
	add	4*0(%r15),%r8d
	add	%dl,%al
	movl	68(%rsi),%ebx
	add	$4096336452,%r8d
	movz	%al,%eax
	xor	%r10d,%r12d
	movl	%edx,4*16(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$6,%r8d
	mov	$-1,%r12d			# forward reference
	movd	(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	pxor	%xmm1,%xmm1
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r8d,%r12d
	add	4*7(%r15),%r11d
	add	%dl,%bl
	movl	72(%rsi),%eax
	add	$1126891415,%r11d
	movz	%bl,%ebx
	xor	%r9d,%r12d
	movl	%edx,4*17(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$10,%r11d
	mov	$-1,%r12d			# forward reference
	movd	(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r11d,%r12d
	add	4*14(%r15),%r10d
	add	%dl,%al
	movl	76(%rsi),%ebx
	add	$2878612391,%r10d
	movz	%al,%eax
	xor	%r8d,%r12d
	movl	%edx,4*18(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$15,%r10d
	mov	$-1,%r12d			# forward reference
	pinsrw	$1,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r10d,%r12d
	add	4*5(%r15),%r9d
	add	%dl,%bl
	movl	80(%rsi),%eax
	add	$4237533241,%r9d
	movz	%bl,%ebx
	xor	%r11d,%r12d
	movl	%edx,4*19(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$21,%r9d
	mov	$-1,%r12d			# forward reference
	pinsrw	$1,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r9d,%r12d
	add	4*12(%r15),%r8d
	add	%dl,%al
	movl	84(%rsi),%ebx
	add	$1700485571,%r8d
	movz	%al,%eax
	xor	%r10d,%r12d
	movl	%edx,4*20(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$6,%r8d
	mov	$-1,%r12d			# forward reference
	pinsrw	$2,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r8d,%r12d
	add	4*3(%r15),%r11d
	add	%dl,%bl
	movl	88(%rsi),%eax
	add	$2399980690,%r11d
	movz	%bl,%ebx
	xor	%r9d,%r12d
	movl	%edx,4*21(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$10,%r11d
	mov	$-1,%r12d			# forward reference
	pinsrw	$2,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r11d,%r12d
	add	4*10(%r15),%r10d
	add	%dl,%al
	movl	92(%rsi),%ebx
	add	$4293915773,%r10d
	movz	%al,%eax
	xor	%r8d,%r12d
	movl	%edx,4*22(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$15,%r10d
	mov	$-1,%r12d			# forward reference
	pinsrw	$3,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r10d,%r12d
	add	4*1(%r15),%r9d
	add	%dl,%bl
	movl	96(%rsi),%eax
	add	$2240044497,%r9d
	movz	%bl,%ebx
	xor	%r11d,%r12d
	movl	%edx,4*23(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$21,%r9d
	mov	$-1,%r12d			# forward reference
	pinsrw	$3,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r9d,%r12d
	add	4*8(%r15),%r8d
	add	%dl,%al
	movl	100(%rsi),%ebx
	add	$1873313359,%r8d
	movz	%al,%eax
	xor	%r10d,%r12d
	movl	%edx,4*24(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$6,%r8d
	mov	$-1,%r12d			# forward reference
	pinsrw	$4,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r8d,%r12d
	add	4*15(%r15),%r11d
	add	%dl,%bl
	movl	104(%rsi),%eax
	add	$4264355552,%r11d
	movz	%bl,%ebx
	xor	%r9d,%r12d
	movl	%edx,4*25(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$10,%r11d
	mov	$-1,%r12d			# forward reference
	pinsrw	$4,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r11d,%r12d
	add	4*6(%r15),%r10d
	add	%dl,%al
	movl	108(%rsi),%ebx
	add	$2734768916,%r10d
	movz	%al,%eax
	xor	%r8d,%r12d
	movl	%edx,4*26(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$15,%r10d
	mov	$-1,%r12d			# forward reference
	pinsrw	$5,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r10d,%r12d
	add	4*13(%r15),%r9d
	add	%dl,%bl
	movl	112(%rsi),%eax
	add	$1309151649,%r9d
	movz	%bl,%ebx
	xor	%r11d,%r12d
	movl	%edx,4*27(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$21,%r9d
	mov	$-1,%r12d			# forward reference
	pinsrw	$5,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	movl	(%rdi,%rcx,4),%edx
	xor	%r11d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r9d,%r12d
	add	4*4(%r15),%r8d
	add	%dl,%al
	movl	116(%rsi),%ebx
	add	$4149444226,%r8d
	movz	%al,%eax
	xor	%r10d,%r12d
	movl	%edx,4*28(%rsi)
	add	%r12d,%r8d
	add	%bl,%cl
	rol	$6,%r8d
	mov	$-1,%r12d			# forward reference
	pinsrw	$6,(%rdi,%rax,4),%xmm0

	add	%r9d,%r8d
	movl	(%rdi,%rcx,4),%edx
	xor	%r10d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r8d,%r12d
	add	4*11(%r15),%r11d
	add	%dl,%bl
	movl	120(%rsi),%eax
	add	$3174756917,%r11d
	movz	%bl,%ebx
	xor	%r9d,%r12d
	movl	%edx,4*29(%rsi)
	add	%r12d,%r11d
	add	%al,%cl
	rol	$10,%r11d
	mov	$-1,%r12d			# forward reference
	pinsrw	$6,(%rdi,%rbx,4),%xmm1

	add	%r8d,%r11d
	movl	(%rdi,%rcx,4),%edx
	xor	%r9d,%r12d
	movl	%eax,(%rdi,%rcx,4)
	or	%r11d,%r12d
	add	4*2(%r15),%r10d
	add	%dl,%al
	movl	124(%rsi),%ebx
	add	$718787259,%r10d
	movz	%al,%eax
	xor	%r8d,%r12d
	movl	%edx,4*30(%rsi)
	add	%r12d,%r10d
	add	%bl,%cl
	rol	$15,%r10d
	mov	$-1,%r12d			# forward reference
	pinsrw	$7,(%rdi,%rax,4),%xmm0

	add	%r11d,%r10d
	movdqu	48(%r13),%xmm5
	add	$32,%bpl
	movl	(%rdi,%rcx,4),%edx
	xor	%r8d,%r12d
	movl	%ebx,(%rdi,%rcx,4)
	or	%r10d,%r12d
	add	4*9(%r15),%r9d
	add	%dl,%bl
	movl	0(%rdi,%rbp,4),%eax
	add	$3951481745,%r9d
	movz	%bl,%ebx
	xor	%r11d,%r12d
	movl	%edx,4*31(%rsi)
	add	%r12d,%r9d
	add	%al,%cl
	rol	$21,%r9d
	mov	$-1,%r12d			# forward reference
	pinsrw	$7,(%rdi,%rbx,4),%xmm1

	add	%r10d,%r9d
	mov	%rbp,%rsi
	xor	%rbp,%rbp			# keyword to partial register
	mov	%sil,%bpl
	mov	%rcx,%rsi
	xor	%rcx,%rcx				# keyword to partial register
	mov	%sil,%cl
	lea	(%rdi,%rbp,4),%rsi
	psllq	$8,%xmm1
	pxor	%xmm0,%xmm5
	pxor	%xmm1,%xmm5
	add	0*4(%rsp),%r8d		# accumulate hash value
	add	1*4(%rsp),%r9d
	add	2*4(%rsp),%r10d
	add	3*4(%rsp),%r11d

	movdqu	%xmm2,(%r14,%r13)	# write RC4 output
	movdqu	%xmm3,16(%r14,%r13)
	movdqu	%xmm4,32(%r14,%r13)
	movdqu	%xmm5,48(%r14,%r13)
	lea	64(%r15),%r15
	lea	64(%r13),%r13
	cmp	16(%rsp),%r15		# are we done?
	jb	.Loop

	mov	24(%rsp),%r12		# restore pointer to MD5_CTX
	sub	%al,%cl		# correct %rcx
	mov	%r8d,0*4(%r12)		# write MD5_CTX
	mov	%r9d,1*4(%r12)
	mov	%r10d,2*4(%r12)
	mov	%r11d,3*4(%r12)
	sub	$1,%bpl
	movl	%ebp,-8(%rdi)
	movl	%ecx,-4(%rdi)

	mov	40(%rsp),%r15
.cfi_restore	%r15
	mov	48(%rsp),%r14
.cfi_restore	%r14
	mov	56(%rsp),%r13
.cfi_restore	%r13
	mov	64(%rsp),%r12
.cfi_restore	%r12
	mov	72(%rsp),%rbp
.cfi_restore	%rbp
	mov	80(%rsp),%rbx
.cfi_restore	%rbx
	lea	88(%rsp),%rsp
.cfi_adjust_cfa_offset	-88
.Lepilogue:
.Labort:
	ret
.cfi_endproc
.size rc4_md5_enc,.-rc4_md5_enc
`;

export default translateAssembly(code);
