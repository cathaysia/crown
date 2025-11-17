function generateAssembly(output?: string, flavour?: string): string {
  let win64 = 0;
  if (
    flavour &&
    (/[nm]asm|mingw64/.test(flavour) || (output && /\.asm$/.test(output)))
  ) {
    win64 = 1;
  }

  let arg1: string, arg2: string, arg3: string, arg4: string;
  if (win64) {
    [arg1, arg2, arg3, arg4] = ['%rcx', '%rdx', '%r8', '%r9'];
  } else {
    [arg1, arg2, arg3, arg4] = ['%rdi', '%rsi', '%rdx', '%rcx'];
  }

  function genRandom(rdop: string): string {
    return `
.globl	OPENSSL_ia32_${rdop}_bytes
.type	OPENSSL_ia32_${rdop}_bytes,\\@abi-omnipotent
.align	16
OPENSSL_ia32_${rdop}_bytes:
.cfi_startproc
	endbranch
	xor	%rax, %rax
	cmp	\\$0,${arg2}
	je	.Ldone_${rdop}_bytes

	mov	\\$8,%r11
.Loop_${rdop}_bytes:
	${rdop}	%r10
	jc	.Lbreak_${rdop}_bytes
	dec	%r11
	jnz	.Loop_${rdop}_bytes
	jmp	.Ldone_${rdop}_bytes

.align	16
.Lbreak_${rdop}_bytes:
	cmp	\\$8,${arg2}
	jb	.Ltail_${rdop}_bytes
	mov	%r10,(${arg1})
	lea	8(${arg1}),${arg1}
	add	\\$8,%rax
	sub	\\$8,${arg2}
	jz	.Ldone_${rdop}_bytes
	mov	\\$8,%r11
	jmp	.Loop_${rdop}_bytes

.align	16
.Ltail_${rdop}_bytes:
	mov	%r10b,(${arg1})
	lea	1(${arg1}),${arg1}
	inc	%rax
	shr	\\$8,%r10
	dec	${arg2}
	jnz	.Ltail_${rdop}_bytes

.Ldone_${rdop}_bytes:
	xor	%r10,%r10
	ret
.cfi_endproc
.size	OPENSSL_ia32_${rdop}_bytes,.-OPENSSL_ia32_${rdop}_bytes`;
  }

  const out = '%r10';
  const cnt = '%rcx';
  const max = '%r11';
  const lasttick = '%r8d';
  const lastdiff = '%r9d';
  const redzone = win64 ? 8 : -8;

  return `#include crypto/cryptlib.h
.extern		OPENSSL_cpuid_setup
.hidden		OPENSSL_cpuid_setup
.hidden	OPENSSL_ia32cap_P
.comm	OPENSSL_ia32cap_P,40,4
.text

.globl	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,\\@abi-omnipotent
.align	16
OPENSSL_atomic_add:
.cfi_startproc
	endbranch
	movl	(${arg1}),%eax
.Lspin:	leaq	(${arg2},%rax),%r8
	.byte	0xf0
	cmpxchgl	%r8d,(${arg1})
	jne	.Lspin
	movl	%r8d,%eax
	.byte	0x48,0x98
	ret
.cfi_endproc
.size	OPENSSL_atomic_add,.-OPENSSL_atomic_add

.globl	OPENSSL_rdtsc
.type	OPENSSL_rdtsc,\\@abi-omnipotent
.align	16
OPENSSL_rdtsc:
.cfi_startproc
	endbranch
	rdtsc
	shl	\\$32,%rdx
	or	%rdx,%rax
	ret
.cfi_endproc
.size	OPENSSL_rdtsc,.-OPENSSL_rdtsc

.globl	OPENSSL_ia32_cpuid
.type	OPENSSL_ia32_cpuid,\\@function,1
.align	16
OPENSSL_ia32_cpuid:
.cfi_startproc
	endbranch
	mov	%rbx,%r8
.cfi_register	%rbx,%r8

	xor	%eax,%eax
	mov	%rax,8(%rdi)
	cpuid
	mov	%eax,%r11d

	xor	%eax,%eax
	cmp	\\$0x756e6547,%ebx
	setne	%al
	mov	%eax,%r9d
	cmp	\\$0x49656e69,%edx
	setne	%al
	or	%eax,%r9d
	cmp	\\$0x6c65746e,%ecx
	setne	%al
	or	%eax,%r9d
	jz	.Lintel

	cmp	\\$0x68747541,%ebx
	setne	%al
	mov	%eax,%r10d
	cmp	\\$0x69746E65,%edx
	setne	%al
	or	%eax,%r10d
	cmp	\\$0x444D4163,%ecx
	setne	%al
	or	%eax,%r10d
	jnz	.Lintel

	mov	\\$0x80000000,%eax
	cpuid
	cmp	\\$0x80000001,%eax
	jb	.Lintel
	mov	%eax,%r10d
	mov	\\$0x80000001,%eax
	cpuid
	or	%ecx,%r9d
	and	\\$0x00000801,%r9d

	cmp	\\$0x80000008,%r10d
	jb	.Lintel

	mov	\\$0x80000008,%eax
	cpuid
	movzb	%cl,%r10
	inc	%r10

	mov	\\$1,%eax
	cpuid
	bt	\\$28,%edx
	jnc	.Lgeneric
	shr	\\$16,%ebx
	cmp	%r10b,%bl
	ja	.Lgeneric
	and	\\$0xefffffff,%edx
	jmp	.Lgeneric

.Lintel:
	cmp	\\$4,%r11d
	mov	\\$-1,%r10d
	jb	.Lnocacheinfo

	mov	\\$4,%eax
	mov	\\$0,%ecx
	cpuid
	mov	%eax,%r10d
	shr	\\$14,%r10d
	and	\\$0xfff,%r10d

.Lnocacheinfo:
	mov	\\$1,%eax
	cpuid
	movd	%eax,%xmm0
	and	\\$0xbfefffff,%edx
	cmp	\\$0,%r9d
	jne	.Lnotintel
	or	\\$0x40000000,%edx
	and	\\$15,%ah
	cmp	\\$15,%ah
	jne	.LnotP4
	or	\\$0x00100000,%edx
.LnotP4:
	cmp	\\$6,%ah
	jne	.Lnotintel
	and	\\$0x0fff0ff0,%eax
	cmp	\\$0x00050670,%eax
	je	.Lknights
	cmp	\\$0x00080650,%eax
	jne	.Lnotintel
.Lknights:
	and	\\$0xfbffffff,%ecx

.Lnotintel:
	bt	\\$28,%edx
	jnc	.Lgeneric
	and	\\$0xefffffff,%edx
	cmp	\\$0,%r10d
	je	.Lgeneric

	or	\\$0x10000000,%edx
	shr	\\$16,%ebx
	cmp	\\$1,%bl
	ja	.Lgeneric
	and	\\$0xefffffff,%edx
.Lgeneric:
	and	\\$0x00000800,%r9d
	and	\\$0xfffff7ff,%ecx
	or	%ecx,%r9d

	mov	%edx,%r10d

	cmp	\\$7,%r11d
	jb	.Lno_extended_info
	mov	\\$7,%eax
	xor	%ecx,%ecx
	cpuid
	movd	%eax,%xmm1
	bt	\\$26,%r9d
	jc	.Lnotknights
	and	\\$0xfff7ffff,%ebx
.Lnotknights:
	movd	%xmm0,%eax
	and	\\$0x0fff0ff0,%eax
	cmp	\\$0x00050650,%eax
	jne	.Lnotskylakex
	and	\\$0xfffeffff,%ebx

.Lnotskylakex:
	mov	%ebx,8(%rdi)
	mov	%ecx,12(%rdi)
	mov	%edx,16(%rdi)

	movd	%xmm1,%eax
	cmp	\\$0x1,%eax
	jb .Lno_extended_info
	mov	\\$0x7,%eax
	mov \\$0x1,%ecx
	cpuid
	mov	%eax,20(%rdi)
	mov	%edx,24(%rdi)
	mov	%ebx,28(%rdi)
	mov	%ecx,32(%rdi)

	and \\$0x80000,%edx
	cmp \\$0x0,%edx
	je .Lno_extended_info
	mov	\\$0x24,%eax
	mov \\$0x0,%ecx
	cpuid
	mov	%ebx,36(%rdi)

.Lno_extended_info:

	bt	\\$27,%r9d
	jnc	.Lclear_avx
	xor	%ecx,%ecx
	.byte	0x0f,0x01,0xd0
	and	\\$0xe6,%eax
	cmp	\\$0xe6,%eax
	je	.Ldone
	andl	\\$0x3fdeffff,8(%rdi)
	and	\\$6,%eax
	cmp	\\$6,%eax
	je	.Ldone
.Lclear_avx:
	andl	\\$0xff7fffff,20(%rdi)
	mov	\\$0xefffe7ff,%eax
	and	%eax,%r9d
	mov	\\$0x3fdeffdf,%eax
	and	%eax,8(%rdi)
.Ldone:
	shl	\\$32,%r9
	mov	%r10d,%eax
	mov	%r8,%rbx
.cfi_restore	%rbx
	or	%r9,%rax
	ret
.cfi_endproc
.size	OPENSSL_ia32_cpuid,.-OPENSSL_ia32_cpuid

.globl  OPENSSL_cleanse
.type   OPENSSL_cleanse,\\@abi-omnipotent
.align  16
OPENSSL_cleanse:
.cfi_startproc
	endbranch
	xor	%rax,%rax
	cmp	\\$15,${arg2}
	jae	.Lot
	cmp	\\$0,${arg2}
	je	.Lret
.Little:
	mov	%al,(${arg1})
	sub	\\$1,${arg2}
	lea	1(${arg1}),${arg1}
	jnz	.Little
.Lret:
	ret
.align	16
.Lot:
	test	\\$7,${arg1}
	jz	.Laligned
	mov	%al,(${arg1})
	lea	-1(${arg2}),${arg2}
	lea	1(${arg1}),${arg1}
	jmp	.Lot
.Laligned:
	mov	%rax,(${arg1})
	lea	-8(${arg2}),${arg2}
	test	\\$-8,${arg2}
	lea	8(${arg1}),${arg1}
	jnz	.Laligned
	cmp	\\$0,${arg2}
	jne	.Little
	ret
.cfi_endproc
.size	OPENSSL_cleanse,.-OPENSSL_cleanse

.globl  CRYPTO_memcmp
.type   CRYPTO_memcmp,\\@abi-omnipotent
.align  16
CRYPTO_memcmp:
.cfi_startproc
	endbranch
	xor	%rax,%rax
	xor	%r10,%r10
	cmp	\\$0,${arg3}
	je	.Lno_data
	cmp	\\$16,${arg3}
	jne	.Loop_cmp
	mov	(${arg1}),%r10
	mov	8(${arg1}),%r11
	mov	\\$1,${arg3}
	xor	(${arg2}),%r10
	xor	8(${arg2}),%r11
	or	%r11,%r10
	cmovnz	${arg3},%rax
	ret

.align	16
.Loop_cmp:
	mov	(${arg1}),%r10b
	lea	1(${arg1}),${arg1}
	xor	(${arg2}),%r10b
	lea	1(${arg2}),${arg2}
	or	%r10b,%al
	dec	${arg3}
	jnz	.Loop_cmp
	neg	%rax
	shr	\\$63,%rax
.Lno_data:
	ret
.cfi_endproc
.size	CRYPTO_memcmp,.-CRYPTO_memcmp

.globl	OPENSSL_instrument_bus
.type	OPENSSL_instrument_bus,\\@abi-omnipotent
.align	16
OPENSSL_instrument_bus:
.cfi_startproc
	endbranch
	mov	${arg1},${out}
	mov	${arg2},${cnt}
	mov	${arg2},${max}

	rdtsc
	mov	%eax,${lasttick}
	mov	\\$0,${lastdiff}
	clflush	(${out})
	.byte	0xf0
	add	${lastdiff},(${out})
	jmp	.Loop
.align	16
.Loop:	rdtsc
	mov	%eax,%edx
	sub	${lasttick},%eax
	mov	%edx,${lasttick}
	mov	%eax,${lastdiff}
	clflush	(${out})
	.byte	0xf0
	add	%eax,(${out})
	lea	4(${out}),${out}
	sub	\\$1,${cnt}
	jnz	.Loop

	mov	${max},%rax
	ret
.cfi_endproc
.size	OPENSSL_instrument_bus,.-OPENSSL_instrument_bus

.globl	OPENSSL_instrument_bus2
.type	OPENSSL_instrument_bus2,\\@abi-omnipotent
.align	16
OPENSSL_instrument_bus2:
.cfi_startproc
	endbranch
	mov	${arg1},${out}
	mov	${arg2},${cnt}
	mov	${arg3},${max}
	mov	${cnt},${redzone}(%rsp)

	rdtsc
	mov	%eax,${lasttick}
	mov	\\$0,${lastdiff}

	clflush	(${out})
	.byte	0xf0
	add	${lastdiff},(${out})

	rdtsc
	mov	%eax,%edx
	sub	${lasttick},%eax
	mov	%edx,${lasttick}
	mov	%eax,${lastdiff}
.Loop2:
	clflush	(${out})
	.byte	0xf0
	add	%eax,(${out})

	sub	\\$1,${max}
	jz	.Ldone2

	rdtsc
	mov	%eax,%edx
	sub	${lasttick},%eax
	mov	%edx,${lasttick}
	cmp	${lastdiff},%eax
	mov	%eax,${lastdiff}
	mov	\\$0,%edx
	setne	%dl
	sub	%rdx,${cnt}
	lea	(${out},%rdx,4),${out}
	jnz	.Loop2

.Ldone2:
	mov	${redzone}(%rsp),%rax
	sub	${cnt},%rax
	ret
.cfi_endproc
.size	OPENSSL_instrument_bus2,.-OPENSSL_instrument_bus2

${genRandom('rdrand')}

${genRandom('rdseed')}
`;
}
export default generateAssembly();
