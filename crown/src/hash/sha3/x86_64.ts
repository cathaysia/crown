/**
 * Keccak-1600 absorb and squeeze for x86_64.
 *
 * TypeScript port of OpenSSL crypto/sha/asm/keccak1600-x86_64.pl.
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

// @A[i][j] = offsets into the state, biased by -100 (size optimization)
const A: number[][] = [0, 5, 10, 15, 20].map(r =>
  [0, 1, 2, 3, 4].map(c => 8 * (r + c) - 100),
);

let C = ['%rax', '%rbx', '%rcx', '%rdx', '%rbp'];
let D = ['%r8', '%r9', '%r10', '%r11', '%r12'];
const T = ['%r13', '%r14'];
const iotas = '%r15';

const rhotates = [
  [0, 1, 62, 28, 27],
  [36, 44, 6, 55, 20],
  [3, 10, 43, 25, 39],
  [41, 45, 15, 21, 8],
  [18, 2, 61, 56, 14],
];

let code = '';

code += `.text

.type	__KeccakF1600,@abi-omnipotent
.align	32
__KeccakF1600:
.cfi_startproc
	mov	${A[4][0]}(%rdi),${C[0]}
	mov	${A[4][1]}(%rdi),${C[1]}
	mov	${A[4][2]}(%rdi),${C[2]}
	mov	${A[4][3]}(%rdi),${C[3]}
	mov	${A[4][4]}(%rdi),${C[4]}
	jmp	.Loop

.align	32
.Loop:
	mov	${A[0][0]}(%rdi),${D[0]}
	mov	${A[1][1]}(%rdi),${D[1]}
	mov	${A[2][2]}(%rdi),${D[2]}
	mov	${A[3][3]}(%rdi),${D[3]}

	xor	${A[0][2]}(%rdi),${C[2]}
	xor	${A[0][3]}(%rdi),${C[3]}
	xor	${D[0]},         ${C[0]}
	xor	${A[0][1]}(%rdi),${C[1]}
	 xor	${A[1][2]}(%rdi),${C[2]}
	 xor	${A[1][0]}(%rdi),${C[0]}
	mov	${C[4]},${D[4]}
	xor	${A[0][4]}(%rdi),${C[4]}

	xor	${D[2]},         ${C[2]}
	xor	${A[2][0]}(%rdi),${C[0]}
	 xor	${A[1][3]}(%rdi),${C[3]}
	 xor	${D[1]},         ${C[1]}
	 xor	${A[1][4]}(%rdi),${C[4]}

	xor	${A[3][2]}(%rdi),${C[2]}
	xor	${A[3][0]}(%rdi),${C[0]}
	 xor	${A[2][3]}(%rdi),${C[3]}
	 xor	${A[2][1]}(%rdi),${C[1]}
	 xor	${A[2][4]}(%rdi),${C[4]}

	mov	${C[2]},${T[0]}
	rol	$1,${C[2]}
	xor	${C[0]},${C[2]}		# D[1] = ROL64(C[2], 1) ^ C[0]
	 xor	${D[3]},         ${C[3]}

	rol	$1,${C[0]}
	xor	${C[3]},${C[0]}		# D[4] = ROL64(C[0], 1) ^ C[3]
	 xor	${A[3][1]}(%rdi),${C[1]}

	rol	$1,${C[3]}
	xor	${C[1]},${C[3]}		# D[2] = ROL64(C[3], 1) ^ C[1]
	 xor	${A[3][4]}(%rdi),${C[4]}

	rol	$1,${C[1]}
	xor	${C[4]},${C[1]}		# D[0] = ROL64(C[1], 1) ^ C[4]

	rol	$1,${C[4]}
	xor	${T[0]},${C[4]}		# D[3] = ROL64(C[4], 1) ^ C[2]
`;
// perl: (@D[0..4], @C) = (@C[1..4,0], @D);
// the right-hand list is evaluated first, so @C receives the old @D
{
  const oldD = D;
  D = [C[1], C[2], C[3], C[4], C[0]];
  C = oldD;
}
code += `	xor	${D[1]},${C[1]}
	xor	${D[2]},${C[2]}
	rol	$${rhotates[1][1]},${C[1]}
	xor	${D[3]},${C[3]}
	xor	${D[4]},${C[4]}
	rol	$${rhotates[2][2]},${C[2]}
	xor	${D[0]},${C[0]}
	 mov	${C[1]},${T[0]}
	rol	$${rhotates[3][3]},${C[3]}
	 or	${C[2]},${C[1]}
	 xor	${C[0]},${C[1]}		#           C[0] ^ ( C[1] | C[2])
	rol	$${rhotates[4][4]},${C[4]}

	 xor	(${iotas}),${C[1]}
	 lea	8(${iotas}),${iotas}

	mov	${C[4]},${T[1]}
	and	${C[3]},${C[4]}
	 mov	${C[1]},${A[0][0]}(%rsi)	# R[0][0] = C[0] ^ ( C[1] | C[2]) ^ iotas[i]
	xor	${C[2]},${C[4]}		#           C[2] ^ ( C[4] & C[3])
	not	${C[2]}
	mov	${C[4]},${A[0][2]}(%rsi)	# R[0][2] = C[2] ^ ( C[4] & C[3])

	or	${C[3]},${C[2]}
	  mov	${A[4][2]}(%rdi),${C[4]}
	xor	${T[0]},${C[2]}		#           C[1] ^ (~C[2] | C[3])
	mov	${C[2]},${A[0][1]}(%rsi)	# R[0][1] = C[1] ^ (~C[2] | C[3])

	and	${C[0]},${T[0]}
	  mov	${A[1][4]}(%rdi),${C[1]}
	xor	${T[1]},${T[0]}		#           C[4] ^ ( C[1] & C[0])
	  mov	${A[2][0]}(%rdi),${C[2]}
	mov	${T[0]},${A[0][4]}(%rsi)	# R[0][4] = C[4] ^ ( C[1] & C[0])

	or	${C[0]},${T[1]}
	  mov	${A[0][3]}(%rdi),${C[0]}
	xor	${C[3]},${T[1]}		#           C[3] ^ ( C[4] | C[0])
	  mov	${A[3][1]}(%rdi),${C[3]}
	mov	${T[1]},${A[0][3]}(%rsi)	# R[0][3] = C[3] ^ ( C[4] | C[0])


	xor	${D[3]},${C[0]}
	xor	${D[2]},${C[4]}
	rol	$${rhotates[0][3]},${C[0]}
	xor	${D[1]},${C[3]}
	xor	${D[4]},${C[1]}
	rol	$${rhotates[4][2]},${C[4]}
	rol	$${rhotates[3][1]},${C[3]}
	xor	${D[0]},${C[2]}
	rol	$${rhotates[1][4]},${C[1]}
	 mov	${C[0]},${T[0]}
	 or	${C[4]},${C[0]}
	rol	$${rhotates[2][0]},${C[2]}

	xor	${C[3]},${C[0]}		#           C[3] ^ (C[0] |  C[4])
	mov	${C[0]},${A[1][3]}(%rsi)	# R[1][3] = C[3] ^ (C[0] |  C[4])

	mov	${C[1]},${T[1]}
	and	${T[0]},${C[1]}
	  mov	${A[0][1]}(%rdi),${C[0]}
	xor	${C[4]},${C[1]}		#           C[4] ^ (C[1] &  C[0])
	not	${C[4]}
	mov	${C[1]},${A[1][4]}(%rsi)	# R[1][4] = C[4] ^ (C[1] &  C[0])

	or	${C[3]},${C[4]}
	  mov	${A[1][2]}(%rdi),${C[1]}
	xor	${C[2]},${C[4]}		#           C[2] ^ (~C[4] | C[3])
	mov	${C[4]},${A[1][2]}(%rsi)	# R[1][2] = C[2] ^ (~C[4] | C[3])

	and	${C[2]},${C[3]}
	  mov	${A[4][0]}(%rdi),${C[4]}
	xor	${T[1]},${C[3]}		#           C[1] ^ (C[3] &  C[2])
	mov	${C[3]},${A[1][1]}(%rsi)	# R[1][1] = C[1] ^ (C[3] &  C[2])

	or	${C[2]},${T[1]}
	  mov	${A[2][3]}(%rdi),${C[2]}
	xor	${T[0]},${T[1]}		#           C[0] ^ (C[1] |  C[2])
	  mov	${A[3][4]}(%rdi),${C[3]}
	mov	${T[1]},${A[1][0]}(%rsi)	# R[1][0] = C[0] ^ (C[1] |  C[2])


	xor	${D[3]},${C[2]}
	xor	${D[4]},${C[3]}
	rol	$${rhotates[2][3]},${C[2]}
	xor	${D[2]},${C[1]}
	rol	$${rhotates[3][4]},${C[3]}
	xor	${D[0]},${C[4]}
	rol	$${rhotates[1][2]},${C[1]}
	xor	${D[1]},${C[0]}
	rol	$${rhotates[4][0]},${C[4]}
	 mov	${C[2]},${T[0]}
	 and	${C[3]},${C[2]}
	rol	$${rhotates[0][1]},${C[0]}

	not	${C[3]}
	xor	${C[1]},${C[2]}		#            C[1] ^ ( C[2] & C[3])
	mov	${C[2]},${A[2][1]}(%rsi)	# R[2][1] =  C[1] ^ ( C[2] & C[3])

	mov	${C[4]},${T[1]}
	and	${C[3]},${C[4]}
	  mov	${A[2][1]}(%rdi),${C[2]}
	xor	${T[0]},${C[4]}		#            C[2] ^ ( C[4] & ~C[3])
	mov	${C[4]},${A[2][2]}(%rsi)	# R[2][2] =  C[2] ^ ( C[4] & ~C[3])

	or	${C[1]},${T[0]}
	  mov	${A[4][3]}(%rdi),${C[4]}
	xor	${C[0]},${T[0]}		#            C[0] ^ ( C[2] | C[1])
	mov	${T[0]},${A[2][0]}(%rsi)	# R[2][0] =  C[0] ^ ( C[2] | C[1])

	and	${C[0]},${C[1]}
	xor	${T[1]},${C[1]}		#            C[4] ^ ( C[1] & C[0])
	mov	${C[1]},${A[2][4]}(%rsi)	# R[2][4] =  C[4] ^ ( C[1] & C[0])

	or	${C[0]},${T[1]}
	  mov	${A[1][0]}(%rdi),${C[1]}
	xor	${C[3]},${T[1]}		#           ~C[3] ^ ( C[0] | C[4])
	  mov	${A[3][2]}(%rdi),${C[3]}
	mov	${T[1]},${A[2][3]}(%rsi)	# R[2][3] = ~C[3] ^ ( C[0] | C[4])


	mov	${A[0][4]}(%rdi),${C[0]}

	xor	${D[1]},${C[2]}
	xor	${D[2]},${C[3]}
	rol	$${rhotates[2][1]},${C[2]}
	xor	${D[0]},${C[1]}
	rol	$${rhotates[3][2]},${C[3]}
	xor	${D[3]},${C[4]}
	rol	$${rhotates[1][0]},${C[1]}
	xor	${D[4]},${C[0]}
	rol	$${rhotates[4][3]},${C[4]}
	 mov	${C[2]},${T[0]}
	 or	${C[3]},${C[2]}
	rol	$${rhotates[0][4]},${C[0]}

	not	${C[3]}
	xor	${C[1]},${C[2]}		#            C[1] ^ ( C[2] | C[3])
	mov	${C[2]},${A[3][1]}(%rsi)	# R[3][1] =  C[1] ^ ( C[2] | C[3])

	mov	${C[4]},${T[1]}
	or	${C[3]},${C[4]}
	xor	${T[0]},${C[4]}		#            C[2] ^ ( C[4] | ~C[3])
	mov	${C[4]},${A[3][2]}(%rsi)	# R[3][2] =  C[2] ^ ( C[4] | ~C[3])

	and	${C[1]},${T[0]}
	xor	${C[0]},${T[0]}		#            C[0] ^ ( C[2] & C[1])
	mov	${T[0]},${A[3][0]}(%rsi)	# R[3][0] =  C[0] ^ ( C[2] & C[1])

	or	${C[0]},${C[1]}
	xor	${T[1]},${C[1]}		#            C[4] ^ ( C[1] | C[0])
	mov	${C[1]},${A[3][4]}(%rsi)	# R[3][4] =  C[4] ^ ( C[1] | C[0])

	and	${T[1]},${C[0]}
	xor	${C[3]},${C[0]}		#           ~C[3] ^ ( C[0] & C[4])
	mov	${C[0]},${A[3][3]}(%rsi)	# R[3][3] = ~C[3] ^ ( C[0] & C[4])


	xor	${A[0][2]}(%rdi),${D[2]}
	xor	${A[1][3]}(%rdi),${D[3]}
	rol	$${rhotates[0][2]},${D[2]}
	xor	${A[4][1]}(%rdi),${D[1]}
	rol	$${rhotates[1][3]},${D[3]}
	xor	${A[2][4]}(%rdi),${D[4]}
	rol	$${rhotates[4][1]},${D[1]}
	xor	${A[3][0]}(%rdi),${D[0]}
	xchg	%rsi,%rdi
	rol	$${rhotates[2][4]},${D[4]}
	rol	$${rhotates[3][0]},${D[0]}
`;
// perl: @C = @D[2..4,0,1];
C = [D[2], D[3], D[4], D[0], D[1]];
code += `	mov	${C[0]},${T[0]}
	and	${C[1]},${C[0]}
	not	${C[1]}
	xor	${C[4]},${C[0]}		#            C[4] ^ ( C[0] & C[1])
	mov	${C[0]},${A[4][4]}(%rdi)	# R[4][4] =  C[4] ^ ( C[0] & C[1])

	mov	${C[2]},${T[1]}
	and	${C[1]},${C[2]}
	xor	${T[0]},${C[2]}		#            C[0] ^ ( C[2] & ~C[1])
	mov	${C[2]},${A[4][0]}(%rdi)	# R[4][0] =  C[0] ^ ( C[2] & ~C[1])

	or	${C[4]},${T[0]}
	xor	${C[3]},${T[0]}		#            C[3] ^ ( C[0] | C[4])
	mov	${T[0]},${A[4][3]}(%rdi)	# R[4][3] =  C[3] ^ ( C[0] | C[4])

	and	${C[3]},${C[4]}
	xor	${T[1]},${C[4]}		#            C[2] ^ ( C[4] & C[3])
	mov	${C[4]},${A[4][2]}(%rdi)	# R[4][2] =  C[2] ^ ( C[4] & C[3])

	or	${T[1]},${C[3]}
	xor	${C[1]},${C[3]}		#           ~C[1] ^ ( C[2] | C[3])
	mov	${C[3]},${A[4][1]}(%rdi)	# R[4][1] = ~C[1] ^ ( C[2] | C[3])

	mov	${C[0]},${C[1]}		# harmonize with the loop top
	mov	${T[0]},${C[0]}

	test	$255,${iotas}
	jnz	.Loop

	lea	-192(${iotas}),${iotas}	# rewind iotas
	ret
.cfi_endproc
.size	__KeccakF1600,.-__KeccakF1600

.type	KeccakF1600,@abi-omnipotent
.align	32
KeccakF1600:
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

	lea	100(%rdi),%rdi		# size optimization
	sub	$200,%rsp
.cfi_adjust_cfa_offset	200

	notq	${A[0][1]}(%rdi)
	notq	${A[0][2]}(%rdi)
	notq	${A[1][3]}(%rdi)
	notq	${A[2][2]}(%rdi)
	notq	${A[3][2]}(%rdi)
	notq	${A[4][0]}(%rdi)

	lea	iotas(%rip),${iotas}
	lea	100(%rsp),%rsi		# size optimization

	call	__KeccakF1600

	notq	${A[0][1]}(%rdi)
	notq	${A[0][2]}(%rdi)
	notq	${A[1][3]}(%rdi)
	notq	${A[2][2]}(%rdi)
	notq	${A[3][2]}(%rdi)
	notq	${A[4][0]}(%rdi)
	lea	-100(%rdi),%rdi		# preserve A[][]

	add	$200,%rsp
.cfi_adjust_cfa_offset	-200

	pop	%r15
.cfi_pop	%r15
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
	pop	%rbp
.cfi_pop	%rbp
	pop	%rbx
.cfi_pop	%rbx
	ret
.cfi_endproc
.size	KeccakF1600,.-KeccakF1600
`;

{
  // my ($A_flat,$inp,$len,$bsz) = (rdi,rsi,rdx,rcx); ($A_flat,$inp) = (r8,r9);
  const A_flat = '%r8';
  const inp = '%r9';
  const len = '%rdx';
  const bsz = '%rcx';

  code += `.globl	SHA3_absorb
.type	SHA3_absorb,@function,4
.align	32
SHA3_absorb:
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

	lea	100(%rdi),%rdi		# size optimization
	sub	$232,%rsp
.cfi_adjust_cfa_offset	232

	mov	%rsi,${inp}
	lea	100(%rsp),%rsi		# size optimization

	notq	${A[0][1]}(%rdi)
	notq	${A[0][2]}(%rdi)
	notq	${A[1][3]}(%rdi)
	notq	${A[2][2]}(%rdi)
	notq	${A[3][2]}(%rdi)
	notq	${A[4][0]}(%rdi)
	lea	iotas(%rip),${iotas}

	mov	${bsz},216-100(%rsi)	# save bsz

.Loop_absorb:
	cmp	${bsz},${len}
	jc	.Ldone_absorb

	shr	$3,${bsz}
	lea	-100(%rdi),${A_flat}

.Lblock_absorb:
	mov	(${inp}),%rax
	lea	8(${inp}),${inp}
	xor	(${A_flat}),%rax
	lea	8(${A_flat}),${A_flat}
	sub	$8,${len}
	mov	%rax,-8(${A_flat})
	sub	$1,${bsz}
	jnz	.Lblock_absorb

	mov	${inp},200-100(%rsi)	# save inp
	mov	${len},208-100(%rsi)	# save len
	call	__KeccakF1600
	mov	200-100(%rsi),${inp}	# pull inp
	mov	208-100(%rsi),${len}	# pull len
	mov	216-100(%rsi),${bsz}	# pull bsz
	jmp	.Loop_absorb

.align	32
.Ldone_absorb:
	mov	${len},%rax		# return value

	notq	${A[0][1]}(%rdi)
	notq	${A[0][2]}(%rdi)
	notq	${A[1][3]}(%rdi)
	notq	${A[2][2]}(%rdi)
	notq	${A[3][2]}(%rdi)
	notq	${A[4][0]}(%rdi)

	add	$232,%rsp
.cfi_adjust_cfa_offset	-232

	pop	%r15
.cfi_pop	%r15
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
	pop	%rbp
.cfi_pop	%rbp
	pop	%rbx
.cfi_pop	%rbx
	ret
.cfi_endproc
.size	SHA3_absorb,.-SHA3_absorb
`;
}

{
  // my ($A_flat,$out,$len,$bsz,$next) = (rdi,rsi,rdx,rcx,r8);
  // ($out,$len,$bsz) = (r12,r13,r14);
  const A_flat = '%rdi';
  const out = '%r12';
  const len = '%r13';
  const bsz = '%r14';
  const next = '%r8';

  code += `.globl	SHA3_squeeze
.type	SHA3_squeeze,@function,5
.align	32
SHA3_squeeze:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14

	shr	$3,%rcx
	mov	${A_flat},%r9
	mov	%rsi,${out}
	mov	%rdx,${len}
	mov	%rcx,${bsz}
	bt	$0,${next}d
	jc	.Lnext_block
	jmp	.Loop_squeeze

.align	32
.Loop_squeeze:
	cmp	$8,${len}
	jb	.Ltail_squeeze

	mov	(%r9),%rax
	lea	8(%r9),%r9
	mov	%rax,(${out})
	lea	8(${out}),${out}
	sub	$8,${len}		# len -= 8
	jz	.Ldone_squeeze

	sub	$1,%rcx		# bsz--
	jnz	.Loop_squeeze
.Lnext_block:
	call	KeccakF1600
	mov	${A_flat},%r9
	mov	${bsz},%rcx
	jmp	.Loop_squeeze

.Ltail_squeeze:
	mov	%r9, %rsi
	mov	${out},%rdi
	mov	${len},%rcx
	.byte	0xf3,0xa4		# rep	movsb

.Ldone_squeeze:
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r13
	ret
.cfi_endproc
.size	SHA3_squeeze,.-SHA3_squeeze
`;
}

code += `.section .rodata align=256
.align	256
	.quad	0,0,0,0,0,0,0,0
.type	iotas,@object
iotas:
	.quad	0x0000000000000001
	.quad	0x0000000000008082
	.quad	0x800000000000808a
	.quad	0x8000000080008000
	.quad	0x000000000000808b
	.quad	0x0000000080000001
	.quad	0x8000000080008081
	.quad	0x8000000000008009
	.quad	0x000000000000008a
	.quad	0x0000000000000088
	.quad	0x0000000080008009
	.quad	0x000000008000000a
	.quad	0x000000008000808b
	.quad	0x800000000000008b
	.quad	0x8000000000008089
	.quad	0x8000000000008003
	.quad	0x8000000000008002
	.quad	0x8000000000000080
	.quad	0x000000000000800a
	.quad	0x800000008000000a
	.quad	0x8000000080008081
	.quad	0x8000000000008080
	.quad	0x0000000080000001
	.quad	0x8000000080008008
.size	iotas,.-iotas
.asciz	"Keccak-1600 absorb and squeeze for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
`;

export default translateAssembly(code);
