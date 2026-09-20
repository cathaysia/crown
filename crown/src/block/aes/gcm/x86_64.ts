/**
 * GHASH for x86_64.
 *
 * TypeScript port of OpenSSL crypto/modes/asm/ghash-x86_64.pl.
 * Copyright 2010-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $do4xaggr=1, $avx=0 (the perl
 * script auto-detects the assembler; without $ENV{CC} the avx functions
 * become stubs jumping to their clmul counterparts).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// common register layout
const nlo = '%rax';
const nhi = '%rbx';
const Zlo = '%r8';
const Zhi = '%r9';
const tmp = '%r10';
const rem_4bit = '%r11';

const Xi = '%rdi';
const Htbl = '%rsi';

// per-function register layout
const cnt = '%rcx';
const rem = '%rdx';

function isNumericLiteral(arg: string): boolean {
  return /^-?[0-9]+$/.test(arg);
}

function AUTOLOAD(opcode: string, ...args: string[]): void {
  let arg = args.pop() as string;
  if (isNumericLiteral(arg)) {
    arg = '$' + arg;
  }
  const rest = [...args].reverse();
  code += `\t${opcode}\t${[arg, ...rest].join(',')}\n`;
}

function LB(r: string): string {
  let out = r.replace(/%[er]([a-d])x/, '%$1l');
  if (out === r) out = r.replace(/%[er]([sd]i)/, '%$1l');
  if (out === r) out = r.replace(/%[er](bp)/, '%$1l');
  if (out === r) out = r.replace(/%(r[0-9]+)[d]?/, '%$1b');
  return out;
}

let N = 0;
function loop(inp: string): void {
  N++;
  code += `	xor	${nlo},${nlo}
	xor	${nhi},${nhi}
	mov	${LB(Zlo)},${LB(nlo)}
	mov	${LB(Zlo)},${LB(nhi)}
	shl	$4,${LB(nlo)}
	mov	$14,${cnt}
	mov	8(${Htbl},${nlo}),${Zlo}
	mov	(${Htbl},${nlo}),${Zhi}
	and	$0xf0,${LB(nhi)}
	mov	${Zlo},${rem}
	jmp	.Loop${N}

.align	16
.Loop${N}:
	shr	$4,${Zlo}
	and	$0xf,${rem}
	mov	${Zhi},${tmp}
	mov	(${inp},${cnt}),${LB(nlo)}
	shr	$4,${Zhi}
	xor	8(${Htbl},${nhi}),${Zlo}
	shl	$60,${tmp}
	xor	(${Htbl},${nhi}),${Zhi}
	mov	${LB(nlo)},${LB(nhi)}
	xor	(${rem_4bit},${rem},8),${Zhi}
	mov	${Zlo},${rem}
	shl	$4,${LB(nlo)}
	xor	${tmp},${Zlo}
	dec	${cnt}
	js	.Lbreak${N}

	shr	$4,${Zlo}
	and	$0xf,${rem}
	mov	${Zhi},${tmp}
	shr	$4,${Zhi}
	xor	8(${Htbl},${nlo}),${Zlo}
	shl	$60,${tmp}
	xor	(${Htbl},${nlo}),${Zhi}
	and	$0xf0,${LB(nhi)}
	xor	(${rem_4bit},${rem},8),${Zhi}
	mov	${Zlo},${rem}
	xor	${tmp},${Zlo}
	jmp	.Loop${N}

.align	16
.Lbreak${N}:
	shr	$4,${Zlo}
	and	$0xf,${rem}
	mov	${Zhi},${tmp}
	shr	$4,${Zhi}
	xor	8(${Htbl},${nlo}),${Zlo}
	shl	$60,${tmp}
	xor	(${Htbl},${nlo}),${Zhi}
	and	$0xf0,${LB(nhi)}
	xor	(${rem_4bit},${rem},8),${Zhi}
	mov	${Zlo},${rem}
	xor	${tmp},${Zlo}

	shr	$4,${Zlo}
	and	$0xf,${rem}
	mov	${Zhi},${tmp}
	shr	$4,${Zhi}
	xor	8(${Htbl},${nhi}),${Zlo}
	shl	$60,${tmp}
	xor	(${Htbl},${nhi}),${Zhi}
	xor	${tmp},${Zlo}
	xor	(${rem_4bit},${rem},8),${Zhi}

	bswap	${Zlo}
	bswap	${Zhi}
`;
}

function genGmult4bit(): void {
  code += `.text
.extern	OPENSSL_ia32cap_P

.globl	gcm_gmult_4bit
.type	gcm_gmult_4bit,@function,2
.align	16
gcm_gmult_4bit:
.cfi_startproc
	endbranch
	push	%rbx
.cfi_push	%rbx
	push	%rbp		# %rbp and others are pushed exclusively in
.cfi_push	%rbp
	push	%r12		# order to reuse Win64 exception handler...
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	$280,%rsp
.cfi_adjust_cfa_offset	280
.Lgmult_prologue:

	movzb	15(${Xi}),${Zlo}
	lea	.Lrem_4bit(%rip),${rem_4bit}
`;
  loop(Xi);
  code += `	mov	${Zlo},8(${Xi})
	mov	${Zhi},(${Xi})

	lea	280+48(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lgmult_epilogue:
	ret
.cfi_endproc
.size	gcm_gmult_4bit,.-gcm_gmult_4bit
`;
}

function genGhash4bit(): void {
  // per-function register layout
  const ginp = '%rdx';
  const glen = '%rcx';
  const rem_8bit = rem_4bit;

  code += `.globl	gcm_ghash_4bit
.type	gcm_ghash_4bit,@function,4
.align	16
gcm_ghash_4bit:
.cfi_startproc
	endbranch
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
	sub	$280,%rsp
.cfi_adjust_cfa_offset	280
.Lghash_prologue:
	mov	${ginp},%r14		# reassign couple of args
	mov	${glen},%r15
`;

  // block-scoped registers (perl: my ...)
  const inp = '%r14';
  const dat = '%edx';
  const len = '%r15';
  let nhiRegs = ['%ebx', '%ecx'];
  let remRegs = ['%r12', '%r13'];
  const Hshr4 = '%rbp';

  AUTOLOAD('sub', Htbl, '-128'); // size optimization
  AUTOLOAD('lea', Hshr4, '16+128(%rsp)');
  {
    let lo = [nlo, nhi];
    const hi = [Zlo, Zhi];

    AUTOLOAD('xor', dat, dat);
    let j = -2;
    for (let i = 0; i < 18; i++, j++) {
      if (i > 1) {
        AUTOLOAD('mov', `${j}(%rsp)`, LB(dat));
      }
      if (i > 1) {
        AUTOLOAD('or', lo[0], tmp);
      }
      if (i > 0 && i < 17) {
        AUTOLOAD('mov', LB(dat), LB(lo[1]));
      }
      if (i > 0 && i < 17) {
        AUTOLOAD('shr', lo[1], '4');
      }
      if (i > 0 && i < 17) {
        AUTOLOAD('mov', tmp, hi[1]);
      }
      if (i > 0 && i < 17) {
        AUTOLOAD('shr', hi[1], '4');
      }
      if (i > 1) {
        AUTOLOAD('mov', `8*${j}(${Hshr4})`, hi[0]);
      }
      if (i < 16) {
        AUTOLOAD('mov', hi[0], `16*${i}+0-128(${Htbl})`);
      }
      if (i > 0 && i < 17) {
        AUTOLOAD('shl', LB(dat), '4');
      }
      if (i > 1) {
        AUTOLOAD('mov', `8*${j}-128(${Hshr4})`, lo[0]);
      }
      if (i < 16) {
        AUTOLOAD('mov', lo[0], `16*${i}+8-128(${Htbl})`);
      }
      if (i > 0 && i < 17) {
        AUTOLOAD('shl', tmp, '60');
      }

      lo.push(lo.shift() as string);
      hi.push(hi.shift() as string);
    }
  }
  AUTOLOAD('add', Htbl, '-128');
  AUTOLOAD('mov', Zlo, `8(${Xi})`);
  AUTOLOAD('mov', Zhi, `0(${Xi})`);
  AUTOLOAD('add', len, inp); // pointer to the end of data
  AUTOLOAD('lea', rem_8bit, '.Lrem_8bit(%rip)');
  AUTOLOAD('jmp', '.Louter_loop');

  code += '.align	16\n.Louter_loop:\n';
  AUTOLOAD('xor', Zhi, `(${inp})`);
  AUTOLOAD('mov', '%rdx', `8(${inp})`);
  AUTOLOAD('lea', inp, `16(${inp})`);
  AUTOLOAD('xor', '%rdx', Zlo);
  AUTOLOAD('mov', `(${Xi})`, Zhi);
  AUTOLOAD('mov', `8(${Xi})`, '%rdx');
  AUTOLOAD('shr', '%rdx', '32');

  AUTOLOAD('xor', nlo, nlo);
  AUTOLOAD('rol', dat, '8');
  AUTOLOAD('mov', LB(nlo), LB(dat));
  AUTOLOAD('movz', nhiRegs[0], LB(dat));
  AUTOLOAD('shl', LB(nlo), '4');
  AUTOLOAD('shr', nhiRegs[0], '4');

  let j = 11;
  for (let i = 0; i < 15; i++) {
    AUTOLOAD('rol', dat, '8');
    if (i > 0) {
      AUTOLOAD('xor', Zlo, `8(${Htbl},${nlo})`);
    }
    if (i > 0) {
      AUTOLOAD('xor', Zhi, `(${Htbl},${nlo})`);
    }
    if (i === 0) {
      AUTOLOAD('mov', Zlo, `8(${Htbl},${nlo})`);
    }
    if (i === 0) {
      AUTOLOAD('mov', Zhi, `(${Htbl},${nlo})`);
    }

    AUTOLOAD('mov', LB(nlo), LB(dat));
    if (i > 0) {
      AUTOLOAD('xor', Zlo, tmp);
    }
    if (i > 0) {
      AUTOLOAD('movzw', remRegs[1], `(${rem_8bit},${remRegs[1]},2)`);
    }

    AUTOLOAD('movz', nhiRegs[1], LB(dat));
    AUTOLOAD('shl', LB(nlo), '4');
    AUTOLOAD('movzb', remRegs[0], `(%rsp,${nhiRegs[0]})`);

    if (i < 14) {
      AUTOLOAD('shr', nhiRegs[1], '4');
    }
    if (i === 14) {
      // perl source uses the hex literal 0xf0, i.e. the number 240
      AUTOLOAD('and', nhiRegs[1], '240');
    }
    if (i > 0) {
      AUTOLOAD('shl', remRegs[1], '48');
    }
    AUTOLOAD('xor', remRegs[0], Zlo);

    AUTOLOAD('mov', tmp, Zhi);
    if (i > 0) {
      AUTOLOAD('xor', Zhi, remRegs[1]);
    }
    AUTOLOAD('shr', Zlo, '8');

    AUTOLOAD('movz', remRegs[0], LB(remRegs[0]));
    j--;
    if (j % 4 === 0) {
      AUTOLOAD('mov', dat, `${j}(${Xi})`);
    }
    AUTOLOAD('shr', Zhi, '8');

    AUTOLOAD('xor', Zlo, `-128(${Hshr4},${nhiRegs[0]},8)`);
    AUTOLOAD('shl', tmp, '56');
    AUTOLOAD('xor', Zhi, `(${Hshr4},${nhiRegs[0]},8)`);

    nhiRegs.unshift(nhiRegs.pop() as string); // "rotate" registers
    remRegs.unshift(remRegs.pop() as string);
  }
  AUTOLOAD('movzw', remRegs[1], `(${rem_8bit},${remRegs[1]},2)`);
  AUTOLOAD('xor', Zlo, `8(${Htbl},${nlo})`);
  AUTOLOAD('xor', Zhi, `(${Htbl},${nlo})`);

  AUTOLOAD('shl', remRegs[1], '48');
  AUTOLOAD('xor', Zlo, tmp);

  AUTOLOAD('xor', Zhi, remRegs[1]);
  AUTOLOAD('movz', remRegs[0], LB(Zlo));
  AUTOLOAD('shr', Zlo, '4');

  AUTOLOAD('mov', tmp, Zhi);
  AUTOLOAD('shl', LB(remRegs[0]), '4');
  AUTOLOAD('shr', Zhi, '4');

  AUTOLOAD('xor', Zlo, `8(${Htbl},${nhiRegs[0]})`);
  AUTOLOAD('movzw', remRegs[0], `(${rem_8bit},${remRegs[0]},2)`);
  AUTOLOAD('shl', tmp, '60');

  AUTOLOAD('xor', Zhi, `(${Htbl},${nhiRegs[0]})`);
  AUTOLOAD('xor', Zlo, tmp);
  AUTOLOAD('shl', remRegs[0], '48');

  AUTOLOAD('bswap', Zlo);
  AUTOLOAD('xor', Zhi, remRegs[0]);

  AUTOLOAD('bswap', Zhi);
  AUTOLOAD('cmp', inp, len);
  AUTOLOAD('jb', '.Louter_loop');

  code += `	mov	${Zlo},8(${Xi})
	mov	${Zhi},(${Xi})

	lea	280+48(%rsp),%rsi
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
	lea	0(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lghash_epilogue:
	ret
.cfi_endproc
.size	gcm_ghash_4bit,.-gcm_ghash_4bit
`;
}

// ---------------------------------------------------------------------------
// PCLMULQDQ version.
// ---------------------------------------------------------------------------
// Unix order argument registers
const _4args = ['%rdi', '%rsi', '%rdx', '%rcx'];

// file-scope xmm registers
const Xireg = '%xmm0';
const Xhireg = '%xmm1';
const Hkeyreg = '%xmm2';
const T1reg = '%xmm3';
const T2reg = '%xmm4';
const T3reg = '%xmm5';

function clmul64x64_T2(
  xhi: string,
  xi: string,
  hkey: string,
  hk?: string,
): void {
  if (hk === undefined) {
    hk = T2reg;
    code += `	movdqa		${xi},${xhi}		#
	pshufd		$0b01001110,${xi},${T1reg}
	pshufd		$0b01001110,${hkey},${T2reg}
	pxor		${xi},${T1reg}			#
	pxor		${hkey},${T2reg}
`;
  } else {
    code += `	movdqa		${xi},${xhi}		#
	pshufd		$0b01001110,${xi},${T1reg}
	pxor		${xi},${T1reg}			#
`;
  }
  code += `	pclmulqdq	$0x00,${hkey},${xi}	#######
	pclmulqdq	$0x11,${hkey},${xhi}	#######
	pclmulqdq	$0x00,${hk},${T1reg}		#######
	pxor		${xi},${T1reg}			#
	pxor		${xhi},${T1reg}		#

	movdqa		${T1reg},${T2reg}			#
	psrldq		$8,${T1reg}
	pslldq		$8,${T2reg}			#
	pxor		${T1reg},${xhi}
	pxor		${T2reg},${xi}			#
`;
}

function reduction_alg9(xhi: string, xi: string): void {
  code += `	# 1st phase
	movdqa		${xi},${T2reg}			#
	movdqa		${xi},${T1reg}
	psllq		$5,${xi}
	pxor		${xi},${T1reg}			#
	psllq		$1,${xi}
	pxor		${T1reg},${xi}			#
	psllq		$57,${xi}		#
	movdqa		${xi},${T1reg}			#
	pslldq		$8,${xi}
	psrldq		$8,${T1reg}			#
	pxor		${T2reg},${xi}
	pxor		${T1reg},${xhi}		#

	# 2nd phase
	movdqa		${xi},${T2reg}
	psrlq		$1,${xi}
	pxor		${T2reg},${xhi}		#
	pxor		${xi},${T2reg}
	psrlq		$5,${xi}
	pxor		${T2reg},${xi}			#
	psrlq		$1,${xi}			#
	pxor		${xhi},${xi}		#
`;
}

function genInitClmul(): void {
  // my ($Htbl,$Xip)=@_4args;
  const cHtbl = _4args[0];
  const cXip = _4args[1];
  const HK = '%xmm6';

  code += `.globl	gcm_init_clmul
.type	gcm_init_clmul,@abi-omnipotent
.align	16
gcm_init_clmul:
.cfi_startproc
	endbranch
.L_init_clmul:
	movdqu		(${cXip}),${Hkeyreg}
	pshufd		$0b01001110,${Hkeyreg},${Hkeyreg}	# dword swap

	# <<1 twist
	pshufd		$0b11111111,${Hkeyreg},${T2reg}	# broadcast uppermost dword
	movdqa		${Hkeyreg},${T1reg}
	psllq		$1,${Hkeyreg}
	pxor		${T3reg},${T3reg}			#
	psrlq		$63,${T1reg}
	pcmpgtd		${T2reg},${T3reg}			# broadcast carry bit
	pslldq		$8,${T1reg}
	por		${T1reg},${Hkeyreg}		# H<<=1

	# magic reduction
	pand		.L0x1c2_polynomial(%rip),${T3reg}
	pxor		${T3reg},${Hkeyreg}		# if(carry) H^=0x1c2_polynomial

	# calculate H^2
	pshufd		$0b01001110,${Hkeyreg},${HK}
	movdqa		${Hkeyreg},${Xireg}
	pxor		${Hkeyreg},${HK}
`;
  clmul64x64_T2(Xhireg, Xireg, Hkeyreg, HK);
  reduction_alg9(Xhireg, Xireg);
  code += `	pshufd		$0b01001110,${Hkeyreg},${T1reg}
	pshufd		$0b01001110,${Xireg},${T2reg}
	pxor		${Hkeyreg},${T1reg}		# Karatsuba pre-processing
	movdqu		${Hkeyreg},0x00(${cHtbl})	# save H
	pxor		${Xireg},${T2reg}			# Karatsuba pre-processing
	movdqu		${Xireg},0x10(${cHtbl})		# save H^2
	palignr		$8,${T1reg},${T2reg}		# low part is H.lo^H.hi...
	movdqu		${T2reg},0x20(${cHtbl})		# save Karatsuba "salt"
`;
  {
    clmul64x64_T2(Xhireg, Xireg, Hkeyreg, HK); // H^3
    reduction_alg9(Xhireg, Xireg);
    code += `	movdqa		${Xireg},${T3reg}
`;
    clmul64x64_T2(Xhireg, Xireg, Hkeyreg, HK); // H^4
    reduction_alg9(Xhireg, Xireg);
    code += `	pshufd		$0b01001110,${T3reg},${T1reg}
	pshufd		$0b01001110,${Xireg},${T2reg}
	pxor		${T3reg},${T1reg}			# Karatsuba pre-processing
	movdqu		${T3reg},0x30(${cHtbl})		# save H^3
	pxor		${Xireg},${T2reg}			# Karatsuba pre-processing
	movdqu		${Xireg},0x40(${cHtbl})		# save H^4
	palignr		$8,${T1reg},${T2reg}		# low part is H^3.lo^H^3.hi...
	movdqu		${T2reg},0x50(${cHtbl})		# save Karatsuba "salt"
`;
  }
  code += `	ret
.cfi_endproc
.size	gcm_init_clmul,.-gcm_init_clmul
`;
}

function genGmultClmul(): void {
  // my ($Xip,$Htbl)=@_4args;
  const cXip = _4args[0];
  const cHtbl = _4args[1];

  code += `.globl	gcm_gmult_clmul
.type	gcm_gmult_clmul,@abi-omnipotent
.align	16
gcm_gmult_clmul:
.cfi_startproc
	endbranch
.L_gmult_clmul:
	movdqu		(${cXip}),${Xireg}
	movdqa		.Lbswap_mask(%rip),${T3reg}
	movdqu		(${cHtbl}),${Hkeyreg}
	movdqu		0x20(${cHtbl}),${T2reg}
	pshufb		${T3reg},${Xireg}
`;
  clmul64x64_T2(Xhireg, Xireg, Hkeyreg, T2reg);
  // The perl evaluates reduction_alg9 inside a false condition in order to
  // append it while skipping the experimental alternative heredoc.
  reduction_alg9(Xhireg, Xireg);
  code += `	pshufb		${T3reg},${Xireg}
	movdqu		${Xireg},(${cXip})
	ret
.cfi_endproc
.size	gcm_gmult_clmul,.-gcm_gmult_clmul
`;
}

function genGhashClmul(): void {
  // my ($Xip,$Htbl,$inp,$len)=@_4args;
  const cXip = _4args[0];
  const cHtbl = _4args[1];
  const cinp = _4args[2];
  const clen = _4args[3];
  // block-scoped registers
  const Xln = '%xmm3';
  const Xmn = '%xmm4';
  const Xhn = '%xmm5';
  const Hkey2 = '%xmm6';
  const HK = '%xmm7';
  const T1 = '%xmm8';
  const T2 = '%xmm9';
  const T3 = '%xmm10';

  code += `.globl	gcm_ghash_clmul
.type	gcm_ghash_clmul,@abi-omnipotent
.align	32
gcm_ghash_clmul:
.cfi_startproc
	endbranch
.L_ghash_clmul:
	movdqa		.Lbswap_mask(%rip),${T3}

	movdqu		(${cXip}),${Xireg}
	movdqu		(${cHtbl}),${Hkeyreg}
	movdqu		0x20(${cHtbl}),${HK}
	pshufb		${T3},${Xireg}

	sub		$0x10,${clen}
	jz		.Lodd_tail

	movdqu		0x10(${cHtbl}),${Hkey2}
`;
  {
    // do4xaggr
    const Xl = '%xmm11';
    const Xm = '%xmm12';
    const Xh = '%xmm13';
    const Hkey3 = '%xmm14';
    const Hkey4 = '%xmm15';

    code += `	mov		OPENSSL_ia32cap_P+4(%rip),%eax
	cmp		$0x30,${clen}
	jb		.Lskip4x

	and		$${(1 << 26) | (1 << 22)},%eax	# isolate MOVBE+XSAVE
	cmp		$${1 << 22},%eax		# check for MOVBE without XSAVE
	je		.Lskip4x

	sub		$0x30,${clen}
	mov		$0xA040608020C0E000,%rax	# ((7..0)·0xE0)&0xff
	movdqu		0x30(${cHtbl}),${Hkey3}
	movdqu		0x40(${cHtbl}),${Hkey4}

	#######
	# Xi+4 =[(H*Ii+3) + (H^2*Ii+2) + (H^3*Ii+1) + H^4*(Ii+Xi)] mod P
	#
	movdqu		0x30(${cinp}),${Xln}
	 movdqu		0x20(${cinp}),${Xl}
	pshufb		${T3},${Xln}
	 pshufb		${T3},${Xl}
	movdqa		${Xln},${Xhn}
	pshufd		$0b01001110,${Xln},${Xmn}
	pxor		${Xln},${Xmn}
	pclmulqdq	$0x00,${Hkeyreg},${Xln}
	pclmulqdq	$0x11,${Hkeyreg},${Xhn}
	pclmulqdq	$0x00,${HK},${Xmn}

	movdqa		${Xl},${Xh}
	pshufd		$0b01001110,${Xl},${Xm}
	pxor		${Xl},${Xm}
	pclmulqdq	$0x00,${Hkey2},${Xl}
	pclmulqdq	$0x11,${Hkey2},${Xh}
	pclmulqdq	$0x10,${HK},${Xm}
	xorps		${Xl},${Xln}
	xorps		${Xh},${Xhn}
	movups		0x50(${cHtbl}),${HK}
	xorps		${Xm},${Xmn}

	movdqu		0x10(${cinp}),${Xl}
	 movdqu		0(${cinp}),${T1}
	pshufb		${T3},${Xl}
	 pshufb		${T3},${T1}
	movdqa		${Xl},${Xh}
	pshufd		$0b01001110,${Xl},${Xm}
	 pxor		${T1},${Xireg}
	pxor		${Xl},${Xm}
	pclmulqdq	$0x00,${Hkey3},${Xl}
	 movdqa		${Xireg},${Xhireg}
	 pshufd		$0b01001110,${Xireg},${T1}
	 pxor		${Xireg},${T1}
	pclmulqdq	$0x11,${Hkey3},${Xh}
	pclmulqdq	$0x00,${HK},${Xm}
	xorps		${Xl},${Xln}
	xorps		${Xh},${Xhn}

	lea	0x40(${cinp}),${cinp}
	sub	$0x40,${clen}
	jc	.Ltail4x

	jmp	.Lmod4_loop
.align	32
.Lmod4_loop:
	pclmulqdq	$0x00,${Hkey4},${Xireg}
	xorps		${Xm},${Xmn}
	 movdqu		0x30(${cinp}),${Xl}
	 pshufb		${T3},${Xl}
	pclmulqdq	$0x11,${Hkey4},${Xhireg}
	xorps		${Xln},${Xireg}
	 movdqu		0x20(${cinp}),${Xln}
	 movdqa		${Xl},${Xh}
	pclmulqdq	$0x10,${HK},${T1}
	 pshufd		$0b01001110,${Xl},${Xm}
	xorps		${Xhn},${Xhireg}
	 pxor		${Xl},${Xm}
	 pshufb		${T3},${Xln}
	movups		0x20(${cHtbl}),${HK}
	xorps		${Xmn},${T1}
	 pclmulqdq	$0x00,${Hkeyreg},${Xl}
	 pshufd		$0b01001110,${Xln},${Xmn}

	pxor		${Xireg},${T1}			# aggregated Karatsuba post-processing
	 movdqa		${Xln},${Xhn}
	pxor		${Xhireg},${T1}		#
	 pxor		${Xln},${Xmn}
	movdqa		${T1},${T2}			#
	 pclmulqdq	$0x11,${Hkeyreg},${Xh}
	pslldq		$8,${T1}
	psrldq		$8,${T2}			#
	pxor		${T1},${Xireg}
	movdqa		.L7_mask(%rip),${T1}
	pxor		${T2},${Xhireg}		#
	movq		%rax,${T2}

	pand		${Xireg},${T1}			# 1st phase
	pshufb		${T1},${T2}			#
	pxor		${Xireg},${T2}			#
	 pclmulqdq	$0x00,${HK},${Xm}
	psllq		$57,${T2}		#
	movdqa		${T2},${T1}			#
	pslldq		$8,${T2}
	 pclmulqdq	$0x00,${Hkey2},${Xln}
	psrldq		$8,${T1}			#
	pxor		${T2},${Xireg}
	pxor		${T1},${Xhireg}		#
	movdqu		0(${cinp}),${T1}

	movdqa		${Xireg},${T2}			# 2nd phase
	psrlq		$1,${Xireg}
	 pclmulqdq	$0x11,${Hkey2},${Xhn}
	 xorps		${Xl},${Xln}
	 movdqu		0x10(${cinp}),${Xl}
	 pshufb		${T3},${Xl}
	 pclmulqdq	$0x10,${HK},${Xmn}
	 xorps		${Xh},${Xhn}
	 movups		0x50(${cHtbl}),${HK}
	pshufb		${T3},${T1}
	pxor		${T2},${Xhireg}		#
	pxor		${Xireg},${T2}
	psrlq		$5,${Xireg}

	 movdqa		${Xl},${Xh}
	 pxor		${Xm},${Xmn}
	 pshufd		$0b01001110,${Xl},${Xm}
	pxor		${T2},${Xireg}			#
	pxor		${T1},${Xhireg}
	 pxor		${Xl},${Xm}
	 pclmulqdq	$0x00,${Hkey3},${Xl}
	psrlq		$1,${Xireg}			#
	pxor		${Xhireg},${Xireg}		#
	movdqa		${Xireg},${Xhireg}
	 pclmulqdq	$0x11,${Hkey3},${Xh}
	 xorps		${Xl},${Xln}
	pshufd		$0b01001110,${Xireg},${T1}
	pxor		${Xireg},${T1}

	 pclmulqdq	$0x00,${HK},${Xm}
	 xorps		${Xh},${Xhn}

	lea	0x40(${cinp}),${cinp}
	sub	$0x40,${clen}
	jnc	.Lmod4_loop

.Ltail4x:
	pclmulqdq	$0x00,${Hkey4},${Xireg}
	pclmulqdq	$0x11,${Hkey4},${Xhireg}
	pclmulqdq	$0x10,${HK},${T1}
	xorps		${Xm},${Xmn}
	xorps		${Xln},${Xireg}
	xorps		${Xhn},${Xhireg}
	pxor		${Xireg},${Xhireg}		# aggregated Karatsuba post-processing
	pxor		${Xmn},${T1}

	pxor		${Xhireg},${T1}		#
	pxor		${Xireg},${Xhireg}

	movdqa		${T1},${T2}			#
	psrldq		$8,${T1}
	pslldq		$8,${T2}			#
	pxor		${T1},${Xhireg}
	pxor		${T2},${Xireg}			#
`;
    reduction_alg9(Xhireg, Xireg);
    code += `	add	$0x40,${clen}
	jz	.Ldone
	movdqu	0x20(${cHtbl}),${HK}
	sub	$0x10,${clen}
	jz	.Lodd_tail
.Lskip4x:
`;
  }
  code += `	#######
	# Xi+2 =[H*(Ii+1 + Xi+1)] mod P =
	#	[(H*Ii+1) + (H*Xi+1)] mod P =
	#	[(H*Ii+1) + H^2*(Ii+Xi)] mod P
	#
	movdqu		(${cinp}),${T1}		# Ii
	movdqu		16(${cinp}),${Xln}		# Ii+1
	pshufb		${T3},${T1}
	pshufb		${T3},${Xln}
	pxor		${T1},${Xireg}			# Ii+Xi

	movdqa		${Xln},${Xhn}
	pshufd		$0b01001110,${Xln},${Xmn}
	pxor		${Xln},${Xmn}
	pclmulqdq	$0x00,${Hkeyreg},${Xln}
	pclmulqdq	$0x11,${Hkeyreg},${Xhn}
	pclmulqdq	$0x00,${HK},${Xmn}

	lea		32(${cinp}),${cinp}		# i+=2
	nop
	sub		$0x20,${clen}
	jbe		.Leven_tail
	nop
	jmp		.Lmod_loop

.align	32
.Lmod_loop:
	movdqa		${Xireg},${Xhireg}
	movdqa		${Xmn},${T1}
	pshufd		$0b01001110,${Xireg},${Xmn}	#
	pxor		${Xireg},${Xmn}		#

	pclmulqdq	$0x00,${Hkey2},${Xireg}
	pclmulqdq	$0x11,${Hkey2},${Xhireg}
	pclmulqdq	$0x10,${HK},${Xmn}

	pxor		${Xln},${Xireg}		# (H*Ii+1) + H^2*(Ii+Xi)
	pxor		${Xhn},${Xhireg}
	  movdqu	(${cinp}),${T2}		# Ii
	pxor		${Xireg},${T1}			# aggregated Karatsuba post-processing
	  pshufb	${T3},${T2}
	  movdqu	16(${cinp}),${Xln}		# Ii+1

	pxor		${Xhireg},${T1}
	  pxor		${T2},${Xhireg}		# "Ii+Xi", consume early
	pxor		${T1},${Xmn}
	 pshufb		${T3},${Xln}
	movdqa		${Xmn},${T1}		#
	psrldq		$8,${T1}
	pslldq		$8,${Xmn}		#
	pxor		${T1},${Xhireg}
	pxor		${Xmn},${Xireg}		#

	movdqa		${Xln},${Xhn}		#

	  movdqa	${Xireg},${T2}			# 1st phase
	  movdqa	${Xireg},${T1}
	  psllq		$5,${Xireg}
	  pxor		${Xireg},${T1}			#
	pclmulqdq	$0x00,${Hkeyreg},${Xln}	#######
	  psllq		$1,${Xireg}
	  pxor		${T1},${Xireg}			#
	  psllq		$57,${Xireg}		#
	  movdqa	${Xireg},${T1}			#
	  pslldq	$8,${Xireg}
	  psrldq	$8,${T1}			#
	  pxor		${T2},${Xireg}
	pshufd		$0b01001110,${Xhn},${Xmn}
	  pxor		${T1},${Xhireg}		#
	pxor		${Xhn},${Xmn}		#

	  movdqa	${Xireg},${T2}			# 2nd phase
	  psrlq		$1,${Xireg}
	pclmulqdq	$0x11,${Hkeyreg},${Xhn}	#######
	  pxor		${T2},${Xhireg}		#
	  pxor		${Xireg},${T2}
	  psrlq		$5,${Xireg}
	  pxor		${T2},${Xireg}			#
	lea		32(${cinp}),${cinp}
	  psrlq		$1,${Xireg}			#
	pclmulqdq	$0x00,${HK},${Xmn}		#######
	  pxor		${Xhireg},${Xireg}		#

	sub		$0x20,${clen}
	ja		.Lmod_loop

.Leven_tail:
	 movdqa		${Xireg},${Xhireg}
	 movdqa		${Xmn},${T1}
	 pshufd		$0b01001110,${Xireg},${Xmn}	#
	 pxor		${Xireg},${Xmn}		#

	pclmulqdq	$0x00,${Hkey2},${Xireg}
	pclmulqdq	$0x11,${Hkey2},${Xhireg}
	pclmulqdq	$0x10,${HK},${Xmn}

	pxor		${Xln},${Xireg}		# (H*Ii+1) + H^2*(Ii+Xi)
	pxor		${Xhn},${Xhireg}
	pxor		${Xireg},${T1}
	pxor		${Xhireg},${T1}
	pxor		${T1},${Xmn}
	movdqa		${Xmn},${T1}		#
	psrldq		$8,${T1}
	pslldq		$8,${Xmn}		#
	pxor		${T1},${Xhireg}
	pxor		${Xmn},${Xireg}		#
`;
  reduction_alg9(Xhireg, Xireg);
  code += `	test		${clen},${clen}
	jnz		.Ldone

.Lodd_tail:
	movdqu		(${cinp}),${T1}		# Ii
	pshufb		${T3},${T1}
	pxor		${T1},${Xireg}			# Ii+Xi
`;
  clmul64x64_T2(Xhireg, Xireg, Hkeyreg, HK); // H*(Ii+Xi)
  reduction_alg9(Xhireg, Xireg);
  code += `.Ldone:
	pshufb		${T3},${Xireg}
	movdqu		${Xireg},(${cXip})
	ret
.cfi_endproc
.size	gcm_ghash_clmul,.-gcm_ghash_clmul
`;
}

function genAvxStubs(): void {
  code += `.globl	gcm_init_avx
.type	gcm_init_avx,@abi-omnipotent
.align	32
gcm_init_avx:
.cfi_startproc
	endbranch
	jmp	.L_init_clmul
.cfi_endproc
.size	gcm_init_avx,.-gcm_init_avx
`;

  code += `.globl	gcm_gmult_avx
.type	gcm_gmult_avx,@abi-omnipotent
.align	32
gcm_gmult_avx:
.cfi_startproc
	endbranch
	jmp	.L_gmult_clmul
.cfi_endproc
.size	gcm_gmult_avx,.-gcm_gmult_avx
`;

  code += `.globl	gcm_ghash_avx
.type	gcm_ghash_avx,@abi-omnipotent
.align	32
gcm_ghash_avx:
.cfi_startproc
	endbranch
	jmp	.L_ghash_clmul
.cfi_endproc
.size	gcm_ghash_avx,.-gcm_ghash_avx
`;
}

function genData(): void {
  code += `.section .rodata align=64
.align	64
.Lbswap_mask:
	.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
.L0x1c2_polynomial:
	.byte	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xc2
.L7_mask:
	.long	7,0,7,0
.L7_mask_poly:
	.long	7,0,${0xe1 << 1},0
.align	64
.type	.Lrem_4bit,@object
.Lrem_4bit:
	.long	0,${0x0000 << 16},0,${0x1c20 * 65536},0,${0x3840 * 65536},0,${0x2460 * 65536}
	.long	0,${0x7080 * 65536},0,${0x6ca0 * 65536},0,${0x48c0 * 65536},0,${0x54e0 * 65536}
	.long	0,${0xe100 * 65536},0,${0xfd20 * 65536},0,${0xd940 * 65536},0,${0xc560 * 65536}
	.long	0,${0x9180 * 65536},0,${0x8da0 * 65536},0,${0xa9c0 * 65536},0,${0xb5e0 * 65536}
.type	.Lrem_8bit,@object
.Lrem_8bit:
	.value	0x0000,0x01C2,0x0384,0x0246,0x0708,0x06CA,0x048C,0x054E
	.value	0x0E10,0x0FD2,0x0D94,0x0C56,0x0918,0x08DA,0x0A9C,0x0B5E
	.value	0x1C20,0x1DE2,0x1FA4,0x1E66,0x1B28,0x1AEA,0x18AC,0x196E
	.value	0x1230,0x13F2,0x11B4,0x1076,0x1538,0x14FA,0x16BC,0x177E
	.value	0x3840,0x3982,0x3BC4,0x3A06,0x3F48,0x3E8A,0x3CCC,0x3D0E
	.value	0x3650,0x3792,0x35D4,0x3416,0x3158,0x309A,0x32DC,0x331E
	.value	0x2460,0x25A2,0x27E4,0x2626,0x2368,0x22AA,0x20EC,0x212E
	.value	0x2A70,0x2BB2,0x29F4,0x2836,0x2D78,0x2CBA,0x2EFC,0x2F3E
	.value	0x7080,0x7142,0x7304,0x72C6,0x7788,0x764A,0x740C,0x75CE
	.value	0x7E90,0x7F52,0x7D14,0x7CD6,0x7998,0x785A,0x7A1C,0x7BDE
	.value	0x6CA0,0x6D62,0x6F24,0x6EE6,0x6BA8,0x6A6A,0x682C,0x69EE
	.value	0x62B0,0x6372,0x6134,0x60F6,0x65B8,0x647A,0x663C,0x67FE
	.value	0x48C0,0x4902,0x4B44,0x4A86,0x4FC8,0x4E0A,0x4C4C,0x4D8E
	.value	0x46D0,0x4712,0x4554,0x4496,0x41D8,0x401A,0x425C,0x439E
	.value	0x54E0,0x5522,0x5764,0x56A6,0x53E8,0x522A,0x506C,0x51AE
	.value	0x5AF0,0x5B32,0x5974,0x58B6,0x5DF8,0x5C3A,0x5E7C,0x5FBE
	.value	0xE100,0xE0C2,0xE284,0xE346,0xE608,0xE7CA,0xE58C,0xE44E
	.value	0xEF10,0xEED2,0xEC94,0xED56,0xE818,0xE9DA,0xEB9C,0xEA5E
	.value	0xFD20,0xFCE2,0xFEA4,0xFF66,0xFA28,0xFBEA,0xF9AC,0xF86E
	.value	0xF330,0xF2F2,0xF0B4,0xF176,0xF438,0xF5FA,0xF7BC,0xF67E
	.value	0xD940,0xD882,0xDAC4,0xDB06,0xDE48,0xDF8A,0xDDCC,0xDC0E
	.value	0xD750,0xD692,0xD4D4,0xD516,0xD058,0xD19A,0xD3DC,0xD21E
	.value	0xC560,0xC4A2,0xC6E4,0xC726,0xC268,0xC3AA,0xC1EC,0xC02E
	.value	0xCB70,0xCAB2,0xC8F4,0xC936,0xCC78,0xCDBA,0xCFFC,0xCE3E
	.value	0x9180,0x9042,0x9204,0x93C6,0x9688,0x974A,0x950C,0x94CE
	.value	0x9F90,0x9E52,0x9C14,0x9DD6,0x9898,0x995A,0x9B1C,0x9ADE
	.value	0x8DA0,0x8C62,0x8E24,0x8FE6,0x8AA8,0x8B6A,0x892C,0x88EE
	.value	0x83B0,0x8272,0x8034,0x81F6,0x84B8,0x857A,0x873C,0x86FE
	.value	0xA9C0,0xA802,0xAA44,0xAB86,0xAEC8,0xAF0A,0xAD4C,0xAC8E
	.value	0xA7D0,0xA612,0xA454,0xA596,0xA0D8,0xA11A,0xA35C,0xA29E
	.value	0xB5E0,0xB422,0xB664,0xB7A6,0xB2E8,0xB32A,0xB16C,0xB0AE
	.value	0xBBF0,0xBA32,0xB874,0xB9B6,0xBCF8,0xBD3A,0xBF7C,0xBEBE

.asciz	"GHASH for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.align	64
.previous
`;
}

genGmult4bit();
genGhash4bit();
genInitClmul();
genGmultClmul();
genGhashClmul();
genAvxStubs();
genData();

export default translateAssembly(code);
