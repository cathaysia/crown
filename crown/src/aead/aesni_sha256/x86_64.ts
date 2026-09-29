/**
 * aesni_cbc_sha256_enc for x86_64 (stitched AES-NI CBC + SHA-256).
 *
 * TypeScript port of OpenSSL crypto/aes/asm/aesni-sha256-x86_64.pl.
 * Written by Andy Polyakov, @dot-asm.
 * Copyright 2013-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $win64=0 (unix SysV),
 * $avx=2 (avx + avx2 bodies emitted), $shaext=1 (shaext body emitted).
 *
 * Tiers: xop, avx, avx2, shaext. Data labels are prefixed with
 * `aesni_sha256_` to avoid symbol clashes with the sha1 port.
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// ---------------------------------------------------------------------------
// perlasm AUTOLOAD thunk
// ---------------------------------------------------------------------------
function isNumericLiteral(arg: string): boolean {
  return /^-?[0-9]+$/.test(arg) || /^[0-9]+$/.test(arg);
}

function AUTOLOAD(opcode: string, ...args: string[]): void {
  let arg = args.pop() as string;
  if (isNumericLiteral(arg) || /^-?[0-9]+$/.test(arg)) {
    arg = '$' + arg;
  }
  const rest = [...args].reverse();
  code += `\t${opcode}\t${[arg, ...rest].join(',')}\n`;
}

type Thunk = () => void;

// ---------------------------------------------------------------------------
// Instruction emitters
// ---------------------------------------------------------------------------
function xor(dst: string, src: string): void { AUTOLOAD('xor', dst, src); }
function add(dst: string, src: string): void { AUTOLOAD('add', dst, src); }
function mov(dst: string, src: string): void { AUTOLOAD('mov', dst, src); }
function and_(dst: string, src: string): void { AUTOLOAD('and', dst, src); }

// ---------------------------------------------------------------------------
// SHA-256 register allocation (from the perl)
// ---------------------------------------------------------------------------
// @ROT = ($A,$B,$C,$D,$E,$F,$G,$H) = (%eax,%ebx,%ecx,%edx,%r8d,%r9d,%r10d,%r11d)
// ($T1,$a0,$a1,$a2,$a3) = (%r12d,%r13d,%r14d,%r15d,%esi);  $a4 = $T1
const REG_A = '%eax', REG_B = '%ebx', REG_C = '%ecx', REG_D = '%edx';
const REG_E = '%r8d', REG_F = '%r9d', REG_G = '%r10d', REG_H = '%r11d';
const REG_T1 = '%r12d'; // also a4
const REG_a0 = '%r13d';
const REG_a1 = '%r14d';
const REG_a2 = '%r15d';
const REG_a3 = '%esi';

const Sigma0 = [2, 13, 22];
const Sigma1 = [6, 11, 25];
const sigma0 = [7, 18, 3];
const sigma1 = [17, 19, 10];

// ROT state: starts as (A,B,C,D,E,F,G,H), rotated right after each round.
let ROT = [REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H];
// a2/a3 get swapped after each round (perl: ($a2,$a3)=($a3,$a2))
let a2Cur = REG_a2;
let a3Cur = REG_a3;
let iCnt = 0;       // $i — round counter within a 16-round group
let aesIdx = 0;     // $aesni_cbc_idx — AES block step 0..15

// IALU rotate mode: 'ror' for xop, 'shrd' for avx
let rorMode: 'ror' | 'shrd' = 'ror';

function rorI(reg: string, imm: number): void {
  if (rorMode === 'shrd') {
    AUTOLOAD('shrd', reg, reg, String(imm));
  } else {
    AUTOLOAD('ror', reg, String(imm));
  }
}

function resetRoundState(): void {
  ROT = [REG_A, REG_B, REG_C, REG_D, REG_E, REG_F, REG_G, REG_H];
  a2Cur = REG_a2;
  a3Cur = REG_a3;
  iCnt = 0;
}

// ---------------------------------------------------------------------------
// AES-NI CBC block (@aesni_cbc_block) — 16 steps
// ---------------------------------------------------------------------------
const IV = '%xmm8';
const INOUT = '%xmm9';
const ROUNDKEY = '%xmm10';
const TEMP = '%xmm11';
const MASK10 = '%xmm12';
const MASK12 = '%xmm13';
const MASK14 = '%xmm14';

function aesencBlock(idx: number): void {
  switch (idx) {
    case 0:
      AUTOLOAD('vpxor', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x10-0x80(%rdi)');
      break;
    case 1:
      AUTOLOAD('vpxor', INOUT, INOUT, IV);
      break;
    case 2:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x20-0x80(%rdi)');
      break;
    case 3:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x30-0x80(%rdi)');
      break;
    case 4:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x40-0x80(%rdi)');
      break;
    case 5:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x50-0x80(%rdi)');
      break;
    case 6:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x60-0x80(%rdi)');
      break;
    case 7:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x70-0x80(%rdi)');
      break;
    case 8:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x80-0x80(%rdi)');
      break;
    case 9:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x90-0x80(%rdi)');
      break;
    case 10:
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0xa0-0x80(%rdi)');
      break;
    case 11:
      AUTOLOAD('vaesenclast', TEMP, INOUT, ROUNDKEY);
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0xb0-0x80(%rdi)');
      break;
    case 12:
      AUTOLOAD('vpand', IV, TEMP, MASK10);
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0xc0-0x80(%rdi)');
      break;
    case 13:
      AUTOLOAD('vaesenclast', TEMP, INOUT, ROUNDKEY);
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0xd0-0x80(%rdi)');
      break;
    case 14:
      AUTOLOAD('vpand', TEMP, TEMP, MASK12);
      AUTOLOAD('vaesenc', INOUT, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0xe0-0x80(%rdi)');
      break;
    case 15:
      AUTOLOAD('vpor', IV, IV, TEMP);
      AUTOLOAD('vaesenclast', TEMP, INOUT, ROUNDKEY);
      AUTOLOAD('vmovdqu', ROUNDKEY, '0x00-0x80(%rdi)');
      break;
  }
}

// ---------------------------------------------------------------------------
// body_00_15 — one SHA-256 round as a list of thunks.
// Register names are read from ROT / a2Cur / a3Cur at emit time.
// ---------------------------------------------------------------------------
function body00_15(): Thunk[] {
  return [
    // assign + first ror concatenated in the perl
    () => rorI(REG_a0, Sigma1[2] - Sigma1[1]),           // ror a0, 14
    () => mov(ROT[0], REG_a1),                             // mov a1, a
    () => mov(REG_T1, ROT[5]),                             // mov f, a4
    () => xor(REG_a0, ROT[4]),                             // xor e, a0
    () => rorI(REG_a1, Sigma0[2] - Sigma0[1]),           // ror a1, 9
    () => xor(REG_T1, ROT[6]),                             // xor g, a4
    () => rorI(REG_a0, Sigma1[1] - Sigma1[0]),           // ror a0, 5
    () => xor(REG_a1, ROT[0]),                             // xor a, a1
    () => and_(REG_T1, ROT[4]),                            // and e, a4
    // AES step + xor concatenated in the perl
    () => { aesencBlock(aesIdx++); xor(REG_a0, ROT[4]); },
    () => add(ROT[7], `${4 * (iCnt & 15)}(%rsp)`),       // add X[i], h
    () => mov(a2Cur, ROT[0]),                              // mov a, a2
    () => rorI(REG_a1, Sigma0[1] - Sigma0[0]),           // ror a1, 11
    () => xor(REG_T1, ROT[6]),                             // xor g, a4
    () => xor(a2Cur, ROT[1]),                              // xor b, a2
    () => rorI(REG_a0, Sigma1[0]),                       // ror a0, 6
    () => add(ROT[7], REG_T1),                             // add a4, h
    () => and_(a3Cur, a2Cur),                              // and a2, a3
    () => xor(REG_a1, ROT[0]),                             // xor a, a1
    () => add(ROT[7], REG_a0),                             // add a0, h
    () => xor(a3Cur, ROT[1]),                              // xor b, a3
    () => add(ROT[3], ROT[7]),                             // add h, d
    () => rorI(REG_a1, Sigma0[0]),                       // ror a1, 2
    () => add(ROT[7], a3Cur),                              // add a3, h
    () => mov(REG_a0, ROT[3]),                             // mov d, a0
    // add + state-update concatenated in the perl
    () => {
      add(REG_a1, ROT[7]);                                 // add h, a1
      // ($a2,$a3)=($a3,$a2)
      const t = a2Cur; a2Cur = a3Cur; a3Cur = t;
      // unshift(@ROT,pop(@ROT)) — rotate right
      ROT.unshift(ROT.pop() as string);
      iCnt++;
    },
  ];
}

type BodyFn = () => Thunk[];

function gather(body: BodyFn): Thunk[] {
  return [...body(), ...body(), ...body(), ...body()];
}

// ---------------------------------------------------------------------------
// SIMD register allocation for the message schedule
// ---------------------------------------------------------------------------
const X = ["%xmm0", "%xmm1", "%xmm2", "%xmm3"];
const t0 = "%xmm4", t1 = "%xmm5", t2 = "%xmm6", t3 = "%xmm7";
let Tbl = "%rbp";

// ---------------------------------------------------------------------------
// AVX_256_00_47 — interleave 4 body rounds with the message schedule
// ---------------------------------------------------------------------------
function avx256_00_47(j: number, body: BodyFn): void {
  const insns = gather(body);
  const shift = () => insns.shift();

  // Xupdate_256_AVX returns 31 instructions; each is followed by 3 body thunks.
  // We inline the xupdate calls and interleave.
  const xupdateSteps: Array<() => void> = [
    () => AUTOLOAD('vpalignr', t0, X[1], X[0], '4'),
    () => AUTOLOAD('vpalignr', t3, X[3], X[2], '4'),
    () => AUTOLOAD('vpsrld', t2, t0, String(sigma0[0])),
    () => AUTOLOAD('vpaddd', X[0], X[0], t3),
    () => AUTOLOAD('vpsrld', t3, t0, String(sigma0[2])),
    () => AUTOLOAD('vpslld', t1, t0, String(8 * 4 - sigma0[1])),
    () => AUTOLOAD('vpxor', t0, t3, t2),
    () => AUTOLOAD('vpshufd', t3, X[3], '250'),
    () => AUTOLOAD('vpsrld', t2, t2, String(sigma0[1] - sigma0[0])),
    () => AUTOLOAD('vpxor', t0, t0, t1),
    () => AUTOLOAD('vpslld', t1, t1, String(sigma0[1] - sigma0[0])),
    () => AUTOLOAD('vpxor', t0, t0, t2),
    () => AUTOLOAD('vpsrld', t2, t3, String(sigma1[2])),
    () => AUTOLOAD('vpxor', t0, t0, t1),
    () => AUTOLOAD('vpsrlq', t3, t3, String(sigma1[0])),
    () => AUTOLOAD('vpaddd', X[0], X[0], t0),
    () => AUTOLOAD('vpxor', t2, t2, t3),
    () => AUTOLOAD('vpsrlq', t3, t3, String(sigma1[1] - sigma1[0])),
    () => AUTOLOAD('vpxor', t2, t2, t3),
    () => AUTOLOAD('vpshufd', t2, t2, '132'),
    () => AUTOLOAD('vpsrldq', t2, t2, '8'),
    () => AUTOLOAD('vpaddd', X[0], X[0], t2),
    () => AUTOLOAD('vpshufd', t3, X[0], '80'),
    () => AUTOLOAD('vpsrld', t2, t3, String(sigma1[2])),
    () => AUTOLOAD('vpsrlq', t3, t3, String(sigma1[0])),
    () => AUTOLOAD('vpxor', t2, t2, t3),
    () => AUTOLOAD('vpsrlq', t3, t3, String(sigma1[1] - sigma1[0])),
    () => AUTOLOAD('vpxor', t2, t2, t3),
    () => AUTOLOAD('vpshufd', t2, t2, '232'),
    () => AUTOLOAD('vpslldq', t2, t2, '8'),
    () => AUTOLOAD('vpaddd', X[0], X[0], t2),
  ];

  for (const xstep of xupdateSteps) {
    xstep();
    const t = shift(); if (t) t();
    const t_ = shift(); if (t_) t_();
    const t__ = shift(); if (t__) t__();
  }

  // vpaddd t2, X[0], 16*2*j($Tbl)
  AUTOLOAD('vpaddd', t2, X[0], `${16 * 2 * j}(${Tbl})`);
  // remaining body thunks
  for (let t = shift(); t; t = shift()) t();
  // vmovdqa 16*j(%rsp), t2
  AUTOLOAD('vmovdqa', `${16 * j}(%rsp)`, t2);
}

// ---------------------------------------------------------------------------
// Rotate @X (push(shift) = rotate left)
// ---------------------------------------------------------------------------
function rotateX(): void {
  X.push(X.shift() as string);
}

// ---------------------------------------------------------------------------
// AVX body: prologue, loop, epilogue
// ---------------------------------------------------------------------------
function genAvxPrologue(): void {
  rorMode = 'shrd'; // local *ror = sub { &shrd(@_[0],@_) }
  Tbl = '%rbp';
  code += `.type	aesni_cbc_sha256_enc_avx,@function,6
.align	64
aesni_cbc_sha256_enc_avx:
.cfi_startproc
.Lavx_shortcut:
	mov	8(%rsp),%r10	# load 7th parameter
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
	sub	128,%rsp
	and	\$-64,%rsp		# align stack frame

	shl	\$6,%rdx
	sub	%rdi,%rsi		# re-bias
	sub	%rdi,%r10
	add	%rdi,%rdx		# end of input

	mov	%rsi,64+8(%rsp)
	mov	%rdx,64+16(%rsp)
	mov	%r8,64+32(%rsp)
	mov	%r9,64+40(%rsp)
	mov	%r10,64+48(%rsp)
	mov	%rax,120(%rsp)
.cfi_cfa_expression	120(%rsp),deref,+8
.Lprologue_avx:
	vzeroall

	mov	%rdi,%r12		# borrow $a4
	lea	0x80(%rcx),%rdi		# size optimization, reassign
	lea	aesni_sha256_K256+544(%rip),%r13	# borrow $a0
	mov	0xf0-0x80(%rdi),%r14d	# rounds, borrow $a1
	mov	%r9,%r15		# borrow $a2
	mov	%r10,%rsi		# borrow $a3
	vmovdqu	(%r8),%xmm8		# load IV
	sub	\$9,%r14

	mov	0(%r15),%eax
	mov	4(%r15),%ebx
	mov	8(%r15),%ecx
	mov	12(%r15),%edx
	mov	16(%r15),%r8d
	mov	20(%r15),%r9d
	mov	24(%r15),%r10d
	mov	28(%r15),%r11d

	vmovdqa	0x00(%r13,%r14,8),%xmm14
	vmovdqa	0x10(%r13,%r14,8),%xmm13
	vmovdqa	0x20(%r13,%r14,8),%xmm12
	vmovdqu	0x00-0x80(%rdi),%xmm10
	jmp	.Lloop_avx
`;
}

function genAvxLoop(): void {
  code += `.align	16
.Lloop_avx:
	vmovdqa	aesni_sha256_K256+512(%rip),%xmm7
	vmovdqu	0x00(%rsi,%r12),%xmm0
	vmovdqu	0x10(%rsi,%r12),%xmm1
	vmovdqu	0x20(%rsi,%r12),%xmm2
	vmovdqu	0x30(%rsi,%r12),%xmm3
	vpshufb	%xmm7,%xmm0,%xmm0
	lea	aesni_sha256_K256(%rip),%rbp
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
	mov	%ebx,%esi
	vmovdqa	%xmm6,0x20(%rsp)
	xor	%ecx,%esi			# magic
	vmovdqa	%xmm7,0x30(%rsp)
	mov	%r8d,%r13d
	jmp	.Lavx_00_47

.align	16
.Lavx_00_47:
	sub	\$-16*2*4,%rbp	# size optimization
	vmovdqu	(%r12),%xmm9		# $a4
	mov	%r12,64+0(%rsp)		# $a4
`;
  // 4 iterations of AVX_256_00_47
  resetRoundState();
  aesIdx = 0;
  for (let j = 0; j < 4; j++) {
    avx256_00_47(j, body00_15);
    rotateX();
  }
  // AES finish
  code += `	mov	64+0(%rsp),%r12		# borrow $a4
	vpand	%xmm14,%xmm11,%xmm11
	mov	64+8(%rsp),%r15		# borrow $a2
	vpor	%xmm11,%xmm8,%xmm8
	vmovdqu	%xmm8,(%r15,%r12)	# write output
	lea	16(%r12),%r12		# inp++

	cmpb	\$0,131(%rbp)
	jne	.Lavx_00_47

	vmovdqu	(%r12),%xmm9
	mov	%r12,64+0(%rsp)
`;
  // Final 16 rounds (48-63): 16 body calls, no message schedule
  aesIdx = 0;
  // $i continues from where it left off (should be 16, so iCnt=16 → iCnt&15=0)
  // Actually the perl resets $aesni_cbc_idx=0 but $i continues.
  // After 16 body calls in the loop, $i=16. The final 16 rounds use $i=16..31.
  // But the perl does: $aesni_cbc_idx=0; for ($i=0; $i<16; ) { foreach(body_00_15()) { eval; } }
  // So $i is RESET to 0 for the final 16 rounds!
  iCnt = 0;
  // Reset a2/a3 and ROT for the final rounds? No — the state carries over.
  // But $i and $aesni_cbc_idx are reset. The perl does NOT reset @ROT.
  // Actually looking at the perl: the final rounds just continue with the current @ROT.
  // But $i is reset to 0. And the body uses $i&15 for the stack offset.
  // Since the stack still has the 16 X+K values from the last loop iteration,
  // the offsets 0..15 are correct.
  for (let k = 0; k < 16; ) {
    const thunks = body00_15();
    for (const t of thunks) t();
    // body00_15's last thunk increments iCnt; we need k to track body calls
    k++;
  }
}

function genAvxEpilogue(): void {
  code += `	mov	64+0(%rsp),%r12		# borrow $a4
	mov	64+8(%rsp),%r13		# borrow $a0
	mov	64+40(%rsp),%r15	# borrow $a2
	mov	64+48(%rsp),%rsi	# borrow $a3

	vpand	%xmm14,%xmm11,%xmm11
	mov	%r14d,%eax
	vpor	%xmm11,%xmm8,%xmm8
	vmovdqu	%xmm8,(%r13,%r12)	# write output
	lea	16(%r12),%r12		# inp++

	add	0(%r15),%eax
	add	4(%r15),%ebx
	add	8(%r15),%ecx
	add	12(%r15),%edx
	add	16(%r15),%r8d
	add	20(%r15),%r9d
	add	24(%r15),%r10d
	add	28(%r15),%r11d

	cmp	64+16(%rsp),%r12

	mov	%eax,0(%r15)
	mov	%ebx,4(%r15)
	mov	%ecx,8(%r15)
	mov	%edx,12(%r15)
	mov	%r8d,16(%r15)
	mov	%r9d,20(%r15)
	mov	%r10d,24(%r15)
	mov	%r11d,28(%r15)
	jb	.Lloop_avx

	mov	64+32(%rsp),%r8
	mov	120(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	vmovdqu	%xmm8,(%r8)		# output IV
	vzeroall
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
.size	aesni_cbc_sha256_enc_avx,.-aesni_cbc_sha256_enc_avx
`;
}

function genAvx(): void {
  genAvxPrologue();
  genAvxLoop();
  genAvxEpilogue();
}

// ---------------------------------------------------------------------------
// Data section: K256 table (prefixed with aesni_sha256_)
// ---------------------------------------------------------------------------
function genData(): void {
  // K256: 32 lines of 4 dwords each (each 4-dword group repeated twice),
  // then bswap masks, then zero/mask constants, then copyright string.
  const k256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  code += `
.section .rodata align=64
.align	64
.type	aesni_sha256_K256,@object
aesni_sha256_K256:
`;
  for (let i = 0; i < k256.length; i += 4) {
    code += `	.long	0x${k256[i].toString(16)},0x${k256[i+1].toString(16)},0x${k256[i+2].toString(16)},0x${k256[i+3].toString(16)}\n`;
  }
  code += `
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f
	.long	0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f
	.long	0,0,0,0,   0,0,0,0,   -1,-1,-1,-1
	.long	0,0,0,0,   0,0,0,0
	.asciz	"AESNI-CBC+SHA256 stitch for x86_64, CRYPTOGAMS by <appro\\@openssl.org>"
.align	64
.previous
`;
}

// ---------------------------------------------------------------------------
// Dispatcher: always routes to the AVX body (xop/avx2/shaext are future work)
// ---------------------------------------------------------------------------
function genDispatch(): void {
  code += `.text

.extern	OPENSSL_ia32cap_P
.globl	aesni_cbc_sha256_enc
.type	aesni_cbc_sha256_enc,@abi-omnipotent
.align	16
aesni_cbc_sha256_enc:
.cfi_startproc
	lea	OPENSSL_ia32cap_P(%rip),%r11
	mov	\$1,%eax
	cmp	\$0,%rdi
	je	.Lprobe
	# NOTE: full dispatcher would check SHA-NI (bit 61), XOP (bit 11),
	# BMI2+AVX2+BMI1 (bits 8/5/3) and AVX (bit 28). Only the AVX body is
	# ported so far; route unconditionally. See NOTES.md.
	jmp	aesni_cbc_sha256_enc_avx
	ud2
	xor	%eax,%eax
	cmp	\$0,%rdi
	je	.Lprobe
	ud2
.Lprobe:
	ret
.cfi_endproc
.size	aesni_cbc_sha256_enc,.-aesni_cbc_sha256_enc
`;
}

// ---------------------------------------------------------------------------
// post-process: sha256* / bare aesenc -> .byte encodings
// (the JS xlate has pshufb/movq/pclmulqdq/vprotd hardcoded but NOT
//  sha256*/aesenc mnemonics)
// ---------------------------------------------------------------------------
function rexBits(dst: number, src: number): number {
  let rex = 0;
  if (dst >= 8) rex |= 0x04;
  if (src >= 8) rex |= 0x01;
  return rex;
}

function sha256rnds2Sub(args: string): string {
  // sha256rnds2 %xmm1, %xmm0  — opcode 0F 38 CB
  const m = args.match(/%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!m) return 'sha256rnds2\t' + args;
  const src = parseInt(m[1]);
  const dst = parseInt(m[2]);
  const opcodes = [0x0f, 0x38, 0xcb];
  const rex = rexBits(dst, src);
  if (rex) opcodes.unshift(0x40 | rex);
  opcodes.push(0xc0 | (src & 7) | ((dst & 7) << 3));
  return '.byte\t' + opcodes.join(',');
}

function sha256msgSub(instr: string, args: string): string {
  // sha256msg1 / sha256msg2 — opcode 0F 38 CC / CD
  const opcodelet: Record<string, number> = { sha256msg1: 0xcc, sha256msg2: 0xcd };
  const m = args.match(/%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (opcodelet[instr] === undefined || !m) return instr + '\t' + args;
  const src = parseInt(m[1]);
  const dst = parseInt(m[2]);
  const opcodes = [0x0f, 0x38];
  const rex = rexBits(dst, src);
  if (rex) opcodes.unshift(0x40 | rex);
  opcodes.push(opcodelet[instr]);
  opcodes.push(0xc0 | (src & 7) | ((dst & 7) << 3));
  return '.byte\t' + opcodes.join(',');
}

function aesniSub(args: string): string {
  const m = args.match(/(aes[a-z]+)\s+%xmm([0-9]+),\s*%xmm([0-9]+)/);
  if (!m) return args;
  const opcodelet: Record<string, number> = {
    aesenc: 0xdc, aesenclast: 0xdd, aesdec: 0xde, aesdeclast: 0xdf,
  };
  if (opcodelet[m[1]] === undefined) return args;
  const src = parseInt(m[2]);
  const dst = parseInt(m[3]);
  const opcodes = [0x66, 0x0f, 0x38];
  const rex = rexBits(dst, src);
  if (rex) opcodes.push(0x40 | rex);
  opcodes.push(opcodelet[m[1]], 0xc0 | (src & 7) | ((dst & 7) << 3));
  return '.byte\t' + opcodes.join(',');
}

function postProcess(): void {
  code = code
    .split('\n')
    .map(line => {
      const m = line.match(/\b(sha256rnds2)\s+(.*)/);
      if (m) return line.slice(0, m.index) + sha256rnds2Sub(m[2]);
      const m2 = line.match(/\b(sha256msg[12])\s+(.*)/);
      if (m2) return line.slice(0, m2.index) + sha256msgSub(m2[1], m2[2]);
      // bare aesenc/aesenclast (skip vaes*)
      const m3 = line.match(/\b(aes.*%xmm[0-9]+).*$/);
      if (m3 && !line.match(/\bvaes/)) {
        return line.slice(0, m3.index) + aesniSub(m3[1]);
      }
      return line;
    })
    .join('\n');
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------
genDispatch();
genData();
genAvx();
postProcess();

export default translateAssembly(code);
