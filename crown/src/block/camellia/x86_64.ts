/**
 * Camellia for x86_64.
 *
 * TypeScript port of OpenSSL crypto/camellia/asm/cmll-x86_64.pl.
 * Copyright 2008-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under Apache License 2.0.
 *
 * Pinned to the reference configuration: $win64=0 (unix SysV argument
 * registers; the Win64 SEH handlers are omitted).
 */

import { translateAssembly } from 'jsasm/x86_64-xlate';

let code = '';

// Register assignments (from the perl, $win64=0).
const t0 = '%eax';
const t1 = '%ebx';
const t2 = '%ecx';
const t3 = '%edx';
const S = ['%r8d', '%r9d', '%r10d', '%r11d'];
const i0 = '%esi';
const i1 = '%edi';
const Tbl = '%rbp'; // size optimization
const inp = '%r12';
const out = '%r13';
const key = '%r14';
const keyend = '%r15';
const arg0d = '%edi';

// perl sub hi(): %eax -> %ah etc.
function hi(r: string): string {
  return r.replace(/%[er]([a-d])x/, '%$1h');
}

// perl sub lo(): %eax -> %al, %esi -> %sil, %r8d -> %r8b etc.
function lo(r: string): string {
  let s = r.replace(/%[er]([a-d])x/, '%$1l');
  s = s.replace(/%[er]([sd]i)/, '%$1l');
  s = s.replace(/%(r[0-9]+)[d]?/, '%$1b');
  return s;
}

const SBOX1_1110 = 0;
const SBOX4_4404 = 4;
const SBOX2_0222 = 2048;
const SBOX3_3033 = 2052;

function Camellia_Feistel(i: number, seed = 0): void {
  const scale = seed < 0 ? -8 : 8;
  const j = (i & 1) * 2;
  const s0 = S[j % 4];
  const s1 = S[(j + 1) % 4];
  const s2 = S[(j + 2) % 4];
  const s3 = S[(j + 3) % 4];

  const koff = seed + (i + 1) * scale;

  code += `	xor	${s0},${t0}				# t0^=key[0]
	xor	${s1},${t1}				# t1^=key[1]
	movz	${hi(t0)},${i0}		# (t0>>8)&0xff
	movz	${lo(t1)},${i1}		# (t1>>0)&0xff
	mov	${SBOX3_3033}(${Tbl},${i0},8),${t3}	# t3=SBOX3_3033[0]
	mov	${SBOX1_1110}(${Tbl},${i1},8),${t2}	# t2=SBOX1_1110[1]
	movz	${lo(t0)},${i0}		# (t0>>0)&0xff
	shr	$16,${t0}
	movz	${hi(t1)},${i1}		# (t1>>8)&0xff
	xor	${SBOX4_4404}(${Tbl},${i0},8),${t3}	# t3^=SBOX4_4404[0]
	shr	$16,${t1}
	xor	${SBOX4_4404}(${Tbl},${i1},8),${t2}	# t2^=SBOX4_4404[1]
	movz	${hi(t0)},${i0}		# (t0>>24)&0xff
	movz	${lo(t1)},${i1}		# (t1>>16)&0xff
	xor	${SBOX1_1110}(${Tbl},${i0},8),${t3}	# t3^=SBOX1_1110[0]
	xor	${SBOX3_3033}(${Tbl},${i1},8),${t2}	# t2^=SBOX3_3033[1]
	movz	${lo(t0)},${i0}		# (t0>>16)&0xff
	movz	${hi(t1)},${i1}		# (t1>>24)&0xff
	xor	${SBOX2_0222}(${Tbl},${i0},8),${t3}	# t3^=SBOX2_0222[0]
	xor	${SBOX2_0222}(${Tbl},${i1},8),${t2}	# t2^=SBOX2_0222[1]
	mov	${koff}(${key}),${t1}	# prefetch key[i+1]
	mov	${koff + 4}(${key}),${t0}
	xor	${t3},${t2}				# t2^=t3
	ror	$8,${t3}				# t3=RightRotate(t3,8)
	xor	${t2},${s2}
	xor	${t2},${s3}
	xor	${t3},${s3}
`;
}

// perl sub _saveround($rnd,$key,@T) with optional leading $bias
function _saveround(
  rnd: number,
  keyReg: string,
  ...rest: (string | number)[]
): void {
  let bias = 0;
  let T = rest;
  if (typeof T[0] === 'number') {
    bias = T[0] as number;
    T = T.slice(1);
  }
  if (T.length === 4) {
    code += `	mov	${T[1]},${bias + rnd * 8 + 0}(${keyReg})
	mov	${T[0]},${bias + rnd * 8 + 4}(${keyReg})
	mov	${T[3]},${bias + rnd * 8 + 8}(${keyReg})
	mov	${T[2]},${bias + rnd * 8 + 12}(${keyReg})
`;
  } else {
    code += `	mov	${T[0]},${bias + rnd * 8 + 0}(${keyReg})\n`;
    if (T.length >= 2) {
      code += `	mov	${T[1]},${bias + rnd * 8 + 8}(${keyReg})\n`;
    }
  }
}

// perl sub _loadround($rnd,$key,@T)
function _loadround(
  rnd: number,
  keyReg: string,
  ...rest: (string | number)[]
): void {
  let bias = 0;
  let T = rest;
  if (typeof T[0] === 'number') {
    bias = T[0] as number;
    T = T.slice(1);
  }
  code += `	mov	${bias + rnd * 8 + 0}(${keyReg}),${T[0]}\n`;
  if (T.length >= 2) {
    code += `	mov	${bias + rnd * 8 + 8}(${keyReg}),${T[1]}\n`;
  }
}

// perl sub _rotl128($i0,$i1,$rot) - rotate without shld
function _rotl128(i0r: string, i1r: string, rot: number): void {
  if (rot) {
    code += `	mov	${i0r},%r11
	shl	$${rot},${i0r}
	mov	${i1r},%r9
	shr	$${64 - rot},%r9
	shr	$${64 - rot},%r11
	or	%r9,${i0r}
	shl	$${rot},${i1r}
	or	%r11,${i1r}
`;
  }
}

code += `.text

# V1.x API
.globl	Camellia_EncryptBlock
.type	Camellia_EncryptBlock,@abi-omnipotent
.align	16
Camellia_EncryptBlock:
.cfi_startproc
	movl	$128,%eax
	subl	${arg0d},%eax
	movl	$3,${arg0d}
	adcl	$0,${arg0d}	# keyBitLength==128?3:4
	jmp	.Lenc_rounds
.cfi_endproc
.size	Camellia_EncryptBlock,.-Camellia_EncryptBlock
# V2
.globl	Camellia_EncryptBlock_Rounds
.type	Camellia_EncryptBlock_Rounds,@function,4
.align	16
.Lenc_rounds:
Camellia_EncryptBlock_Rounds:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
.Lenc_prologue:

	#mov	%rsi,${inp}		# put away arguments
	mov	%rcx,${out}
	mov	%rdx,${key}

	shl	$6,%edi		# process grandRounds
	lea	.LCamellia_SBOX(%rip),${Tbl}
	lea	(${key},%rdi),${keyend}

	mov	0(%rsi),${S[0]}		# load plaintext
	mov	4(%rsi),${S[1]}
	mov	8(%rsi),${S[2]}
	bswap	${S[0]}
	mov	12(%rsi),${S[3]}
	bswap	${S[1]}
	bswap	${S[2]}
	bswap	${S[3]}

	call	_x86_64_Camellia_encrypt

	bswap	${S[0]}
	bswap	${S[1]}
	bswap	${S[2]}
	mov	${S[0]},0(${out})
	bswap	${S[3]}
	mov	${S[1]},4(${out})
	mov	${S[2]},8(${out})
	mov	${S[3]},12(${out})

	mov	0(%rsp),%r15
.cfi_restore	%r15
	mov	8(%rsp),%r14
.cfi_restore	%r14
	mov	16(%rsp),%r13
.cfi_restore	%r13
	mov	24(%rsp),%rbp
.cfi_restore	%rbp
	mov	32(%rsp),%rbx
.cfi_restore	%rbx
	lea	40(%rsp),%rsp
.cfi_adjust_cfa_offset	-40
.Lenc_epilogue:
	ret
.cfi_endproc
.size	Camellia_EncryptBlock_Rounds,.-Camellia_EncryptBlock_Rounds

.type	_x86_64_Camellia_encrypt,@abi-omnipotent
.align	16
_x86_64_Camellia_encrypt:
.cfi_startproc
	xor	0(${key}),${S[1]}
	xor	4(${key}),${S[0]}		# ^=key[0-3]
	xor	8(${key}),${S[3]}
	xor	12(${key}),${S[2]}
.align	16
.Leloop:
	mov	16(${key}),${t1}		# prefetch key[4-5]
	mov	20(${key}),${t0}

`;
for (let i = 0; i < 6; i++) {
  Camellia_Feistel(i, 16);
}
code += `	lea	16*4(${key}),${key}
	cmp	${keyend},${key}
	mov	8(${key}),${t3}		# prefetch key[2-3]
	mov	12(${key}),${t2}
	je	.Ledone

	and	${S[0]},${t0}
	or	${S[3]},${t3}
	rol	$1,${t0}
	xor	${t3},${S[2]}		# s2^=s3|key[3];
	xor	${t0},${S[1]}		# s1^=LeftRotate(s0&key[0],1);
	and	${S[2]},${t2}
	or	${S[1]},${t1}
	rol	$1,${t2}
	xor	${t1},${S[0]}		# s0^=s1|key[1];
	xor	${t2},${S[3]}		# s3^=LeftRotate(s2&key[2],1);
	jmp	.Leloop

.align	16
.Ledone:
	xor	${S[2]},${t0}		# SwapHalf
	xor	${S[3]},${t1}
	xor	${S[0]},${t2}
	xor	${S[1]},${t3}

	mov	${t0},${S[0]}
	mov	${t1},${S[1]}
	mov	${t2},${S[2]}
	mov	${t3},${S[3]}

	.byte	0xf3,0xc3		# rep ret
.cfi_endproc
.size	_x86_64_Camellia_encrypt,.-_x86_64_Camellia_encrypt

# V1.x API
.globl	Camellia_DecryptBlock
.type	Camellia_DecryptBlock,@abi-omnipotent
.align	16
Camellia_DecryptBlock:
.cfi_startproc
	movl	$128,%eax
	subl	${arg0d},%eax
	movl	$3,${arg0d}
	adcl	$0,${arg0d}	# keyBitLength==128?3:4
	jmp	.Ldec_rounds
.cfi_endproc
.size	Camellia_DecryptBlock,.-Camellia_DecryptBlock
# V2
.globl	Camellia_DecryptBlock_Rounds
.type	Camellia_DecryptBlock_Rounds,@function,4
.align	16
.Ldec_rounds:
Camellia_DecryptBlock_Rounds:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
.Ldec_prologue:

	#mov	%rsi,${inp}		# put away arguments
	mov	%rcx,${out}
	mov	%rdx,${keyend}

	shl	$6,%edi		# process grandRounds
	lea	.LCamellia_SBOX(%rip),${Tbl}
	lea	(${keyend},%rdi),${key}

	mov	0(%rsi),${S[0]}		# load plaintext
	mov	4(%rsi),${S[1]}
	mov	8(%rsi),${S[2]}
	bswap	${S[0]}
	mov	12(%rsi),${S[3]}
	bswap	${S[1]}
	bswap	${S[2]}
	bswap	${S[3]}

	call	_x86_64_Camellia_decrypt

	bswap	${S[0]}
	bswap	${S[1]}
	bswap	${S[2]}
	mov	${S[0]},0(${out})
	bswap	${S[3]}
	mov	${S[1]},4(${out})
	mov	${S[2]},8(${out})
	mov	${S[3]},12(${out})

	mov	0(%rsp),%r15
.cfi_restore	%r15
	mov	8(%rsp),%r14
.cfi_restore	%r14
	mov	16(%rsp),%r13
.cfi_restore	%r13
	mov	24(%rsp),%rbp
.cfi_restore	%rbp
	mov	32(%rsp),%rbx
.cfi_restore	%rbx
	lea	40(%rsp),%rsp
.cfi_adjust_cfa_offset	-40
.Ldec_epilogue:
	ret
.cfi_endproc
.size	Camellia_DecryptBlock_Rounds,.-Camellia_DecryptBlock_Rounds

.type	_x86_64_Camellia_decrypt,@abi-omnipotent
.align	16
_x86_64_Camellia_decrypt:
.cfi_startproc
	xor	0(${key}),${S[1]}
	xor	4(${key}),${S[0]}		# ^=key[0-3]
	xor	8(${key}),${S[3]}
	xor	12(${key}),${S[2]}
.align	16
.Ldloop:
	mov	-8(${key}),${t1}		# prefetch key[4-5]
	mov	-4(${key}),${t0}

`;
for (let i = 0; i < 6; i++) {
  Camellia_Feistel(i, -8);
}
code += `	lea	-16*4(${key}),${key}
	cmp	${keyend},${key}
	mov	0(${key}),${t3}		# prefetch key[2-3]
	mov	4(${key}),${t2}
	je	.Lddone

	and	${S[0]},${t0}
	or	${S[3]},${t3}
	rol	$1,${t0}
	xor	${t3},${S[2]}		# s2^=s3|key[3];
	xor	${t0},${S[1]}		# s1^=LeftRotate(s0&key[0],1);
	and	${S[2]},${t2}
	or	${S[1]},${t1}
	rol	$1,${t2}
	xor	${t1},${S[0]}		# s0^=s1|key[1];
	xor	${t2},${S[3]}		# s3^=LeftRotate(s2&key[2],1);

	jmp	.Ldloop

.align	16
.Lddone:
	xor	${S[2]},${t2}
	xor	${S[3]},${t3}
	xor	${S[0]},${t0}
	xor	${S[1]},${t1}

	mov	${t2},${S[0]}		# SwapHalf
	mov	${t3},${S[1]}
	mov	${t0},${S[2]}
	mov	${t1},${S[3]}

	.byte	0xf3,0xc3		# rep ret
.cfi_endproc
.size	_x86_64_Camellia_decrypt,.-_x86_64_Camellia_decrypt
`;

{
  let step = 0;

  code += `.globl	Camellia_Ekeygen
.type	Camellia_Ekeygen,@function,3
.align	16
Camellia_Ekeygen:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
.Lkey_prologue:

	mov	%edi,${keyend}d		# put away arguments, keyBitLength
	mov	%rdx,${out}		# keyTable

	mov	0(%rsi),${S[0]}		# load 0-127 bits
	mov	4(%rsi),${S[1]}
	mov	8(%rsi),${S[2]}
	mov	12(%rsi),${S[3]}

	bswap	${S[0]}
	bswap	${S[1]}
	bswap	${S[2]}
	bswap	${S[3]}
`;
  _saveround(0, out, ...S); // KL<<<0
  code += `	cmp	$128,${keyend}		# check keyBitLength
	je	.L1st128

	mov	16(%rsi),${S[0]}		# load 128-191 bits
	mov	20(%rsi),${S[1]}
	cmp	$192,${keyend}
	je	.L1st192
	mov	24(%rsi),${S[2]}		# load 192-255 bits
	mov	28(%rsi),${S[3]}
	jmp	.L1st256
.L1st192:
	mov	${S[0]},${S[2]}
	mov	${S[1]},${S[3]}
	not	${S[2]}
	not	${S[3]}
.L1st256:
	bswap	${S[0]}
	bswap	${S[1]}
	bswap	${S[2]}
	bswap	${S[3]}
`;
  _saveround(4, out, ...S); // temp storage for KR!
  code += `	xor	0(${out}),${S[1]}		# KR^KL
	xor	4(${out}),${S[0]}
	xor	8(${out}),${S[3]}
	xor	12(${out}),${S[2]}

.L1st128:
	lea	.LCamellia_SIGMA(%rip),${key}
	lea	.LCamellia_SBOX(%rip),${Tbl}

	mov	0(${key}),${t1}
	mov	4(${key}),${t0}
`;
  Camellia_Feistel(step++);
  Camellia_Feistel(step++);
  code += `	xor	0(${out}),${S[1]}		# ^KL
	xor	4(${out}),${S[0]}
	xor	8(${out}),${S[3]}
	xor	12(${out}),${S[2]}
`;
  Camellia_Feistel(step++);
  Camellia_Feistel(step++);
  code += `	cmp	$128,${keyend}
	jne	.L2nd256

	lea	128(${out}),${out}		# size optimization
	shl	$32,%r8		# ${S[0]}||
	shl	$32,%r10		# ${S[2]}||
	or	%r9,%r8			# ||${S[1]}
	or	%r11,%r10		# ||${S[3]}
`;
  _loadround(0, out, -128, '%rax', '%rbx'); // KL
  _saveround(2, out, -128, '%r8', '%r10'); // KA<<<0
  _rotl128('%rax', '%rbx', 15);
  _saveround(4, out, -128, '%rax', '%rbx'); // KL<<<15
  _rotl128('%r8', '%r10', 15);
  _saveround(6, out, -128, '%r8', '%r10'); // KA<<<15
  _rotl128('%r8', '%r10', 15); // 15+15=30
  _saveround(8, out, -128, '%r8', '%r10'); // KA<<<30
  _rotl128('%rax', '%rbx', 30); // 15+30=45
  _saveround(10, out, -128, '%rax', '%rbx'); // KL<<<45
  _rotl128('%r8', '%r10', 15); // 30+15=45
  _saveround(12, out, -128, '%r8'); // KA<<<45
  _rotl128('%rax', '%rbx', 15); // 45+15=60
  _saveround(13, out, -128, '%rbx'); // KL<<<60
  _rotl128('%r8', '%r10', 15); // 45+15=60
  _saveround(14, out, -128, '%r8', '%r10'); // KA<<<60
  _rotl128('%rax', '%rbx', 17); // 60+17=77
  _saveround(16, out, -128, '%rax', '%rbx'); // KL<<<77
  _rotl128('%rax', '%rbx', 17); // 77+17=94
  _saveround(18, out, -128, '%rax', '%rbx'); // KL<<<94
  _rotl128('%r8', '%r10', 34); // 60+34=94
  _saveround(20, out, -128, '%r8', '%r10'); // KA<<<94
  _rotl128('%rax', '%rbx', 17); // 94+17=111
  _saveround(22, out, -128, '%rax', '%rbx'); // KL<<<111
  _rotl128('%r8', '%r10', 17); // 94+17=111
  _saveround(24, out, -128, '%r8', '%r10'); // KA<<<111
  code += `	mov	$3,%eax
	jmp	.Ldone
.align	16
.L2nd256:
`;
  _saveround(6, out, ...S); // temp storage for KA!
  code += `	xor	${4 * 8 + 0}(${out}),${S[1]}	# KA^KR
	xor	${4 * 8 + 4}(${out}),${S[0]}
	xor	${5 * 8 + 0}(${out}),${S[3]}
	xor	${5 * 8 + 4}(${out}),${S[2]}
`;
  Camellia_Feistel(step++);
  Camellia_Feistel(step++);

  _loadround(0, out, '%rax', '%rbx'); // KL
  _loadround(4, out, '%rcx', '%rdx'); // KR
  _loadround(6, out, '%r14', '%r15'); // KA
  code += `	lea	128(${out}),${out}		# size optimization
	shl	$32,%r8		# ${S[0]}||
	shl	$32,%r10		# ${S[2]}||
	or	%r9,%r8			# ||${S[1]}
	or	%r11,%r10		# ||${S[3]}
`;
  _saveround(2, out, -128, '%r8', '%r10'); // KB<<<0
  _rotl128('%rcx', '%rdx', 15);
  _saveround(4, out, -128, '%rcx', '%rdx'); // KR<<<15
  _rotl128('%r14', '%r15', 15);
  _saveround(6, out, -128, '%r14', '%r15'); // KA<<<15
  _rotl128('%rcx', '%rdx', 15); // 15+15=30
  _saveround(8, out, -128, '%rcx', '%rdx'); // KR<<<30
  _rotl128('%r8', '%r10', 30);
  _saveround(10, out, -128, '%r8', '%r10'); // KB<<<30
  _rotl128('%rax', '%rbx', 45);
  _saveround(12, out, -128, '%rax', '%rbx'); // KL<<<45
  _rotl128('%r14', '%r15', 30); // 15+30=45
  _saveround(14, out, -128, '%r14', '%r15'); // KA<<<45
  _rotl128('%rax', '%rbx', 15); // 45+15=60
  _saveround(16, out, -128, '%rax', '%rbx'); // KL<<<60
  _rotl128('%rcx', '%rdx', 30); // 30+30=60
  _saveround(18, out, -128, '%rcx', '%rdx'); // KR<<<60
  _rotl128('%r8', '%r10', 30); // 30+30=60
  _saveround(20, out, -128, '%r8', '%r10'); // KB<<<60
  _rotl128('%rax', '%rbx', 17); // 60+17=77
  _saveround(22, out, -128, '%rax', '%rbx'); // KL<<<77
  _rotl128('%r14', '%r15', 32); // 45+32=77
  _saveround(24, out, -128, '%r14', '%r15'); // KA<<<77
  _rotl128('%rcx', '%rdx', 34); // 60+34=94
  _saveround(26, out, -128, '%rcx', '%rdx'); // KR<<<94
  _rotl128('%r14', '%r15', 17); // 77+17=94
  _saveround(28, out, -128, '%r14', '%r15'); // KA<<<77
  _rotl128('%rax', '%rbx', 34); // 77+34=111
  _saveround(30, out, -128, '%rax', '%rbx'); // KL<<<111
  _rotl128('%r8', '%r10', 51); // 60+51=111
  _saveround(32, out, -128, '%r8', '%r10'); // KB<<<111
  code += `	mov	$4,%eax
.Ldone:
	mov	0(%rsp),%r15
.cfi_restore	%r15
	mov	8(%rsp),%r14
.cfi_restore	%r14
	mov	16(%rsp),%r13
.cfi_restore	%r13
	mov	24(%rsp),%rbp
.cfi_restore	%rbp
	mov	32(%rsp),%rbx
.cfi_restore	%rbx
	lea	40(%rsp),%rsp
.cfi_adjust_cfa_offset	-40
.Lkey_epilogue:
	ret
.cfi_endproc
.size	Camellia_Ekeygen,.-Camellia_Ekeygen
`;
}

// Interleaved S-box tables (Camellia_SBOX[0..3]).
const SBOX: number[] = [
  112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65, 35,
  239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189, 134, 184,
  175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26, 166, 225, 57,
  202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77, 139, 13, 154, 102,
  251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153, 223, 76, 203, 194, 52,
  126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215, 20, 88, 58, 97, 222, 27, 17,
  28, 50, 15, 156, 22, 83, 24, 242, 34, 254, 68, 207, 178, 195, 181, 122, 145,
  36, 8, 232, 168, 96, 252, 105, 80, 170, 208, 160, 125, 161, 137, 98, 151, 84,
  91, 30, 149, 224, 255, 100, 210, 16, 196, 0, 72, 163, 247, 117, 219, 138, 3,
  230, 218, 9, 63, 221, 148, 135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246,
  243, 157, 127, 191, 226, 82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111,
  75, 19, 190, 99, 46, 233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249,
  182, 47, 253, 180, 89, 120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66,
  136, 162, 141, 250, 114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60,
  56, 241, 164, 64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119,
  199, 128, 158,
];

function hex8(n: number): string {
  return '0x' + (n >>> 0).toString(16).padStart(8, '0');
}

function S1110(i: number): string {
  const s = SBOX[i];
  return hex8((s << 24) | (s << 16) | (s << 8));
}

function S4404(i: number): string {
  const idx = ((i << 1) | (i >> 7)) & 0xff;
  const s = SBOX[idx];
  return hex8((s << 24) | (s << 16) | s);
}

function S0222(i: number): string {
  let s = SBOX[i];
  s = ((s << 1) | (s >> 7)) & 0xff;
  return hex8((s << 16) | (s << 8) | s);
}

function S3033(i: number): string {
  let s = SBOX[i];
  s = ((s >> 1) | (s << 7)) & 0xff;
  return hex8((s << 24) | (s << 8) | s);
}

code += `.section .rodata align=64
.align	64
.LCamellia_SIGMA:
.long	0x3bcc908b, 0xa09e667f, 0x4caa73b2, 0xb67ae858
.long	0xe94f82be, 0xc6ef372f, 0xf1d36f1c, 0x54ff53a5
.long	0xde682d1d, 0x10e527fa, 0xb3e6c1fd, 0xb05688c2
.long	0,          0,          0,          0
.LCamellia_SBOX:
`;
// tables are interleaved, remember?
for (let i = 0; i < 256; i++) {
  code += `.long\t${S1110(i)},${S4404(i)}\n`;
}
for (let i = 0; i < 256; i++) {
  code += `.long\t${S0222(i)},${S3033(i)}\n`;
}

// void Camellia_cbc_encrypt (const void char *inp, unsigned char *out,
//			size_t length, const CAMELLIA_KEY *key,
//			unsigned char *ivp,const int enc);
const _key = '0(%rsp)';
const _end = '8(%rsp)'; // inp+len&~15
const _res = '16(%rsp)'; // len&15
const ivec = '24(%rsp)';
const _ivp = '40(%rsp)';
const _rsp = '48(%rsp)';

code += `.text
.globl	Camellia_cbc_encrypt
.type	Camellia_cbc_encrypt,@function,6
.align	16
Camellia_cbc_encrypt:
.cfi_startproc
	endbranch
	cmp	$0,%rdx
	je	.Lcbc_abort
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
.Lcbc_prologue:

	mov	%rsp,%rbp
.cfi_def_cfa_register	%rbp
	sub	$64,%rsp
	and	$-64,%rsp

	# place stack frame just "above mod 1024" the key schedule,
	# this ensures that cache associativity suffices
	lea	-64-63(%rcx),%r10
	sub	%rsp,%r10
	neg	%r10
	and	$0x3C0,%r10
	sub	%r10,%rsp
	#add	$8,%rsp		# 8 is reserved for callee's ra

	mov	%rdi,${inp}		# inp argument
	mov	%rsi,${out}		# out argument
	mov	%r8,%rbx		# ivp argument
	mov	%rcx,${key}		# key argument
	mov	272(%rcx),${keyend}d	# grandRounds

	mov	%r8,${_ivp}
	mov	%rbp,${_rsp}
.cfi_cfa_expression	${_rsp},deref,+56

.Lcbc_body:
	lea	.LCamellia_SBOX(%rip),${Tbl}

	mov	$32,%ecx
.align	4
.Lcbc_prefetch_sbox:
	mov	0(${Tbl}),%rax
	mov	32(${Tbl}),%rsi
	mov	64(${Tbl}),%rdi
	mov	96(${Tbl}),%r11
	lea	128(${Tbl}),${Tbl}
	loop	.Lcbc_prefetch_sbox
	sub	$4096,${Tbl}
	shl	$6,${keyend}
	mov	%rdx,%rcx		# len argument
	lea	(${key},${keyend}),${keyend}

	cmp	$0,%r9d		# enc argument
	je	.LCBC_DECRYPT

	and	$-16,%rdx
	and	$15,%rcx		# length residue
	lea	(${inp},%rdx),%rdx
	mov	${key},${_key}
	mov	%rdx,${_end}
	mov	%rcx,${_res}

	cmp	${inp},%rdx
	mov	0(%rbx),${S[0]}		# load IV
	mov	4(%rbx),${S[1]}
	mov	8(%rbx),${S[2]}
	mov	12(%rbx),${S[3]}
	je	.Lcbc_enc_tail
	jmp	.Lcbc_eloop

.align	16
.Lcbc_eloop:
	xor	0(${inp}),${S[0]}
	xor	4(${inp}),${S[1]}
	xor	8(${inp}),${S[2]}
	bswap	${S[0]}
	xor	12(${inp}),${S[3]}
	bswap	${S[1]}
	bswap	${S[2]}
	bswap	${S[3]}

	call	_x86_64_Camellia_encrypt

	mov	${_key},${key}		# "rewind" the key
	bswap	${S[0]}
	mov	${_end},%rdx
	bswap	${S[1]}
	mov	${_res},%rcx
	bswap	${S[2]}
	mov	${S[0]},0(${out})
	bswap	${S[3]}
	mov	${S[1]},4(${out})
	mov	${S[2]},8(${out})
	lea	16(${inp}),${inp}
	mov	${S[3]},12(${out})
	cmp	%rdx,${inp}
	lea	16(${out}),${out}
	jne	.Lcbc_eloop

	cmp	$0,%rcx
	jne	.Lcbc_enc_tail

	mov	${_ivp},${out}
	mov	${S[0]},0(${out})		# write out IV residue
	mov	${S[1]},4(${out})
	mov	${S[2]},8(${out})
	mov	${S[3]},12(${out})
	jmp	.Lcbc_done

.align	16
.Lcbc_enc_tail:
	xor	%rax,%rax
	mov	%rax,0+${ivec}
	mov	%rax,8+${ivec}
	mov	%rax,${_res}

.Lcbc_enc_pushf:
	pushfq
	cld
	mov	${inp},%rsi
	lea	8+${ivec},%rdi
	.long	0x9066A4F3		# rep movsb
	popfq
.Lcbc_enc_popf:

	lea	${ivec},${inp}
	lea	16+${ivec},%rax
	mov	%rax,${_end}
	jmp	.Lcbc_eloop		# one more time

.align	16
.LCBC_DECRYPT:
	xchg	${key},${keyend}
	add	$15,%rdx
	and	$15,%rcx		# length residue
	and	$-16,%rdx
	mov	${key},${_key}
	lea	(${inp},%rdx),%rdx
	mov	%rdx,${_end}
	mov	%rcx,${_res}

	mov	(%rbx),%rax		# load IV
	mov	8(%rbx),%rbx
	jmp	.Lcbc_dloop
.align	16
.Lcbc_dloop:
	mov	0(${inp}),${S[0]}
	mov	4(${inp}),${S[1]}
	mov	8(${inp}),${S[2]}
	bswap	${S[0]}
	mov	12(${inp}),${S[3]}
	bswap	${S[1]}
	mov	%rax,0+${ivec}		# save IV to temporary storage
	bswap	${S[2]}
	mov	%rbx,8+${ivec}
	bswap	${S[3]}

	call	_x86_64_Camellia_decrypt

	mov	${_key},${key}		# "rewind" the key
	mov	${_end},%rdx
	mov	${_res},%rcx

	bswap	${S[0]}
	mov	(${inp}),%rax		# load IV for next iteration
	bswap	${S[1]}
	mov	8(${inp}),%rbx
	bswap	${S[2]}
	xor	0+${ivec},${S[0]}
	bswap	${S[3]}
	xor	4+${ivec},${S[1]}
	xor	8+${ivec},${S[2]}
	lea	16(${inp}),${inp}
	xor	12+${ivec},${S[3]}
	cmp	%rdx,${inp}
	je	.Lcbc_ddone

	mov	${S[0]},0(${out})
	mov	${S[1]},4(${out})
	mov	${S[2]},8(${out})
	mov	${S[3]},12(${out})

	lea	16(${out}),${out}
	jmp	.Lcbc_dloop

.align	16
.Lcbc_ddone:
	mov	${_ivp},%rdx
	cmp	$0,%rcx
	jne	.Lcbc_dec_tail

	mov	${S[0]},0(${out})
	mov	${S[1]},4(${out})
	mov	${S[2]},8(${out})
	mov	${S[3]},12(${out})

	mov	%rax,(%rdx)		# write out IV residue
	mov	%rbx,8(%rdx)
	jmp	.Lcbc_done
.align	16
.Lcbc_dec_tail:
	mov	${S[0]},0+${ivec}
	mov	${S[1]},4+${ivec}
	mov	${S[2]},8+${ivec}
	mov	${S[3]},12+${ivec}

.Lcbc_dec_pushf:
	pushfq
	cld
	lea	8+${ivec},%rsi
	lea	(${out}),%rdi
	.long	0x9066A4F3		# rep movsb
	popfq
.Lcbc_dec_popf:

	mov	%rax,(%rdx)		# write out IV residue
	mov	%rbx,8(%rdx)
	jmp	.Lcbc_done

.align	16
.Lcbc_done:
	mov	${_rsp},%rcx
.cfi_def_cfa	%rcx,56
	mov	0(%rcx),%r15
.cfi_restore	%r15
	mov	8(%rcx),%r14
.cfi_restore	%r14
	mov	16(%rcx),%r13
.cfi_restore	%r13
	mov	24(%rcx),%r12
.cfi_restore	%r12
	mov	32(%rcx),%rbp
.cfi_restore	%rbp
	mov	40(%rcx),%rbx
.cfi_restore	%rbx
	lea	48(%rcx),%rsp
.cfi_def_cfa	%rsp,8
.Lcbc_abort:
	ret
.cfi_endproc
.size	Camellia_cbc_encrypt,.-Camellia_cbc_encrypt

.asciz	"Camellia for x86_64 by <https://github.com/dot-asm>"
`;

export default translateAssembly(code);
