// RC4 for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>
// Converted from Perl to TypeScript

let dat = '%rdi'; // arg1
let len = '%rsi'; // arg2
let inp = '%rdx'; // arg3
let out = '%rcx'; // arg4

let code = '';

// Main RC4 function
code += `
.text
.extern	OPENSSL_ia32cap_P

.globl	RC4
.type	RC4,@function,4
.align	16
RC4:
.cfi_startproc
	endbranch
	or	${len},${len}
	jne	.Lentry
	ret
.Lentry:
	push	%rbx
.cfi_push	%rbx
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
.Lprologue:
	mov	${len},%r11
	mov	${inp},%r12
	mov	${out},%r13
`;

// Reassign input arguments
len = '%r11';
inp = '%r12';
out = '%r13';

const XX = ['%r10', '%rsi'];
const TX = ['%rax', '%rbx'];
const YY = '%rcx';
const TY = '%rdx';

code += `
	xor	${XX[0]},${XX[0]}
	xor	${YY},${YY}

	lea	8(${dat}),${dat}
	mov	-8(${dat}),${XX[0]}#b
	mov	-4(${dat}),${YY}#b
	cmpl	$-1,256(${dat})
	je	.LRC4_CHAR
	mov	OPENSSL_ia32cap_P(%rip),%r8d
	xor	${TX[1]},${TX[1]}
	inc	${XX[0]}#b
	sub	${XX[0]},${TX[1]}
	sub	${inp},${out}
	movl	(${dat},${XX[0]},4),${TX[0]}#d
	test	$-16,${len}
	jz	.Lloop1
	bt	$30,%r8d	# Intel CPU?
	jc	.Lintel
	and	$7,${TX[1]}
	lea	1(${XX[0]}),${XX[1]}
	jz	.Loop8
	sub	${TX[1]},${len}
.Loop8_warmup:
	add	${TX[0]}#b,${YY}#b
	movl	(${dat},${YY},4),${TY}#d
	movl	${TX[0]}#d,(${dat},${YY},4)
	movl	${TY}#d,(${dat},${XX[0]},4)
	add	${TY}#b,${TX[0]}#b
	inc	${XX[0]}#b
	movl	(${dat},${TX[0]},4),${TY}#d
	movl	(${dat},${XX[0]},4),${TX[0]}#d
	xorb	(${inp}),${TY}#b
	movb	${TY}#b,(${out},${inp})
	lea	1(${inp}),${inp}
	dec	${TX[1]}
	jnz	.Loop8_warmup

	lea	1(${XX[0]}),${XX[1]}
	jmp	.Loop8
.align	16
.Loop8:
`;

// Loop8 unrolling
for (let i = 0; i < 8; i++) {
  if (i === 7) {
    code += `	add	$8,${XX[1]}#b\n`;
  }
  code += `	add	${TX[0]}#b,${YY}#b
	movl	(${dat},${YY},4),${TY}#d
	movl	${TX[0]}#d,(${dat},${YY},4)
	movl	${i === 7 ? -1 : i}*4(${dat},${XX[1]},4),${TX[1]}#d
	ror	$8,%r8				# ror is redundant when $i=0
	movl	${TY}#d,${i * 4}(${dat},${XX[0]},4)
	add	${TX[0]}#b,${TY}#b
	movb	(${dat},${TY},4),%r8b
`;
  // Rotate registers
  TX.push(TX.shift()!);
}

code += `	add	$8,${XX[0]}#b
	ror	$8,%r8
	sub	$8,${len}

	xor	(${inp}),%r8
	mov	%r8,(${out},${inp})
	lea	8(${inp}),${inp}

	test	$-8,${len}
	jnz	.Loop8
	cmp	$0,${len}
	jne	.Lloop1
	jmp	.Lexit

.align	16
.Lintel:
	test	$-32,${len}
	jz	.Lloop1
	and	$15,${TX[1]}
	jz	.Loop16_is_hot
	sub	${TX[1]},${len}
.Loop16_warmup:
	add	${TX[0]}#b,${YY}#b
	movl	(${dat},${YY},4),${TY}#d
	movl	${TX[0]}#d,(${dat},${YY},4)
	movl	${TY}#d,(${dat},${XX[0]},4)
	add	${TY}#b,${TX[0]}#b
	inc	${XX[0]}#b
	movl	(${dat},${TX[0]},4),${TY}#d
	movl	(${dat},${XX[0]},4),${TX[0]}#d
	xorb	(${inp}),${TY}#b
	movb	${TY}#b,(${out},${inp})
	lea	1(${inp}),${inp}
	dec	${TX[1]}
	jnz	.Loop16_warmup

	mov	${YY},${TX[1]}
	xor	${YY},${YY}
	mov	${TX[1]}#b,${YY}#b

.Loop16_is_hot:
	lea	(${dat},${XX[0]},4),${XX[1]}
`;

function RC4_loop(i: number): void {
  const j = i < 0 ? 0 : i;
  const xmm = `%xmm${j & 1}`;

  if (i === 15) code += `	add	$16,${XX[0]}#b\n`;
  if (i === 15) code += `	movdqu	(${inp}),%xmm2\n`;
  if (i <= 0) code += `	add	${TX[0]}#b,${YY}#b\n`;
  code += `	movl	(${dat},${YY},4),${TY}#d\n`;
  if (i === 0) code += `	pxor	%xmm0,%xmm2\n`;
  if (i === 0) code += `	psllq	$8,%xmm1\n`;
  if (i <= 1) code += `	pxor	${xmm},${xmm}\n`;
  code += `	movl	${TX[0]}#d,(${dat},${YY},4)\n`;
  code += `	add	${TY}#b,${TX[0]}#b\n`;
  if (i < 15) code += `	movl	${4 * (j + 1)}(${XX[1]}),${TX[1]}#d\n`;
  code += `	movz	${TX[0]}#b,${TX[0]}#d\n`;
  code += `	movl	${TY}#d,${4 * j}(${XX[1]})\n`;
  if (i === 0) code += `	pxor	%xmm1,%xmm2\n`;
  if (i === 15) code += `	lea	(${dat},${XX[0]},4),${XX[1]}\n`;
  if (i < 15) code += `	add	${TX[1]}#b,${YY}#b\n`;
  code += `	pinsrw	$${(j >> 1) & 7},(${dat},${TX[0]},4),${xmm}\n`;
  if (i === 0) code += `	movdqu	%xmm2,(${out},${inp})\n`;
  if (i === 0) code += `	lea	16(${inp}),${inp}\n`;
  if (i === 15) code += `	movl	(${XX[1]}),${TX[1]}#d\n`;
}

RC4_loop(-1);

code += `	jmp	.Loop16_enter
.align	16
.Loop16:
`;

for (let i = 0; i < 16; i++) {
  if (i === 1) code += `.Loop16_enter:\n`;
  RC4_loop(i);
  TX.push(TX.shift()!);
}

code += `	mov	${YY},${TX[1]}
	xor	${YY},${YY}			# keyword to partial register
	sub	$16,${len}
	mov	${TX[1]}#b,${YY}#b
	test	$-16,${len}
	jnz	.Loop16

	psllq	$8,%xmm1
	pxor	%xmm0,%xmm2
	pxor	%xmm1,%xmm2
	movdqu	%xmm2,(${out},${inp})
	lea	16(${inp}),${inp}

	cmp	$0,${len}
	jne	.Lloop1
	jmp	.Lexit

.align	16
.Lloop1:
	add	${TX[0]}#b,${YY}#b
	movl	(${dat},${YY},4),${TY}#d
	movl	${TX[0]}#d,(${dat},${YY},4)
	movl	${TY}#d,(${dat},${XX[0]},4)
	add	${TY}#b,${TX[0]}#b
	inc	${XX[0]}#b
	movl	(${dat},${TX[0]},4),${TY}#d
	movl	(${dat},${XX[0]},4),${TX[0]}#d
	xorb	(${inp}),${TY}#b
	movb	${TY}#b,(${out},${inp})
	lea	1(${inp}),${inp}
	dec	${len}
	jnz	.Lloop1
	jmp	.Lexit

.align	16
.LRC4_CHAR:
	add	$1,${XX[0]}#b
	movzb	(${dat},${XX[0]}),${TX[0]}#d
	test	$-8,${len}
	jz	.Lcloop1
	jmp	.Lcloop8
.align	16
.Lcloop8:
	mov	(${inp}),%r8d
	mov	4(${inp}),%r9d
`;

// Unroll 2x4-wise for character mode
for (let i = 0; i < 4; i++) {
  code += `	add	${TX[0]}#b,${YY}#b
	lea	1(${XX[0]}),${XX[1]}
	movzb	(${dat},${YY}),${TY}#d
	movzb	${XX[1]}#b,${XX[1]}#d
	movzb	(${dat},${XX[1]}),${TX[1]}#d
	movb	${TX[0]}#b,(${dat},${YY})
	cmp	${XX[1]},${YY}
	movb	${TY}#b,(${dat},${XX[0]})
	jne	.Lcmov${i}			# Intel cmov is sloooow...
	mov	${TX[0]},${TX[1]}
.Lcmov${i}:
	add	${TX[0]}#b,${TY}#b
	xor	(${dat},${TY}),%r8b
	ror	$8,%r8d
`;
  TX.push(TX.shift()!);
  XX.push(XX.shift()!);
}

for (let i = 4; i < 8; i++) {
  code += `	add	${TX[0]}#b,${YY}#b
	lea	1(${XX[0]}),${XX[1]}
	movzb	(${dat},${YY}),${TY}#d
	movzb	${XX[1]}#b,${XX[1]}#d
	movzb	(${dat},${XX[1]}),${TX[1]}#d
	movb	${TX[0]}#b,(${dat},${YY})
	cmp	${XX[1]},${YY}
	movb	${TY}#b,(${dat},${XX[0]})
	jne	.Lcmov${i}			# Intel cmov is sloooow...
	mov	${TX[0]},${TX[1]}
.Lcmov${i}:
	add	${TX[0]}#b,${TY}#b
	xor	(${dat},${TY}),%r9b
	ror	$8,%r9d
`;
  TX.push(TX.shift()!);
  XX.push(XX.shift()!);
}

code += `	lea	-8(${len}),${len}
	mov	%r8d,(${out})
	lea	8(${inp}),${inp}
	mov	%r9d,4(${out})
	lea	8(${out}),${out}

	test	$-8,${len}
	jnz	.Lcloop8
	cmp	$0,${len}
	jne	.Lcloop1
	jmp	.Lexit
`;

code += `.align	16
.Lcloop1:
	add	${TX[0]}#b,${YY}#b
	movzb	${YY}#b,${YY}#d
	movzb	(${dat},${YY}),${TY}#d
	movb	${TX[0]}#b,(${dat},${YY})
	movb	${TY}#b,(${dat},${XX[0]})
	add	${TX[0]}#b,${TY}#b
	add	$1,${XX[0]}#b
	movzb	${TY}#b,${TY}#d
	movzb	${XX[0]}#b,${XX[0]}#d
	movzb	(${dat},${TY}),${TY}#d
	movzb	(${dat},${XX[0]}),${TX[0]}#d
	xorb	(${inp}),${TY}#b
	lea	1(${inp}),${inp}
	movb	${TY}#b,(${out})
	lea	1(${out}),${out}
	sub	$1,${len}
	jnz	.Lcloop1
	jmp	.Lexit

.align	16
.Lexit:
	sub	$1,${XX[0]}#b
	movl	${XX[0]}#d,-8(${dat})
	movl	${YY}#d,-4(${dat})

	mov	(%rsp),%r13
.cfi_restore	%r13
	mov	8(%rsp),%r12
.cfi_restore	%r12
	mov	16(%rsp),%rbx
.cfi_restore	%rbx
	add	$24,%rsp
.cfi_adjust_cfa_offset	-24
.Lepilogue:
	ret
.cfi_endproc
.size	RC4,.-RC4
`;

const idx = '%r8';
const ido = '%r9';

code += `
.globl	RC4_set_key
.type	RC4_set_key,@function,3
.align	16
RC4_set_key:
.cfi_startproc
	endbranch
	lea	8(${dat}),${dat}
	lea	(${inp},${len}),${inp}
	neg	${len}
	mov	${len},%rcx
	xor	%eax,%eax
	xor	${ido},${ido}
	xor	%r10,%r10
	xor	%r11,%r11

	mov	OPENSSL_ia32cap_P(%rip),${idx}#d
	bt	$20,${idx}#d	# RC4_CHAR?
	jc	.Lc1stloop
	jmp	.Lw1stloop

.align	16
.Lw1stloop:
	mov	%eax,(${dat},%rax,4)
	add	$1,%al
	jnc	.Lw1stloop

	xor	${ido},${ido}
	xor	${idx},${idx}
.align	16
.Lw2ndloop:
	mov	(${dat},${ido},4),%r10d
	add	(${inp},${len},1),${idx}#b
	add	%r10b,${idx}#b
	add	$1,${len}
	mov	(${dat},${idx},4),%r11d
	cmovz	%rcx,${len}
	mov	%r10d,(${dat},${idx},4)
	mov	%r11d,(${dat},${ido},4)
	add	$1,${ido}#b
	jnc	.Lw2ndloop
	jmp	.Lexit_key

.align	16
.Lc1stloop:
	mov	%al,(${dat},%rax)
	add	$1,%al
	jnc	.Lc1stloop

	xor	${ido},${ido}
	xor	${idx},${idx}
.align	16
.Lc2ndloop:
	mov	(${dat},${ido}),%r10b
	add	(${inp},${len}),${idx}#b
	add	%r10b,${idx}#b
	add	$1,${len}
	mov	(${dat},${idx}),%r11b
	jnz	.Lcnowrap
	mov	%rcx,${len}
.Lcnowrap:
	mov	%r10b,(${dat},${idx})
	mov	%r11b,(${dat},${ido})
	add	$1,${ido}#b
	jnc	.Lc2ndloop
	movl	$-1,256(${dat})

.align	16
.Lexit_key:
	xor	%eax,%eax
	mov	%eax,-8(${dat})
	mov	%eax,-4(${dat})
	ret
.cfi_endproc
.size	RC4_set_key,.-RC4_set_key

.globl	RC4_options
.type	RC4_options,@abi-omnipotent
.align	16
RC4_options:
.cfi_startproc
	endbranch
	lea	.Lopts(%rip),%rax
	mov	OPENSSL_ia32cap_P(%rip),%edx
	bt	$20,%edx
	jc	.L8xchar
	bt	$30,%edx
	jnc	.Ldone
	add	$25,%rax
	ret
.L8xchar:
	add	$12,%rax
.Ldone:
	ret
.cfi_endproc
.align	64
.Lopts:
.asciz	"rc4(8x,int)"
.asciz	"rc4(8x,char)"
.asciz	"rc4(16x,int)"
.asciz	"RC4 for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.align	64
.size	RC4_options,.-RC4_options
`;

// Windows x64 exception handling (if needed)
const win64 = false; // Set to true if building for Windows

if (win64) {
  const rec = '%rcx';
  const frame = '%rdx';
  const context = '%r8';
  const disp = '%r9';

  code += `
.extern	__imp_RtlVirtualUnwind
.type	stream_se_handler,@abi-omnipotent
.align	16
stream_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	$64,%rsp

	mov	120(${context}),%rax	# pull context->Rax
	mov	248(${context}),%rbx	# pull context->Rip

	lea	.Lprologue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<prologue label
	jb	.Lin_prologue

	mov	152(${context}),%rax	# pull context->Rsp

	lea	.Lepilogue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lin_prologue

	lea	24(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%r12
	mov	-24(%rax),%r13
	mov	%rbx,144(${context})	# restore context->Rbx
	mov	%r12,216(${context})	# restore context->R12
	mov	%r13,224(${context})	# restore context->R13

.Lin_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152(${context})	# restore context->Rsp
	mov	%rsi,168(${context})	# restore context->Rsi
	mov	%rdi,176(${context})	# restore context->Rdi

	jmp	.Lcommon_seh_exit
.size	stream_se_handler,.-stream_se_handler

.type	key_se_handler,@abi-omnipotent
.align	16
key_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	$64,%rsp

	mov	152(${context}),%rax	# pull context->Rsp
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rsi,168(${context})	# restore context->Rsi
	mov	%rdi,176(${context})	# restore context->Rdi

.Lcommon_seh_exit:

	mov	40(${disp}),%rdi		# disp->ContextRecord
	mov	${context},%rsi		# context
	mov	$154,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	${disp},%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	$1,%eax		# ExceptionContinueSearch
	add	$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	key_se_handler,.-key_se_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_RC4
	.rva	.LSEH_end_RC4
	.rva	.LSEH_info_RC4

	.rva	.LSEH_begin_RC4_set_key
	.rva	.LSEH_end_RC4_set_key
	.rva	.LSEH_info_RC4_set_key

.section	.xdata
.align	8
.LSEH_info_RC4:
	.byte	9,0,0,0
	.rva	stream_se_handler
.LSEH_info_RC4_set_key:
	.byte	9,0,0,0
	.rva	key_se_handler
`;
}

function regPart(reg: string, conv: string): string {
  if (reg.match(/%r[0-9]+/)) {
    return reg + conv;
  } else if (conv === 'b') {
    return reg.replace(/%[er]([^x]+)x?/, '%$1l');
  } else if (conv === 'w') {
    return reg.replace(/%[er](.+)/, '%$1');
  } else if (conv === 'd') {
    return reg.replace(/%[er](.+)/, '%e$1');
  }
  return reg;
}

code = code.replace(/(%[a-z0-9]+)#([bwd])/g, (match, reg, conv) => {
  return regPart(reg, conv);
});

code = code.replace(/`([^`]*)`/g, (match, expr) => {
  try {
    // Simple evaluation for arithmetic expressions
    return String(eval(expr));
  } catch {
    return match;
  }
});

import { translateAssembly } from 'jsasm/x86_64-xlate';

export default translateAssembly(code);
