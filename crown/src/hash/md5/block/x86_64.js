/**
 * @file MD5 x86_64 Assembly Code Generator
 * @description Generates optimized x86_64 assembly code for MD5 hash computation.
 * This is a JavaScript port of the original Perl script that generates
 * high-performance assembly implementation of the MD5 algorithm.
 *
 * @author Converted from Perl script by Marc Bevand <bevand_m (at) epita.fr>
 * @copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 * @license Apache License 2.0
 *
 * The generated assembly implements the four rounds of MD5:
 * - Round 1: F(x,y,z) = (x & y) | ((~x) & z)
 * - Round 2: G(x,y,z) = (x & z) | (y & (~z))
 * - Round 3: H(x,y,z) = x ^ y ^ z
 * - Round 4: I(x,y,z) = y ^ (x | (~z))
 *
 * Each round processes 16 steps with different constants and shift amounts
 * for optimal performance on AMD64 architecture.
 */

/**
 * Generates assembly code for MD5 round 1 step
 * Implements: dst = x + ((dst + F(x,y,z) + X[k] + T_i) <<< s)
 * @param {number} pos - Position indicator (-1 for first step, 0 for middle steps, 1 for last step)
 * @param {string} dst - Destination register (e.g., '%eax')
 * @param {string} x - X register (e.g., '%ebx')
 * @param {string} y - Y register (e.g., '%ecx')
 * @param {string} z - Z register (e.g., '%edx')
 * @param {number} k_next - Index for next X[k_next] value (0-15)
 * @param {string} T_i - MD5 constant value in hex format (e.g., '0xd76aa478')
 * @param {number} s - Left rotate shift amount
 * @returns {string} Generated assembly code for the round 1 step
 */
function round1_step(pos, dst, x, y, z, k_next, T_i, s) {
  let result = '';
  if (pos === -1) {
    result += `	mov	0(%rsi),%r10d\n`;
    result += `	mov	%edx,%r11d\n`;
  }
  result += `	xor	${y},%r11d
	lea	${T_i}(${dst.replace('%e', '%r')},%r10,1),${dst}
	and	${x},%r11d
	mov	${k_next * 4}(%rsi),%r10d
	xor	${z},%r11d
	add	%r11d,${dst}
	rol	$${s},${dst}
	mov	${y},%r11d
	add	${x},${dst}
`;
  return result;
}

/**
 * Generates assembly code for MD5 round 2 step
 * Implements: dst = x + ((dst + G(x,y,z) + X[k] + T_i) <<< s)
 * @param {number} pos - Position indicator (-1 for first step, 0 for middle steps, 1 for last step)
 * @param {string} dst - Destination register (e.g., '%eax')
 * @param {string} x - X register (e.g., '%ebx')
 * @param {string} y - Y register (e.g., '%ecx')
 * @param {string} z - Z register (e.g., '%edx')
 * @param {number} k_next - Index for next X[k_next] value (0-15)
 * @param {string} T_i - MD5 constant value in hex format (e.g., '0xf61e2562')
 * @param {number} s - Left rotate shift amount
 * @returns {string} Generated assembly code for the round 2 step
 */
function round2_step(pos, dst, x, y, z, k_next, T_i, s) {
  let result = '';
  if (pos === -1) {
    result += `	mov	%edx,%r11d\n`;
    result += `	mov	%edx,%r12d\n`;
  }
  result += `	not	%r11d
	and	${x},%r12d
	lea	${T_i}(${dst.replace('%e', '%r')},%r10,1),${dst}
	and	${y},%r11d
	mov	${k_next * 4}(%rsi),%r10d
	add	%r11d,${dst}
	mov	${y},%r11d
	add	%r12d,${dst}
	mov	${y},%r12d
	rol	$${s},${dst}
	add	${x},${dst}
`;
  return result;
}

/** @type {number} Alternating flag for round 3 instruction ordering optimization */
let round3_alter = 0;

/**
 * Generates assembly code for MD5 round 3 step
 * Implements: dst = x + ((dst + H(x,y,z) + X[k] + T_i) <<< s)
 * @param {number} pos - Position indicator (-1 for first step, 0 for middle steps, 1 for last step)
 * @param {string} dst - Destination register (e.g., '%eax')
 * @param {string} x - X register (e.g., '%ebx')
 * @param {string} y - Y register (e.g., '%ecx')
 * @param {string} z - Z register (e.g., '%edx')
 * @param {number} k_next - Index for next X[k_next] value (0-15)
 * @param {string} T_i - MD5 constant value in hex format (e.g., '0xfffa3942')
 * @param {number} s - Left rotate shift amount
 * @returns {string} Generated assembly code for the round 3 step
 */
function round3_step(pos, dst, x, y, z, k_next, T_i, s) {
  let result = '';
  if (pos === -1) {
    result += `	mov	%ecx,%r11d\n`;
  }
  result += `	lea	${T_i}(${dst.replace('%e', '%r')},%r10,1),${dst}
 xor	${z},%r11d
	mov	${k_next * 4}(%rsi),%r10d
	xor	${x},%r11d
	add	%r11d,${dst}
`;
  if (round3_alter) {
    result += `	rol	$${s},${dst}
	mov	${x},%r11d
`;
  } else {
    result += `	mov	${x},%r11d
	rol	$${s},${dst}
`;
  }
  result += `	add	${x},${dst}
`;
  round3_alter ^= 1;
  return result;
}

/**
 * Generates assembly code for MD5 round 4 step
 * Implements: dst = x + ((dst + I(x,y,z) + X[k] + T_i) <<< s)
 * @param {number} pos - Position indicator (-1 for first step, 0 for middle steps, 1 for last step)
 * @param {string} dst - Destination register (e.g., '%eax')
 * @param {string} x - X register (e.g., '%ebx')
 * @param {string} y - Y register (e.g., '%ecx')
 * @param {string} z - Z register (e.g., '%edx')
 * @param {number} k_next - Index for next X[k_next] value (0-15)
 * @param {string} T_i - MD5 constant value in hex format (e.g., '0xf4292244')
 * @param {number} s - Left rotate shift amount
 * @returns {string} Generated assembly code for the round 4 step
 */
function round4_step(pos, dst, x, y, z, k_next, T_i, s) {
  let result = '';
  if (pos === -1) {
    result += `	mov	$0xffffffff,%r11d\n`;
    result += `	xor	%edx,%r11d\n`;
  }
  result += `	lea	${T_i}(${dst.replace('%e', '%r')},%r10,1),${dst}
	orl	${x},%r11d
	mov	${k_next * 4}(%rsi),%r10d
	xor	${y},%r11d
	add	%r11d,${dst}
	mov	$0xffffffff,%r11d
	rol	$${s},${dst}
	xor	${y},%r11d
	add	${x},${dst}
`;
  return result;
}

/** @type {string} Generated assembly code buffer */
let code = '';

code += `.text
.align	16

.globl	ossl_md5_block_asm_data_order
.type	ossl_md5_block_asm_data_order,@function
ossl_md5_block_asm_data_order:
.cfi_startproc
	pushq	%rbp
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbp,-16
	pushq	%rbx
.cfi_adjust_cfa_offset	8
.cfi_offset	%rbx,-24
	pushq	%r12
.cfi_adjust_cfa_offset	8
.cfi_offset	%r12,-32
	pushq	%r14
.cfi_adjust_cfa_offset	8
.cfi_offset	%r14,-40
	pushq	%r15
.cfi_adjust_cfa_offset	8
.cfi_offset	%r15,-48
.Lprologue:



	mov	%rdi,%rbp
	shl	$6,%rdx
	lea	(%rsi,%rdx,1),%rdi
	mov	0(%rbp),%eax
	mov	4(%rbp),%ebx
	mov	8(%rbp),%ecx
	mov	12(%rbp),%edx




	cmp	%rdi,%rsi
	je	.Lend


.Lloop:
	mov	%eax,%r8d
	mov	%ebx,%r9d
	mov	%ecx,%r14d
	mov	%edx,%r15d
`;

code += round1_step(-1, '%eax', '%ebx', '%ecx', '%edx', 1, -680876936, 7);
code += round1_step(0, '%edx', '%eax', '%ebx', '%ecx', 2, -389564586, 12);
code += round1_step(0, '%ecx', '%edx', '%eax', '%ebx', 3, 606105819, 17);
code += round1_step(0, '%ebx', '%ecx', '%edx', '%eax', 4, -1044525330, 22);
code += round1_step(0, '%eax', '%ebx', '%ecx', '%edx', 5, -176418897, 7);
code += round1_step(0, '%edx', '%eax', '%ebx', '%ecx', 6, 1200080426, 12);
code += round1_step(0, '%ecx', '%edx', '%eax', '%ebx', 7, -1473231341, 17);
code += round1_step(0, '%ebx', '%ecx', '%edx', '%eax', 8, -45705983, 22);
code += round1_step(0, '%eax', '%ebx', '%ecx', '%edx', 9, 1770035416, 7);
code += round1_step(0, '%edx', '%eax', '%ebx', '%ecx', 10, -1958414417, 12);
code += round1_step(0, '%ecx', '%edx', '%eax', '%ebx', 11, -42063, 17);
code += round1_step(0, '%ebx', '%ecx', '%edx', '%eax', 12, -1990404162, 22);
code += round1_step(0, '%eax', '%ebx', '%ecx', '%edx', 13, 1804603682, 7);
code += round1_step(0, '%edx', '%eax', '%ebx', '%ecx', 14, -40341101, 12);
code += round1_step(0, '%ecx', '%edx', '%eax', '%ebx', 15, -1502002290, 17);
code += round1_step(1, '%ebx', '%ecx', '%edx', '%eax', 1, 1236535329, 22);

code += round2_step(-1, '%eax', '%ebx', '%ecx', '%edx', 6, -165796510, 5);
code += round2_step(0, '%edx', '%eax', '%ebx', '%ecx', 11, -1069501632, 9);
code += round2_step(0, '%ecx', '%edx', '%eax', '%ebx', 0, 643717713, 14);
code += round2_step(0, '%ebx', '%ecx', '%edx', '%eax', 5, -373897302, 20);
code += round2_step(0, '%eax', '%ebx', '%ecx', '%edx', 10, -701558691, 5);
code += round2_step(0, '%edx', '%eax', '%ebx', '%ecx', 15, 38016083, 9);
code += round2_step(0, '%ecx', '%edx', '%eax', '%ebx', 4, -660478335, 14);
code += round2_step(0, '%ebx', '%ecx', '%edx', '%eax', 9, -405537848, 20);
code += round2_step(0, '%eax', '%ebx', '%ecx', '%edx', 14, 568446438, 5);
code += round2_step(0, '%edx', '%eax', '%ebx', '%ecx', 3, -1019803690, 9);
code += round2_step(0, '%ecx', '%edx', '%eax', '%ebx', 8, -187363961, 14);
code += round2_step(0, '%ebx', '%ecx', '%edx', '%eax', 13, 1163531501, 20);
code += round2_step(0, '%eax', '%ebx', '%ecx', '%edx', 2, -1444681467, 5);
code += round2_step(0, '%edx', '%eax', '%ebx', '%ecx', 7, -51403784, 9);
code += round2_step(0, '%ecx', '%edx', '%eax', '%ebx', 12, 1735328473, 14);
code += round2_step(1, '%ebx', '%ecx', '%edx', '%eax', 5, -1926607734, 20);

code += round3_step(-1, '%eax', '%ebx', '%ecx', '%edx', 8, -378558, 4);
code += round3_step(0, '%edx', '%eax', '%ebx', '%ecx', 11, -2022574463, 11);
code += round3_step(0, '%ecx', '%edx', '%eax', '%ebx', 14, 1839030562, 16);
code += round3_step(0, '%ebx', '%ecx', '%edx', '%eax', 1, -35309556, 23);
code += round3_step(0, '%eax', '%ebx', '%ecx', '%edx', 4, -1530992060, 4);
code += round3_step(0, '%edx', '%eax', '%ebx', '%ecx', 7, 1272893353, 11);
code += round3_step(0, '%ecx', '%edx', '%eax', '%ebx', 10, -155497632, 16);
code += round3_step(0, '%ebx', '%ecx', '%edx', '%eax', 13, -1094730640, 23);
code += round3_step(0, '%eax', '%ebx', '%ecx', '%edx', 0, 681279174, 4);
code += round3_step(0, '%edx', '%eax', '%ebx', '%ecx', 3, -358537222, 11);
code += round3_step(0, '%ecx', '%edx', '%eax', '%ebx', 6, -722521979, 16);
code += round3_step(0, '%ebx', '%ecx', '%edx', '%eax', 9, 76029189, 23);
code += round3_step(0, '%eax', '%ebx', '%ecx', '%edx', 12, -640364487, 4);
code += round3_step(0, '%edx', '%eax', '%ebx', '%ecx', 15, -421815835, 11);
code += round3_step(0, '%ecx', '%edx', '%eax', '%ebx', 2, 530742520, 16);
code += round3_step(1, '%ebx', '%ecx', '%edx', '%eax', 0, -995338651, 23);

code += round4_step(-1, '%eax', '%ebx', '%ecx', '%edx', 7, -198630844, 6);
code += round4_step(0, '%edx', '%eax', '%ebx', '%ecx', 14, 1126891415, 10);
code += round4_step(0, '%ecx', '%edx', '%eax', '%ebx', 5, -1416354905, 15);
code += round4_step(0, '%ebx', '%ecx', '%edx', '%eax', 12, -57434055, 21);
code += round4_step(0, '%eax', '%ebx', '%ecx', '%edx', 3, 1700485571, 6);
code += round4_step(0, '%edx', '%eax', '%ebx', '%ecx', 10, -1894986606, 10);
code += round4_step(0, '%ecx', '%edx', '%eax', '%ebx', 1, -1051523, 15);
code += round4_step(0, '%ebx', '%ecx', '%edx', '%eax', 8, -2054922799, 21);
code += round4_step(0, '%eax', '%ebx', '%ecx', '%edx', 15, 1873313359, 6);
code += round4_step(0, '%edx', '%eax', '%ebx', '%ecx', 6, -30611744, 10);
code += round4_step(0, '%ecx', '%edx', '%eax', '%ebx', 13, -1560198380, 15);
code += round4_step(0, '%ebx', '%ecx', '%edx', '%eax', 4, 1309151649, 21);
code += round4_step(0, '%eax', '%ebx', '%ecx', '%edx', 11, -145523070, 6);
code += round4_step(0, '%edx', '%eax', '%ebx', '%ecx', 2, -1120210379, 10);
code += round4_step(0, '%ecx', '%edx', '%eax', '%ebx', 9, 718787259, 15);
code += round4_step(1, '%ebx', '%ecx', '%edx', '%eax', 0, -343485551, 21);

code += `
	add	%r8d,%eax
	add	%r9d,%ebx
	add	%r14d,%ecx
	add	%r15d,%edx


	add	$64,%rsi
	cmp	%rdi,%rsi
	jb	.Lloop


.Lend:
	mov	%eax,0(%rbp)
	mov	%ebx,4(%rbp)
	mov	%ecx,8(%rbp)
	mov	%edx,12(%rbp)

	mov	(%rsp),%r15
.cfi_restore	%r15
	mov	8(%rsp),%r14
.cfi_restore	%r14
	mov	16(%rsp),%r12
.cfi_restore	%r12
	mov	24(%rsp),%rbx
.cfi_restore	%rbx
	mov	32(%rsp),%rbp
.cfi_restore	%rbp
	add	$40,%rsp
.cfi_adjust_cfa_offset	-40
.Lepilogue:
	.byte	0xf3,0xc3
.cfi_endproc
.size	ossl_md5_block_asm_data_order,.-ossl_md5_block_asm_data_order
	.section ".note.gnu.property", "a"
	.p2align 3
	.long 1f - 0f
	.long 4f - 1f
	.long 5
0:
	# "GNU" encoded with .byte, since .asciz isn't supported
	# on Solaris.
	.byte 0x47
	.byte 0x4e
	.byte 0x55
	.byte 0
1:
	.p2align 3
	.long 0xc0000002
	.long 3f - 2f
2:
	.long 3
3:
	.p2align 3
4:
`;

code;
