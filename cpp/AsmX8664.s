/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */


/* uint32_t asm_Uint256_add(uint32_t dest[8], const uint32_t src[8], uint32_t enable) */
.globl asm_Uint256_add
asm_Uint256_add:
	negq    %rdx
	movq     0(%rsi), %rax
	movq     8(%rsi), %rcx
	movq    16(%rsi), %r8
	movq    24(%rsi), %r9
	andq    %rdx, %rax
	andq    %rdx, %rcx
	andq    %rdx, %r8
	andq    %rdx, %r9
	addq    %rax,  0(%rdi)
	adcq    %rcx,  8(%rdi)
	adcq    %r8 , 16(%rdi)
	adcq    %r9 , 24(%rdi)
	setc    %al
	movzbl  %al, %eax
	retq


/* uint32_t asm_Uint256_subtract(uint32_t dest[8], const uint32_t src[8], uint32_t enable) */
.globl asm_Uint256_subtract
asm_Uint256_subtract:
	negq    %rdx
	movq     0(%rsi), %rax
	movq     8(%rsi), %rcx
	movq    16(%rsi), %r8
	movq    24(%rsi), %r9
	andq    %rdx, %rax
	andq    %rdx, %rcx
	andq    %rdx, %r8
	andq    %rdx, %r9
	subq    %rax,  0(%rdi)
	sbbq    %rcx,  8(%rdi)
	sbbq    %r8 , 16(%rdi)
	sbbq    %r9 , 24(%rdi)
	setc    %al
	movzbl  %al, %eax
	retq


/* uint32_t asm_Uint256_shiftLeft1(uint32_t dest[8]) */
.globl asm_Uint256_shiftLeft1
asm_Uint256_shiftLeft1:
	shlq    $1,  0(%rdi)
	rclq    $1,  8(%rdi)
	rclq    $1, 16(%rdi)
	rclq    $1, 24(%rdi)
	setc    %al
	movzbl  %al, %eax
	retq


/* void asm_Uint256_shiftRight1(uint32_t dest[8], uint32_t enable); */
.globl asm_Uint256_shiftRight1
asm_Uint256_shiftRight1:
	movq     0(%rdi), %rax
	movq     8(%rdi), %rcx
	movq    16(%rdi), %r8
	movq    24(%rdi), %r9
	shrq    $1, %r9
	rcrq    $1, %r8
	rcrq    $1, %rcx
	rcrq    $1, %rax
	testl   %esi, %esi
	movq    0(%rdi), %rdx
	movq    8(%rdi), %rsi
	cmovzq  %rdx, %rax
	cmovzq  %rsi, %rcx
	movq    16(%rdi), %rdx
	movq    24(%rdi), %rsi
	cmovzq  %rdx, %r8
	cmovzq  %rsi, %r9
	movq    %rax,  0(%rdi)
	movq    %rcx,  8(%rdi)
	movq    %r8 , 16(%rdi)
	movq    %r9 , 24(%rdi)
	retq


/* void asm_Uint256_replace(uint32_t dest[8], const uint32_t src[8], uint32_t enable) */
.globl asm_Uint256_replace
asm_Uint256_replace:
	testl   %edx, %edx
	movq     0(%rsi), %rax
	movq     0(%rdi), %rcx
	movq     8(%rsi), %r8
	movq     8(%rdi), %r9
	cmovzq  %rcx, %rax
	cmovzq  %r9 , %r8
	movq    %rax,  0(%rdi)
	movq    %r8 ,  8(%rdi)
	movq    16(%rsi), %rax
	movq    16(%rdi), %rcx
	movq    24(%rsi), %r8
	movq    24(%rdi), %r9
	cmovzq  %rcx, %rax
	cmovzq  %r9 , %r8
	movq    %rax, 16(%rdi)
	movq    %r8 , 24(%rdi)
	retq


/* void asm_Uint256_swap(uint32_t left[8], uint32_t right[8], uint32_t enable) */
.globl asm_Uint256_swap
asm_Uint256_swap:
	pushq  %rbx
	negq   %rdx
	movq   0(%rdi), %rax
	movq   8(%rdi), %rcx
	movq   0(%rsi), %r8
	movq   8(%rsi), %r9
	movq   %rax, %rbx
	xorq   %r8, %rbx
	andq   %rdx, %rbx
	xorq   %rbx, %rax
	xorq   %rbx, %r8
	movq   %rax, 0(%rdi)
	movq   %r8, 0(%rsi)
	movq   %rcx, %rbx
	xorq   %r9, %rbx
	andq   %rdx, %rbx
	xorq   %rbx, %rcx
	xorq   %rbx, %r9
	movq   %rcx, 8(%rdi)
	movq   %r9, 8(%rsi)
	movq   16(%rdi), %rax
	movq   24(%rdi), %rcx
	movq   16(%rsi), %r8
	movq   24(%rsi), %r9
	movq   %rax, %rbx
	xorq   %r8, %rbx
	andq   %rdx, %rbx
	xorq   %rbx, %rax
	xorq   %rbx, %r8
	movq   %rax, 16(%rdi)
	movq   %r8, 16(%rsi)
	movq   %rcx, %rbx
	xorq   %r9, %rbx
	andq   %rdx, %rbx
	xorq   %rbx, %rcx
	xorq   %rbx, %r9
	movq   %rcx, 24(%rdi)
	movq   %r9, 24(%rsi)
	popq   %rbx
	retq


/* bool asm_Uint256_equalTo(const uint32_t left[8], const uint32_t right[8]) */
.globl asm_Uint256_equalTo
asm_Uint256_equalTo:
	movq      0(%rdi), %rcx
	movq      8(%rdi), %rdx
	movq     16(%rdi), %r8
	movq     24(%rdi), %r9
	movl     $1, %eax
	xorl     %edi, %edi
	cmpq     0(%rsi), %rcx
	cmovnel  %edi, %eax
	cmpq     8(%rsi), %rdx
	cmovnel  %edi, %eax
	cmpq     16(%rsi), %r8
	cmovnel  %edi, %eax
	cmpq     24(%rsi), %r9
	cmovnel  %edi, %eax
	retq


/* bool asm_Uint256_lessThan(const uint32_t left[8], const uint32_t right[8]) */
.globl asm_Uint256_lessThan
asm_Uint256_lessThan:
	movq     0(%rdi), %rcx
	movq     8(%rdi), %rdx
	movq    16(%rdi), %r8
	movq    24(%rdi), %r9
	xorl    %edi, %edi
	cmpq    0(%rsi), %rcx
	movl    $1, %ecx
	setb    %al
	movzbl  %al, %eax
	cmpq    8(%rsi), %rdx
	cmovbl  %ecx, %eax
	cmoval  %edi, %eax
	cmpq    16(%rsi), %r8
	cmovbl  %ecx, %eax
	cmoval  %edi, %eax
	cmpq    24(%rsi), %r9
	cmovbl  %ecx, %eax
	cmoval  %edi, %eax
	retq


/* void asm_FieldInt_multiply256x256eq512(uint32_t z[16], const uint32_t x[8], const uint32_t y[8]) */
.globl asm_FieldInt_multiply256x256eq512
asm_FieldInt_multiply256x256eq512:
	pushq   %r10
	pushq   %r11
	
	movl    $0, %ecx
.zeroize:
	movq    $0, (%rdi,%rcx)
	addl    $8, %ecx
	cmpl    $64, %ecx
	jb      .zeroize
	
	movq    %rdx, %rcx
	movl    $0, %r9d
.outer:
	movl    $0, %r10d
	movl    %r9d, %r11d
	movq    $0, %r8
	
.inner0:
	movq    (%rsi,%r9), %rax
	mulq    (%rcx,%r10)
	addq    %r8, %rax
	adcq    $0, %rdx
	addq    %rax, (%rdi,%r11)
	adcq    $0, %rdx
	movq    %rdx, %r8
	addl    $8, %r10d
	addl    $8, %r11d
	cmpl    $32, %r10d
	jb      .inner0
	
.inner1:
	addq    %r8, (%rdi,%r11)
	setc    %r8b
	movzbl  %r8b, %r8d
	addl    $8, %r11d
	cmpl    $64, %r11d
	jb      .inner1
	
	addl    $8, %r9d
	cmpl    $32, %r9d
	jb      .outer
	
	popq    %r11
	popq    %r10
	retq


/* void asm_FieldInt_multiplyBarrettStep0(uint32_t dest[24], const uint32_t src[16]) */
.globl asm_FieldInt_multiplyBarrettStep0
asm_FieldInt_multiplyBarrettStep0:
	movq     0(%rsi), %rax
	movq     8(%rsi), %rdx
	movq    16(%rsi), %r8
	movq    24(%rsi), %r9
	movq    %rax, 32(%rdi)
	movq    %rdx, 40(%rdi)
	movq    %r8 , 48(%rdi)
	movq    %r9 , 56(%rdi)
	movq    32(%rsi), %rax
	movq    40(%rsi), %rdx
	movq    48(%rsi), %r8
	movq    56(%rsi), %r9
	movq    %rax, 64(%rdi)
	movq    %rdx, 72(%rdi)
	movq    %r8 , 80(%rdi)
	movq    %r9 , 88(%rdi)
	
	movl    0(%rsi), %eax
	movl    $0, 0(%rdi)
	movl    %eax, 4(%rdi)
	movq     4(%rsi), %rax
	movq    12(%rsi), %rcx
	movq    20(%rsi), %rdx
	movq    %rax,  8(%rdi)
	movq    %rcx, 16(%rdi)
	movq    %rdx, 24(%rdi)
	
	movq    28(%rsi), %rax
	addq    %rax, 32(%rdi)
	movq    36(%rsi), %rax
	adcq    %rax, 40(%rdi)
	movq    44(%rsi), %rax
	adcq    %rax, 48(%rdi)
	movq    52(%rsi), %rax
	adcq    %rax, 56(%rdi)
	
	movl    60(%rsi), %eax
	adcq    %rax, 64(%rdi)
	adcq    $0, 72(%rdi)
	adcq    $0, 80(%rdi)
	adcq    $0, 88(%rdi)
	
	movl    $0, %ecx
	movq    $0, %r8
.loop0:
	movl    $0x3D1, %eax
	mulq    (%rsi,%rcx)
	addq    %r8, %rax
	adcq    $0, %rdx
	addq    %rax, (%rdi,%rcx)
	adcq    $0, %rdx
	movq    %rdx, %r8
	addl    $8, %ecx
	cmpl    $64, %ecx
	jb      .loop0
	
	addq    %r8, 64(%rdi)
	adcq    $0, 72(%rdi)
	adcq    $0, 80(%rdi)
	adcq    $0, 88(%rdi)
	retq


/* void asm_FieldInt_multiplyBarrettStep1(uint32_t dest[16], const uint32_t src[8]) */
.globl asm_FieldInt_multiplyBarrettStep1
asm_FieldInt_multiplyBarrettStep1:
	movq     0(%rsi), %rax
	movq     8(%rsi), %rcx
	movq    16(%rsi), %r8
	movq    24(%rsi), %r9
	movq    %rax, 32(%rdi)
	movq    %rcx, 40(%rdi)
	movq    %r8 , 48(%rdi)
	movq    %r9 , 56(%rdi)
	
	movl    0(%rsi), %eax
	shlq    $32, %rax
	negq    %rax
	movq    %rax, 0(%rdi)
	movl    $0, %eax
	sbbq    4(%rsi), %rax
	movq    %rax, 8(%rdi)
	movl    $0, %eax
	sbbq    12(%rsi), %rax
	movq    %rax, 16(%rdi)
	movl    $0, %eax
	sbbq    20(%rsi), %rax
	movq    %rax, 24(%rdi)
	movl    28(%rsi), %eax
	sbbq    %rax, 32(%rdi)
	sbbq    $0, 40(%rdi)
	sbbq    $0, 48(%rdi)
	sbbq    $0, 56(%rdi)
	
	movl    $0, %ecx
	movq    $0, %r8
	movl    $0, %r9d
.loop1:
	movl    $0x3D1, %eax
	mulq    (%rsi,%rcx)
	addq    %r8, %rax
	adcq    $0, %rdx
	negl    %r9d
	sbbq    %rax, (%rdi,%rcx)
	movl    $0, %r9d
	sbbl    $0, %r9d
	movq    %rdx, %r8
	addl    $8, %ecx
	cmpl    $32, %ecx
	jb      .loop1
	
	negl    %r9d
	sbbq    %r8, 32(%rdi)
	sbbq    $0, 40(%rdi)
	sbbq    $0, 48(%rdi)
	sbbq    $0, 56(%rdi)
	retq


/* void asm_FieldInt_multiplyBarrettStep2(uint32_t z[9], const uint32_t x[16], const uint32_t y[16]) */
.globl asm_FieldInt_multiplyBarrettStep2
asm_FieldInt_multiplyBarrettStep2:
	movq  0(%rsi), %rax
	subq  0(%rdx), %rax
	movq  %rax, 0(%rdi)
	movq  8(%rsi), %rax
	sbbq  8(%rdx), %rax
	movq  %rax, 8(%rdi)
	movq  16(%rsi), %rax
	sbbq  16(%rdx), %rax
	movq  %rax, 16(%rdi)
	movq  24(%rsi), %rax
	sbbq  24(%rdx), %rax
	movq  %rax, 24(%rdi)
	movl  32(%rsi), %eax
	sbbl  32(%rdx), %eax
	movl  %eax, 32(%rdi)
	retq
