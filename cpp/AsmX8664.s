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
	movq     0(%rdi), %rcx
	movq     8(%rdi), %rdx
	movq    16(%rdi), %r8
	movq    24(%rdi), %r9
	testq   %r9, %r9
	sets    %al
	movzbl  %al, %eax
	shldq   $1, %r8 , %r9
	shldq   $1, %rdx, %r8
	shldq   $1, %rcx, %rdx
	shlq    $1, %rcx
	movq    %rcx,  0(%rdi)
	movq    %rdx,  8(%rdi)
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
