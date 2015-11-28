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
	cmovzq  %rdx, %rax
	movq    8(%rdi), %rdx
	cmovzq  %rdx, %rcx
	movq    16(%rdi), %rdx
	cmovzq  %rdx, %r8
	movq    24(%rdi), %rdx
	cmovzq  %rdx, %r9
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
