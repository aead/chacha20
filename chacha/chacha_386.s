// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386, !gccgo, !appengine

#include "textflag.h"

DATA constants<>+0x00(SB)/4, $0x61707865
DATA constants<>+0x04(SB)/4, $0x3320646e
DATA constants<>+0x08(SB)/4, $0x79622d32
DATA constants<>+0x0c(SB)/4, $0x6b206574
GLOBL constants<>(SB), (NOPTR+RODATA), $16

DATA one<>+0x00(SB)/8, $1
DATA one<>+0x08(SB)/8, $0
GLOBL one<>(SB), (NOPTR+RODATA), $16

DATA rol16<>+0x00(SB)/8, $0x0504070601000302
DATA rol16<>+0x08(SB)/8, $0x0D0C0F0E09080B0A
GLOBL rol16<>(SB), (NOPTR+RODATA), $16

DATA rol8<>+0x00(SB)/8, $0x0605040702010003
DATA rol8<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
GLOBL rol8<>(SB), (NOPTR+RODATA), $16

#define ROTL_SSE2(n, t, v) \
 	MOVAPD v, t; \
	PSLLL $n, t; \
	PSRLL $(32-n), v; \
	PXOR t, v

#define ROTL_SSSE3(c, v) \
	PSHUFB c, v

#define SHUFFLE_64(a, b, c) \
	PSHUFL $0x39, a, a; \
	PSHUFL $0x4E, b, b; \
	PSHUFL $0x93, c, c

#define HALF_ROUND_64_SSE2(v0 , v1 , v2 , v3 , t0) \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL_SSE2(16, t0, v3); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL_SSE2(12, t0, v1); \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL_SSE2(8, t0, v3); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL_SSE2(7, t0, v1)

#define HALF_ROUND_64_SSSE3(v0 , v1 , v2 , v3 , t0, c16, c8) \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL_SSSE3(c16, v3); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL_SSE2(12, t0, v1); \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL_SSSE3(c8, v3); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL_SSE2(7, t0, v1)

// func coreSSE2(dst *[64]byte, state *[16]uint32, rounds int)
TEXT ·coreSSE2(SB),4,$0-12
	MOVL state+4(FP), SI
	MOVL dst+0(FP), DI
	MOVL rounds+8(FP), CX
	MOVOU 0(SI), X0
	MOVOU 16(SI), X1
	MOVOU 32(SI), X2
	MOVOU 48(SI), X3
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	loop:
		HALF_ROUND_64_SSE2(X4, X5, X6, X7, X0)
		SHUFFLE_64(X5, X6, X7)
		HALF_ROUND_64_SSE2(X4, X5, X6, X7, X0)
		SHUFFLE_64(X7, X6, X5)
		SUBL $2, CX
		JA loop
    MOVOU 0(SI), X0
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
    MOVOU one<>(SB), X1
	PADDL X1, X3
	MOVOU X4, 0(DI)
	MOVOU X5, 16(DI)
	MOVOU X6, 32(DI)
	MOVOU X7, 48(DI)
	MOVOU X3, 48(SI)
	RET

// func coreSSSE3(dst *[64]byte, state *[64]byte, rounds int)
TEXT ·coreSSSE3(SB),4,$0-12
	MOVL state+4(FP), SI
	MOVL dst+0(FP), DI
	MOVL rounds+8(FP), CX
	MOVOU 0(SI), X4
	MOVOU 16(SI), X5
	MOVOU 32(SI), X6
	MOVOU 48(SI), X7
	MOVOU rol16<>(SB), X1
    MOVOU rol8<>(SB), X2
	loop:
		HALF_ROUND_64_SSSE3(X4, X5, X6, X7, X0, X1, X2)
		SHUFFLE_64(X5, X6, X7)
		HALF_ROUND_64_SSSE3(X4, X5, X6, X7, X0, X1, X2)
		SHUFFLE_64(X7, X6, X5)
		SUBL $2, CX
		JA loop
    MOVOU 0(SI), X0
    MOVOU 16(SI), X1
    MOVOU 32(SI), X2
    MOVOU 48(SI), X3
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
    MOVOU one<>(SB), X1
	PADDL X1, X3
	MOVOU X4, 0(DI)
	MOVOU X5, 16(DI)
	MOVOU X6, 32(DI)
	MOVOU X7, 48(DI)
	MOVOU X3, 48(SI)
	RET

// func setState(state *[64]byte, key *[32]byte, nonce *[12]byte, counter uint32)
TEXT ·setState(SB),4,$0-16
	MOVL state+0(FP), AX
	MOVL key+4(FP), BX
	MOVL nonce+8(FP), CX
	MOVL counter+12(FP), DX
	
	MOVOU constants<>(SB), X0
	MOVOU 0(BX), X1
	MOVOU 16(BX), X2
	MOVL 0(CX), BP
	MOVL 4(CX), SI
    MOVL 8(CX), DI
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	MOVOU X2, 32(AX)
	MOVL DX, 48(AX)
	MOVL BP, 52(AX)
	MOVL SI, 56(AX)
    MOVL DI, 60(AX)
	RET

// func supportSSE2() bool
TEXT ·supportSSE2(SB),4,$0-1
	XORL DX, DX
	MOVL $1, AX
	CPUID
    XORL AX, AX
	ANDL $(1<<26), DX	    // DX != 0 if support SSE2
    SHRL $26, DX
	MOVB DX, ret+0(FP)
	RET

// func supportSSSE3() bool
TEXT ·supportSSSE3(SB),4,$0-1
	XORL CX, CX
	MOVL $1, AX
	CPUID
	MOVL CX, BX
	ANDL $0x1, BX	// BX != 0 if support SSE3
	CMPL BX, $0
	JE FALSE
	ANDL $0x200, CX // CX != 0 if support SSSE3
	CMPL CX, $0
	JE FALSE
	MOVB $1, ret+0(FP)
	JMP DONE
FALSE:
	MOVB $0, ret+0(FP)
DONE:
	RET
