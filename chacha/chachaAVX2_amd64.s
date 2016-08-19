// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build go1.7
// +build amd64, !gccgo, !appengine

#include "textflag.h"

DATA rol16<>+0x00(SB)/8, $0x0504070601000302
DATA rol16<>+0x08(SB)/8, $0x0D0C0F0E09080B0A
DATA rol16<>+0x10(SB)/8, $0x0504070601000302
DATA rol16<>+0x18(SB)/8, $0x0D0C0F0E09080B0A
GLOBL rol16<>(SB), (NOPTR+RODATA), $32

DATA rol8<>+0x00(SB)/8, $0x0605040702010003
DATA rol8<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
DATA rol8<>+0x10(SB)/8, $0x0605040702010003
DATA rol8<>+0x18(SB)/8, $0x0E0D0C0F0A09080B
GLOBL rol8<>(SB), (NOPTR+RODATA), $32

DATA one<>+0x00(SB)/8, $0x0
DATA one<>+0x08(SB)/8, $0x0
DATA one<>+0x10(SB)/8, $0x1
DATA one<>+0x18(SB)/8, $0x0
GLOBL one<>(SB), (NOPTR+RODATA), $32

#define ROTL(n, v, t) \
	VPSLLD $n, v, t; \
	VPSRLD $(32-n), v, v; \
	VPXOR v, t, v

#define ROTL_FAST(c, v) \
	VPSHUFB c, v, v

// If src is a mem location, src must contain at least 32 bytes -> see xorBlocksAVX2
// dst must not be a mem location!
#define BROADCASTI128(src, dst) \
	VPERM2I128 $0x22, src, dst, dst		// len(src) < 32 (e.g. state[48]) -> error!

// VPSHUFD $-109 -> See github.com/golang/go/issues/16499
#define SHUFFLE_128(a, b, c) \
	VPSHUFD $0x39, a, a; \
	VPSHUFD $0x4E, b, b; \
	VPSHUFD $-109, c, c

#define SHUFFLE_256(a0, a1, b0, b1, c0, c1) \
	VPSHUFD $0x39, a0, a0; \
	VPSHUFD $0x39, a1, a1; \
	VPSHUFD $0x4E, b0, b0; \
	VPSHUFD $0x4E, b1, b1; \
	VPSHUFD $-109, c0, c0; \
	VPSHUFD $-109, c1, c1

#define HALF_ROUND_128(v0, v1, v2, v3, t0) \
	VPADDD v0, v1, v0; \
	VPXOR v3, v0, v3; \
	ROTL_FAST(rol16<>(SB), v3); \
	VPADDD v2, v3, v2; \
	VPXOR v1, v2, v1; \
	ROTL(12, v1, t0); \
	VPADDD v0, v1, v0; \
	VPXOR v3, v0, v3; \
	ROTL_FAST(rol8<>(SB), v3); \
	VPADDD v2, v3, v2; \
	VPXOR v1, v2, v1; \
	ROTL(7, v1, t0)

#define HALF_ROUND_256(v0, v1, v2, v3, v4, v5, v6, v7, t0) \
	VPADDD v0, v1, v0; \
	VPADDD v4, v5, v4; \
	VPXOR v3, v0, v3; \
	VPXOR v7, v4, v7; \
	ROTL_FAST(rol16<>(SB), v3); \
	ROTL_FAST(rol16<>(SB), v7); \
	VPADDD v2, v3, v2; \
	VPADDD v6, v7, v6; \
	VPXOR v1, v2, v1; \
	VPXOR v5, v6, v5; \
	ROTL(12, v1, t0); \
	ROTL(12, v5, t0); \
	VPADDD v0, v1, v0; \
	VPADDD v4, v5, v4; \
	VPXOR v3, v0, v3; \
	VPXOR v7, v4, v7; \
	ROTL_FAST(rol8<>(SB), v3); \
	ROTL_FAST(rol8<>(SB), v7); \
	VPADDD v2, v3, v2; \
	VPADDD v6, v7, v6; \
	VPXOR v1, v2, v1; \
	VPXOR v5, v6, v5; \
	ROTL(7, v1, t0); \
	ROTL(7, v5, t0)

#define XOR_128(dst, src, off, v0, v1, v2, v3, t0) \
	VPERM2I128 $32, v1, v0, t0; \
	VPXOR (0+off)(src), t0, t0; \
	VMOVDQU t0, (0+off)(dst); \
	VPERM2I128 $32, v3, v2, t0; \
	VPXOR (32+off)(src), t0, t0; \
	VMOVDQU t0, (32+off)(dst); \
	VPERM2I128 $49, v1, v0, t0; \
	VPXOR (64+off)(src), t0, t0; \
	VMOVDQU t0, (64+off)(dst); \
	VPERM2I128 $49, v3, v2, t0; \
	VPXOR (96+off)(src), t0, t0; \
	VMOVDQU t0, (96+off)(dst)

// func xorBlocksAVX2(dst, src []byte, state *[64]byte, rounds int)
TEXT ·xorBlocksAVX2(SB),4,$0-64
	MOVQ state+48(FP), AX
	MOVQ dst_base+0(FP), CX
	MOVQ src_base+24(FP), BX
	MOVQ src_len+32(FP), DX
	MOVQ rounds+56(FP), BP
	ANDQ $0xFFFFFFFFFFFFFFC0, DX	// DX = len(src) - (len(src) % 64)
	
	VMOVDQU one<>(SB), Y0
	VPERM2I128 $0x33, Y0, Y14, Y14 // (1,0,1,0)
	VPADDQ Y14, Y14, Y14	// (2,0,2,0)
	
	BROADCASTI128(0(AX), Y8)
	BROADCASTI128(16(AX), Y9)
	BROADCASTI128(32(AX), Y10)
	VPERM2I128 $0x33, 32(AX), Y11, Y11	// cannot use BROADCASTI128 -> 48(AX) contains only 16 bytes
	VPADDQ Y0, Y11, Y11
	SUBQ $256, DX
	JCS BYTES_BETWEEN_0_AND_255
BYTES_AT_LEAST_256:
		VMOVDQA Y8, Y0
		VMOVDQA Y9, Y1
		VMOVDQA Y10, Y2
		VMOVDQA Y11, Y3
		VMOVDQA Y8, Y4
		VMOVDQA Y9, Y5
		VMOVDQA Y10, Y6
		VPADDQ Y11, Y14, Y7
		MOVQ BP, R9
CHACHA_LOOP_256:
			HALF_ROUND_256(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y12)
			SHUFFLE_256(Y1, Y5, Y2, Y6, Y3, Y7)
			HALF_ROUND_256(Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y12)
			SHUFFLE_256(Y3, Y7, Y2, Y6, Y1, Y5)
			SUBQ $2, R9
			JA CHACHA_LOOP_256
		VPADDD Y0, Y8, Y0
		VPADDD Y1, Y9, Y1
		VPADDD Y2, Y10, Y2
		VPADDD Y3, Y11, Y3
		XOR_128(CX, BX, 0, Y0, Y1, Y2, Y3, Y12)
		VPADDD Y11, Y14, Y11
		VPADDD Y4, Y8, Y4
		VPADDD Y5, Y9, Y5
		VPADDD Y6, Y10, Y6
		VPADDD Y7, Y11, Y7
		XOR_128(CX, BX, 128, Y4, Y5, Y6, Y7, Y12)
		VPADDD Y11, Y14, Y11
		ADDQ $256, BX
		ADDQ $256, CX
		SUBQ $256, DX
		JCC BYTES_AT_LEAST_256
BYTES_BETWEEN_0_AND_255:
	ADDQ $256, DX
	JEQ WRITE_EVEN_64_BLOCKS
BYTES_LESS_THAN_255:
		VMOVDQA Y8, Y0
		VMOVDQA Y9, Y1
		VMOVDQA Y10, Y2
		VMOVDQA Y11, Y3
		MOVQ BP, R9
CHACHA_LOOP_128:
			HALF_ROUND_128(Y0, Y1, Y2, Y3, Y12)
			SHUFFLE_128(Y1, Y2, Y3)
			HALF_ROUND_128(Y0, Y1, Y2, Y3, Y12)
			SHUFFLE_128(Y3, Y2, Y1)
			SUBQ $2, R9
			JA CHACHA_LOOP_128
		VPADDD Y0, Y8, Y0
		VPADDD Y1, Y9, Y1
		VPADDD Y2, Y10, Y2
		VPADDD Y3, Y11, Y3
		
		VPERM2I128 $32, Y1, Y0, Y12
		VPXOR 0(BX), Y12, Y12
		VMOVDQU Y12, 0(CX)
		VPERM2I128 $32, Y3, Y2, Y12
		VPXOR 32(BX), Y12, Y12
		VMOVDQU Y12, 32(CX)
		SUBQ $64, DX
		JEQ WRITE_ODD_64_BLOCKS
		
		VPADDD Y11, Y14, Y11
		VPERM2I128 $49, Y1, Y0, Y12
		VPXOR 64(BX), Y12, Y12
		VMOVDQU Y12, 64(CX)
		VPERM2I128 $49, Y3, Y2, Y12
		VPXOR 96(BX), Y12, Y12
		VMOVDQU Y12, 96(CX)
		SUBQ $64, DX
		JEQ WRITE_EVEN_64_BLOCKS
		
		ADDQ $128, BX
		ADDQ $128, CX
		JMP BYTES_LESS_THAN_255
WRITE_ODD_64_BLOCKS:
	VPERM2I128 $1, Y11, Y11, Y11
WRITE_EVEN_64_BLOCKS:
	VZEROUPPER
	MOVO X11, 48(AX)
	RET

// func supportAVX2() bool
TEXT ·supportAVX2(SB),4,$0-1
	XORQ AX, AX
	MOVQ runtime·support_avx2(SB), AX
	MOVB AX, ret+0(FP)
	RET
