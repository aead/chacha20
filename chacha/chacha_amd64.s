// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

#define ROTL32(n, v , t) \
 	MOVO v, t; \
	PSLLL $n, t; \
	PSRLL $(32-n), v; \
	PXOR t, v

#define HALF_ROUND_64B(v0 , v1 , v2 , v3 , t0) \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL32(16, v3, t0); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL32(12, v1, t0); \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL32(8, v3, t0); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL32(7, v1, t0); \

#define ROUND_64B(v0 , v1 , v2 , v3 , t0) \
	HALF_ROUND_64B(v0, v1, v2, v3, t0); \
	PSHUFL $57, v1, v1; \
	PSHUFL $78, v2, v2; \
	PSHUFL $147, v3, v3; \
	HALF_ROUND_64B(v0, v1, v2, v3, t0); \
	PSHUFL $147, v1, v1; \
	PSHUFL $78, v2, v2; \
	PSHUFL $57, v3, v3

#define HALF_ROUND_128B(v0, v1, v2, v3, v4, v5, v6, v7, t0) \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	ROTL32(16, v3, t0); \
	ROTL32(16, v7, t0); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	ROTL32(12, v1, t0); \
	ROTL32(12, v5, t0); \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	ROTL32(8, v3, t0); \
	ROTL32(8, v7, t0); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	ROTL32(7, v1, t0); \
	ROTL32(7, v5, t0); \

#define ROUND_128B(v0, v1, v2, v3, v4, v5, v6, v7, t0) \
	HALF_ROUND_128B(v0, v1, v2, v3, v4, v5, v6, v7, t0); \
	PSHUFL $57, v1, v1; \
	PSHUFL $57, v5, v5; \
	PSHUFL $78, v2, v2; \
	PSHUFL $78, v6, v6; \
	PSHUFL $147, v3, v3; \
	PSHUFL $147, v7, v7; \
	HALF_ROUND_128B(v0, v1, v2, v3, v4, v5, v6, v7, t0); \
	PSHUFL $147, v1, v1; \
	PSHUFL $147, v5, v5; \
	PSHUFL $78, v2, v2; \
	PSHUFL $78, v6, v6; \
	PSHUFL $57, v3, v3; \
	PSHUFL $57, v7, v7

#define HALF_ROUND_256B(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, t0) \
	PADDL v1, v0; \ 
	PADDL v5, v4; \
	PADDL v9, v8; \ 
	PADDL v13, v12; \ 
	PXOR v0, v3; \ 
	PXOR v4, v7; \ 
	PXOR v8, v11; \ 
	PXOR v12, v15; \ 
	MOVO v12, t0; \ 
	ROTL32(16, v3, v12); \
	ROTL32(16, v7, v12); \
	ROTL32(16, v11, v12); \
	ROTL32(16, v15, v12); \
	PADDL v3, v2; \ 
	PADDL v7, v6; \ 
	PADDL v11, v10; \ 
	PADDL v15, v14; \ 
	PXOR v2, v1; \ 
	PXOR v6, v5; \ 
	PXOR v10, v9; \ 
	PXOR v14, v13; \ 
	ROTL32(12, v1, v12); \
	ROTL32(12, v5, v12); \
	ROTL32(12, v9, v12); \
	ROTL32(12, v13, v12); \
	MOVO t0, v12; \ 
	PADDL v1, v0; \ 
	PADDL v5, v4; \ 
	PADDL v9, v8; \ 
	PADDL v13, v12; \ 
	PXOR v0, v3; \ 
	PXOR v4, v7; \ 
	PXOR v8, v11; \ 
	PXOR v12, v15; \ 
	MOVO v12, 16(SP); \ 
	ROTL32(8, v3, v12); \
	ROTL32(8, v7, v12); \
	ROTL32(8, v11, v12); \
	ROTL32(8, v15, v12); \
	PADDL v3, v2; \ 
	PADDL v7, v6; \ 
	PADDL v11, v10; \ 
	PADDL v15, v14; \ 
	PXOR v2, v1; \ 
	PXOR v6, v5; \ 
	PXOR v10, v9; \ 
	PXOR v14, v13; \ 
	ROTL32(7, v1, v12); \
	ROTL32(7, v5, v12); \
	ROTL32(7, v9, v12); \
	ROTL32(7, v13, v12); \
	
#define ROUND_256B(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, t0) \
	HALF_ROUND_256B(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, t0); \
	PSHUFL $57, v1, v1; \ 
	PSHUFL $57, v5, v5; \ 
	PSHUFL $57, v9, v9; \ 
	PSHUFL $57, v13, v13; \ 
	PSHUFL $78, v2, v2; \ 
	PSHUFL $78, v6, v6; \ 
	PSHUFL $78, v10, v10; \ 
	PSHUFL $78, v14, v14; \ 
	PSHUFL $147, v3, v3; \ 
	PSHUFL $147, v7, v7; \ 
	PSHUFL $147, v11, v11; \ 
	PSHUFL $147, v15, v15; \ 
	MOVO t0, v12; \ 
	HALF_ROUND_256B(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, t0); \
	PSHUFL $147, v1, v1; \ 
	PSHUFL $147, v5, v5; \ 
	PSHUFL $147, v9, v9; \ 
	PSHUFL $147, v13, v13; \ 
	PSHUFL $78, v2, v2; \ 
	PSHUFL $78, v6, v6; \ 
	PSHUFL $78, v10, v10; \ 
	PSHUFL $78, v14, v14; \ 
	PSHUFL $57, v3, v3; \ 
	PSHUFL $57, v7, v7; \ 
	PSHUFL $57, v11, v11; \ 
	PSHUFL $57, v15, v15; \ 
	MOVO t0, v12
	
#define XOR_64B(dst, src, off, v0 , v1 , v2 , v3 , t0) \
	MOVOU 0+off(src), t0; \
	PXOR v0, t0; \
	MOVOU t0, 0+off(dst); \
	MOVOU 16+off(src), t0; \
	PXOR v1, t0; \
	MOVOU t0, 16+off(dst); \
	MOVOU 32+off(src), t0; \
	PXOR v2, t0; \
	MOVOU t0, 32+off(dst); \
	MOVOU 48+off(src), t0; \
	PXOR v3, t0; \
	MOVOU t0, 48+off(dst)

// func Core(dst *[64]byte, state *[16]uint32, rounds int)
TEXT ·Core(SB),4,$0-24
	MOVQ state+8(FP), AX
	MOVQ dst+0(FP), BX
	MOVQ rounds+16(FP), CX
	MOVL 48(AX), DI
	MOVO 0(AX), X0
	MOVO 16(AX), X1
	MOVO 32(AX), X2
	MOVO 48(AX), X3
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	loop:
		ROUND_64B(X4, X5, X6, X7, X8)
		SUBQ $2, CX
		JA loop
	PADDL X4, X0
	PADDL X5, X1
	PADDL X6, X2
	PADDL X7, X3
	MOVO X0, 0(BX)
	MOVO X1, 16(BX)
	MOVO X2, 32(BX)
	MOVO X3, 48(BX)
	ADDL $1, DI
	MOVL DI, 48(AX)
	RET

TEXT ·xorBlocks(SB),4,$0-64
	MOVQ state+48(FP), AX
	MOVQ dst_base+0(FP), BX
	MOVQ src_base+24(FP), CX
	MOVQ src_len+32(FP), DX
	MOVQ rounds+56(FP), DI
	CMPQ dst_len+8(FP), DX
	JB DONE
	
	MOVQ SP, SI
	MOVQ $31, BP
	NOTQ BP
	ANDQ BP, SP
	SUBQ $32, SP
	PXOR X0, X0
	SUBQ $32, SP
	MOVO X0, 0(SP)
	MOVL $1, BP
	MOVL BP, 0(SP)
	
	CMPQ DX, $256
	JB BYTES_BETWEEN_0_AND_255
	BYTES_AT_LEAST_256:	
	MOVO 0(AX), X0
	MOVO 16(AX), X1
	MOVO 32(AX), X2
	MOVO 48(AX), X3
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	PADDQ 0(SP), X7
	MOVO X0, X8
	MOVO X1, X9
	MOVO X2, X10
	MOVO X7, X11
	PADDQ 0(SP), X11
	MOVO X0, X12
	MOVO X1, X13
	MOVO X2, X14
	MOVO X11, X15
	PADDQ 0(SP), X15
	MOVQ DI, BP
	CHACHA_LOOP_256:
		ROUND_256B(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, 16(SP))
		SUBQ $2, BP
		JA CHACHA_LOOP_256
	MOVO X12, 16(SP)
	PADDL 0(AX), X0
	PADDL 16(AX), X1
	PADDL 32(AX), X2
	PADDL 48(AX), X3
	XOR_64B(BX, CX, 0, X0, X1, X2, X3, X12)
	MOVO 48(AX), X3
	PADDQ 0(SP), X3
	PADDL 0(AX), X4
	PADDL 16(AX), X5
	PADDL 32(AX), X6
	PADDL X3, X7
	XOR_64B(BX, CX, 64, X4, X5, X6, X7, X12)
	PADDQ 0(SP), X3
	PADDL 0(AX), X8
	PADDL 16(AX), X9
	PADDL 32(AX), X10
	PADDL X3, X11
	XOR_64B(BX, CX, 128, X8, X9, X10, X11, X12)
	PADDQ 0(SP), X3
	MOVO 16(SP), X12
	PADDL 0(AX), X12
	PADDL 16(AX), X13
	PADDL 32(AX), X14
	PADDL X3, X15		
	XOR_64B(BX, CX, 192, X12, X13, X14, X15, X0)		
	PADDQ 0(SP), X3
	MOVO X3, 48(AX)
	ADDQ $256, CX
	ADDQ $256, BX
	SUBQ $256, DX
	CMPQ DX, $256
	JAE BYTES_AT_LEAST_256	
	BYTES_BETWEEN_0_AND_255:
	CMPQ DX, $0
	JE DONE
	CMPQ DX, $128
	JB BYTES_BETWEEN_0_AND_127
	MOVQ 0(SP), X15
	MOVO 0(AX), X0
	MOVO 16(AX), X1
	MOVO 32(AX), X2
	MOVO 48(AX), X3
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	MOVO X0, X8
	MOVO X1, X9
	MOVO X2, X10
	MOVO X3, X11
	PADDQ X15, X11
	MOVQ DI, BP
	CHACHA_LOOP_128:
		ROUND_128B(X4, X5, X6, X7, X8, X9, X10, X11, X12)
		SUBQ $2, BP
		JA CHACHA_LOOP_128
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	XOR_64B(BX, CX, 0, X4, X5, X6, X7, X12)
	PADDQ X15, X3
	PADDL X0, X8
	PADDL X1, X9
	PADDL X2, X10
	PADDL X3, X11
	XOR_64B(BX, CX, 64, X8, X9, X10, X11, X12)
	MOVO X3, 48(AX)
	ADDQ $128, CX
	ADDQ $128, BX
	SUBQ $128, DX	
	BYTES_BETWEEN_0_AND_127:
	CMPQ DX, $64
	JB DONE
	MOVQ 0(SP), X15
	MOVO 0(AX), X0
	MOVO 16(AX), X1
	MOVO 32(AX), X2
	MOVO 48(AX), X3
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	MOVQ DI, BP
	CHACHA_LOOP_64:
		ROUND_64B(X4, X5, X6, X7, X8)
		SUBQ $2, BP
		JA CHACHA_LOOP_64
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	XOR_64B(BX, CX, 0, X4, X5, X6, X7, X8)	
	PADDQ X15, X3
	MOVO X3, 48(AX)
	DONE:
	PXOR X0, X0
	MOVO X0, 16(SP)
	MOVQ SI, SP
	RET
