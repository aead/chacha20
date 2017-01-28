// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build go1.7,amd64,!gccgo,!appengine,!nacl

#include "textflag.h"

// func supportsAVX2() bool
TEXT ·supportsAVX2(SB), 4, $0-1
	MOVQ runtime·support_avx2(SB), AX
	MOVB AX, ret+0(FP)
	RET
