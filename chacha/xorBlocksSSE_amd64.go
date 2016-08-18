// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build !go1.7
// +build amd64, !gccgo, !appengine

package chacha

// xorBlocks crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state. Src and dst may be the same slice but otherwise should not
// overlap. This function increments the counter of state.
func xorBlocks(dst, src []byte, state *[64]byte, rounds int) {
	if useSSSE3 {
		xorBlocksSSSE3(dst, src, state, rounds)
	} else {
		xorBlocksSSE2(dst, src, state, rounds)
	}
}
