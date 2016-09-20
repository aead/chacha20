// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386, !gccgo, !appengine

package chacha

import "unsafe"

var (
	useSSE2  = supportSSE2()
	useSSSE3 = supportSSSE3()
)

// Core generates 64 byte keystream from the given state performing the
// provided number of rounds and writes them to dst. Valid values for
// rounds are 8, 12, or 20. Core increments the counter of state.
func Core(dst *[64]byte, state *[64]byte, rounds int) {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: rounds must be a 8, 12, or 20")
	}
	if useSSSE3 {
		coreSSSE3(dst, state, rounds)
	} else if useSSE2 {
		coreSSE2(dst, state, rounds)
	} else {
		core(dst, state, rounds)
	}
}

// xor xors the bytes in src and with and writes the result to dst.
// The destination is assumed to have enough space. Returns the
// number of bytes xor'd.
func xor(dst, src, with []byte) int {
	n := len(src)
	if len(with) < n {
		n = len(with)
	}

	w := n / 4
	if w > 0 {
		dstPtr := *(*[]uint32)(unsafe.Pointer(&dst))
		srcPtr := *(*[]uint32)(unsafe.Pointer(&src))
		withPtr := *(*[]uint32)(unsafe.Pointer(&with))
		for i, v := range srcPtr[:w] {
			dstPtr[i] = withPtr[i] ^ v
		}
	}

	// n & (^(4 - 1))   equal to   n - (n % 4) (on 386 the wordsize is 4)
	for i := (n & (^(4 - 1))); i < n; i++ {
		dst[i] = src[i] ^ with[i]
	}

	return n
}

// xorBlocks crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the behavior is undefined.
// This function increments the counter of state.
func xorBlocks(dst, src []byte, state *[64]byte, rounds int) {
	n := len(src) & (^(64 - 1)) // n := len(src) - (len(src) % 64)

	var block [64]byte
	for i := 0; i < n; i += 64 {
		Core(&block, state, rounds)
		xor(dst[i:], src[i:], block[:])
	}

}

//go:noescape
func coreSSE2(dst *[64]byte, state *[64]byte, rounds int)

//go:noescape
func coreSSSE3(dst *[64]byte, state *[64]byte, rounds int)

//go:noescape
func setState(state *[64]byte, key *[32]byte, nonce *[12]byte, counter uint32)

//go:noescape
func supportSSE2() bool

//go:noescape
func supportSSSE3() bool
