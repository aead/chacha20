// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64, !gccgo, !appengine

package chacha

import "unsafe"

var useSSSE3 = supportSSSE3()
var useAVX2 bool

// Core generates 64 byte keystream from the given state performing the
// provided number of rounds and writes them to dst. Valid values for
// rounds are 8, 12, or 20. Core increments the counter of state.
func Core(dst *[64]byte, state *[64]byte, rounds int) {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: rounds must be a 8, 12, or 20")
	}
	if useSSSE3 {
		coreSSSE3(dst, state, rounds)
	} else {
		coreSSE2(dst, state, rounds)
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

	w := n / 8
	if w > 0 {
		dstPtr := *(*[]uint64)(unsafe.Pointer(&dst))
		srcPtr := *(*[]uint64)(unsafe.Pointer(&src))
		withPtr := *(*[]uint64)(unsafe.Pointer(&with))
		for i, v := range srcPtr[:w] {
			dstPtr[i] = withPtr[i] ^ v
		}
	}

	// n & (^(8 - 1))   equal to   n - (n % 8) (on amd64 the wordsize is 8)
	for i := (n & (^(8 - 1))); i < n; i++ {
		dst[i] = src[i] ^ with[i]
	}

	return n
}

// supportSSSE3 returns true if the runtime (the executing machine) supports SSSE3.
//go:noescape
func supportSSSE3() bool

// setState builds the ChaCha state from the key, the nonce and the counter.
//go:noescape
func setState(state *[64]byte, key *[32]byte, nonce *[12]byte, counter uint32)

// xorBlocksSSE2 crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state.
//go:noescape
func xorBlocksSSE2(dst, src []byte, state *[64]byte, rounds int)

// xorBlocksSSSE3 crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state.
//go:noescape
func xorBlocksSSSE3(dst, src []byte, state *[64]byte, rounds int)

// coreSSE2 generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst.
func coreSSE2(dst *[64]byte, state *[64]byte, rounds int)

// coreSSSE3 generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst.
func coreSSSE3(dst *[64]byte, state *[64]byte, rounds int)
