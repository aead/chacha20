// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine,!nacl

package chacha

func init() {
	useSSE2 = true
	useSSSE3 = supportsSSSE3()
	useAVX2 = false
}

//go:noescape
func initialize(state *[64]byte, key *[32]byte, nonce *[16]byte)

//go:noescape
func supportsSSSE3() bool

//go:noescape
func hChaCha20SSE2(out *[32]byte, nonce *[16]byte, key *[32]byte)

//go:noescape
func hChaCha20SSSE3(out *[32]byte, nonce *[16]byte, key *[32]byte)

func HChaCha20(out *[32]byte, nonce *[16]byte, key *[32]byte) {
	if useSSSE3 {
		hChaCha20SSSE3(out, nonce, key)
	} else {
		hChaCha20SSE2(out, nonce, key)
	}
}

//go:noescape
func xorKeyStreamSSE2(dst, src []byte, block, state *[64]byte, rounds int) int

//go:noescape
func xorKeyStreamSSSE3(dst, src []byte, block, state *[64]byte, rounds int) int

func xorKeyStream(dst, src []byte, block, state *[64]byte, rounds int) int {
	if useSSSE3 {
		return xorKeyStreamSSSE3(dst, src, block, state, rounds)
	}
	return xorKeyStreamSSE2(dst, src, block, state, rounds)
}
