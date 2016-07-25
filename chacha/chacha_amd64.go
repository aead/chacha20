// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package chacha

import "unsafe"

// XORKeyStream crypts bytes from src to dst using the given key, nonce and counter.
// The rounds argument specifies the number of rounds (must be even) performed for
// keystream generation. (Common values are 20, 12 or 8) Src and dst may be the same
// slice but otherwise should not overlap. If len(dst) < len(src) this function panics.
func XORKeyStream(dst, src []byte, nonce *[12]byte, key *[32]byte, counter uint32, rounds int) {
	length := len(src)
	if len(dst) < length {
		panic("chacha20/chacha: dst buffer is to small")
	}
	if rounds <= 0 || rounds%2 != 0 {
		panic("chacha20/chacha: rounds must be a multiple of 2")
	}

	var state [64]byte
	setState(&state, key, nonce, counter)

	if length >= 64 {
		xorBlocks(dst, src, &state, rounds)
	}

	if n := length & (^(64 - 1)); length-n > 0 {
		var block [64]byte
		Core(&block, &state, rounds)
		xor(dst[n:], src[n:], block[:])
	}
}

// NewCipher returns a new *chacha.Cipher implementing the ChaCha/X (X = even number of rounds)
// stream cipher. The nonce must be unique for one key for all time.
func NewCipher(nonce *[12]byte, key *[32]byte, rounds int) *Cipher {
	if rounds <= 0 || rounds%2 != 0 {
		panic("chacha20/chacha: rounds must be a multiply of 2")
	}
	c := new(Cipher)
	c.rounds = rounds
	setState(&(c.state), key, nonce, 0)

	return c
}

// xorBlocks crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state. Src and dst may be the same slice but otherwise should not
// overlap. This function increments the counter of state.
// If len(src) > len(dst), XORBlocks does nothing.
//go:noescape
func xorBlocks(dst, src []byte, state *[64]byte, rounds int)

// setState builds the ChaCha state from the key, the nonce and the counter.
//go:noescape
func setState(state *[64]byte, key *[32]byte, nonce *[12]byte, counter uint32)

// Core generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst. This function expects valid values. (no nil ptr etc.)
// Core increments the counter of state.
func Core(dst *[64]byte, state *[64]byte, rounds int)

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

	for i := (n & (^(8 - 1))); i < n; i++ {
		dst[i] = src[i] ^ with[i]
	}

	return n
}
