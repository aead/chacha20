// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package chacha

import "unsafe"

const wordSize = int(unsafe.Sizeof(uintptr(0)))

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

	copy(state[:], constants[:])

	statePtr := (*[8]uint64)(unsafe.Pointer(&state[0]))
	keyPtr := (*[4]uint64)(unsafe.Pointer(&key[0]))

	statePtr[2] = keyPtr[0]
	statePtr[3] = keyPtr[1]
	statePtr[4] = keyPtr[2]
	statePtr[5] = keyPtr[3]

	statePtr[6] = (*(*uint64)(unsafe.Pointer(&nonce[0])) << 32) | uint64(counter)

	statePtr[7] = *(*uint64)(unsafe.Pointer(&nonce[4]))

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

	copy(c.state[:], constants[:])

	statePtr := (*[8]uint64)(unsafe.Pointer(&(c.state[0])))
	keyPtr := (*[4]uint64)(unsafe.Pointer(&key[0]))

	statePtr[2] = keyPtr[0]
	statePtr[3] = keyPtr[1]
	statePtr[4] = keyPtr[2]
	statePtr[5] = keyPtr[3]

	statePtr[6] = (*(*uint64)(unsafe.Pointer(&nonce[0])) << 32)

	statePtr[7] = *(*uint64)(unsafe.Pointer(&nonce[4]))

	return c
}

// xorBlocks crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state. Src and dst may be the same slice but otherwise should not
// overlap. This function increments the counter of state.
// If len(src) > len(dst), XORBlocks does nothing.
//go:noescape
func xorBlocks(dst, src []byte, state *[64]byte, rounds int)

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

	w := n / wordSize
	if w > 0 {
		dstPtr := *(*[]uintptr)(unsafe.Pointer(&dst))
		srcPtr := *(*[]uintptr)(unsafe.Pointer(&src))
		withPtr := *(*[]uintptr)(unsafe.Pointer(&with))
		for i, v := range srcPtr[:w] {
			dstPtr[i] = withPtr[i] ^ v
		}
	}

	for i := (n & (^(wordSize - 1))); i < n; i++ {
		dst[i] = src[i] ^ with[i]
	}

	return n
}
