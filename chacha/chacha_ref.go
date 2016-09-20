// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build !amd64
// +build !386

package chacha

var constants = [16]byte{
	0x65, 0x78, 0x70, 0x61,
	0x6e, 0x64, 0x20, 0x33,
	0x32, 0x2d, 0x62, 0x79,
	0x74, 0x65, 0x20, 0x6b,
}

// Core generates 64 byte keystream from the given state performing the
// provided number of rounds and writes them to dst. Valid values for
// rounds are 8, 12, or 20. Core increments the counter of state.
func Core(dst *[64]byte, state *[64]byte, rounds int) {
	core(dst, state, rounds)
}

// setState builds the ChaCha state from the key, the nonce and the counter.
func setState(state *[64]byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	copy(state[:], constants[:])
	copy(state[16:], key[:])
	state[48] = byte(counter)
	state[49] = byte(counter << 8)
	state[50] = byte(counter << 16)
	state[51] = byte(counter << 24)
	copy(state[52:], nonce[:])
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

// xor xors the bytes in src and with and writes the result to dst.
// The destination is assumed to have enough space. Returns the
// number of bytes xor'd.
func xor(dst, src, with []byte) int {
	var a, b []byte
	if len(src) <= len(with) {
		a = src
		b = with
	} else {
		b = src
		a = with
	}

	for i, v := range a {
		dst[i] = b[i] ^ v
	}
	return len(a)
}
