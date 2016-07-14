// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build !amd64

package chacha

import "github.com/enceve/crypto"

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

	copy(state[16:], key[:])

	state[48] = byte(counter)
	state[49] = byte(counter << 8)
	state[50] = byte(counter << 16)
	state[51] = byte(counter << 24)

	copy(state[52:], nonce[:])

	if length >= 64 {
		XORBlocks(dst, src, &state, rounds)
	}

	if n := length & (^(64 - 1)); length-n > 0 {
		var block [64]byte
		Core(&block, &state, rounds)

		crypto.XOR(dst[n:], src[n:], block[:])
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

	copy(c.state[16:], key[:])

	copy(c.state[52:], nonce[:])

	return c
}

// XORKeyStream crypts bytes from src to dst. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the function panics.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("chacha20/chacha: dst buffer is to small")
	}

	if c.off > 0 {
		n := crypto.XOR(dst, src, c.block[c.off:])
		if n == length {
			c.off += n
			return
		}
		src = src[n:]
		dst = dst[n:]
		length -= n
		c.off = 0
	}

	if length >= 64 {
		XORBlocks(dst, src, &(c.state), c.rounds)
	}

	if n := length & (^(64 - 1)); length-n > 0 {
		Core(&(c.block), &(c.state), c.rounds)

		c.off += crypto.XOR(dst[n:], src[n:], c.block[:])
	}
}

// XORBlocks crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the behavior is undefined.
// This function increments the counter of state.
func XORBlocks(dst, src []byte, state *[64]byte, rounds int) {
	n := len(src) & (^(64 - 1))

	var block [64]byte
	for i := 0; i < n; i += 64 {
		Core(&block, state, rounds)
		crypto.XOR(dst[i:], src[i:], block[:])
	}
}

// Core generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst. This function expects valid values. (no nil ptr etc.)
// Core increments the counter of the state.
func Core(dst *[64]byte, state *[64]byte, rounds int) {
	v00 := uint32(state[0]) | (uint32(state[1]) << 8) | (uint32(state[2]) << 16) | (uint32(state[3]) << 24)
	v01 := uint32(state[4]) | (uint32(state[5]) << 8) | (uint32(state[6]) << 16) | (uint32(state[7]) << 24)
	v02 := uint32(state[8]) | (uint32(state[9]) << 8) | (uint32(state[10]) << 16) | (uint32(state[11]) << 24)
	v03 := uint32(state[12]) | (uint32(state[13]) << 8) | (uint32(state[14]) << 16) | (uint32(state[15]) << 24)
	v04 := uint32(state[16]) | (uint32(state[17]) << 8) | (uint32(state[18]) << 16) | (uint32(state[19]) << 24)
	v05 := uint32(state[20]) | (uint32(state[21]) << 8) | (uint32(state[22]) << 16) | (uint32(state[23]) << 24)
	v06 := uint32(state[24]) | (uint32(state[25]) << 8) | (uint32(state[26]) << 16) | (uint32(state[27]) << 24)
	v07 := uint32(state[28]) | (uint32(state[29]) << 8) | (uint32(state[30]) << 16) | (uint32(state[31]) << 24)
	v08 := uint32(state[32]) | (uint32(state[33]) << 8) | (uint32(state[34]) << 16) | (uint32(state[35]) << 24)
	v09 := uint32(state[36]) | (uint32(state[37]) << 8) | (uint32(state[38]) << 16) | (uint32(state[39]) << 24)
	v10 := uint32(state[40]) | (uint32(state[41]) << 8) | (uint32(state[42]) << 16) | (uint32(state[43]) << 24)
	v11 := uint32(state[44]) | (uint32(state[45]) << 8) | (uint32(state[46]) << 16) | (uint32(state[47]) << 24)
	v12 := uint32(state[48]) | (uint32(state[49]) << 8) | (uint32(state[50]) << 16) | (uint32(state[51]) << 24)
	v13 := uint32(state[52]) | (uint32(state[53]) << 8) | (uint32(state[54]) << 16) | (uint32(state[55]) << 24)
	v14 := uint32(state[56]) | (uint32(state[57]) << 8) | (uint32(state[58]) << 16) | (uint32(state[59]) << 24)
	v15 := uint32(state[60]) | (uint32(state[61]) << 8) | (uint32(state[62]) << 16) | (uint32(state[63]) << 24)

	s00, s01, s02, s03, s04, s05, s06, s07 := v00, v01, v02, v03, v04, v05, v06, v07
	s08, s09, s10, s11, s12, s13, s14, s15 := v08, v09, v10, v11, v12, v13, v14, v15

	for i := 0; i < rounds; i += 2 {
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 16) | (v12 >> (16))
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 12) | (v04 >> (20))
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 8) | (v12 >> (24))
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 7) | (v04 >> (25))
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 16) | (v13 >> 16)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 12) | (v05 >> 20)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 8) | (v13 >> 24)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 7) | (v05 >> 25)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 16) | (v14 >> 16)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 12) | (v06 >> 20)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 8) | (v14 >> 24)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 7) | (v06 >> 25)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 16) | (v15 >> 16)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 12) | (v07 >> 20)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 8) | (v15 >> 24)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 7) | (v07 >> 25)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 16) | (v15 >> 16)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 12) | (v05 >> 20)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 8) | (v15 >> 24)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 7) | (v05 >> 25)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 16) | (v12 >> 16)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 12) | (v06 >> 20)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 8) | (v12 >> 24)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 7) | (v06 >> 25)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 16) | (v13 >> 16)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 12) | (v07 >> 20)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 8) | (v13 >> 24)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 7) | (v07 >> 25)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 16) | (v14 >> 16)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 12) | (v04 >> 20)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 8) | (v14 >> 24)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 7) | (v04 >> 25)
	}

	v00 += s00
	v01 += s01
	v02 += s02
	v03 += s03
	v04 += s04
	v05 += s05
	v06 += s06
	v07 += s07
	v08 += s08
	v09 += s09
	v10 += s10
	v11 += s11
	v12 += s12
	v13 += s13
	v14 += s14
	v15 += s15

	s12 += 1
	state[48] = byte(s12)
	state[49] = byte(s12 >> 8)
	state[50] = byte(s12 >> 16)
	state[51] = byte(s12 >> 24)

	dst[0] = byte(v00)
	dst[1] = byte(v00 >> 8)
	dst[2] = byte(v00 >> 16)
	dst[3] = byte(v00 >> 24)

	dst[4] = byte(v01)
	dst[5] = byte(v01 >> 8)
	dst[6] = byte(v01 >> 16)
	dst[7] = byte(v01 >> 24)

	dst[8] = byte(v02)
	dst[9] = byte(v02 >> 8)
	dst[10] = byte(v02 >> 16)
	dst[11] = byte(v02 >> 24)

	dst[12] = byte(v03)
	dst[13] = byte(v03 >> 8)
	dst[14] = byte(v03 >> 16)
	dst[15] = byte(v03 >> 24)

	dst[16] = byte(v04)
	dst[17] = byte(v04 >> 8)
	dst[18] = byte(v04 >> 16)
	dst[19] = byte(v04 >> 24)

	dst[20] = byte(v05)
	dst[21] = byte(v05 >> 8)
	dst[22] = byte(v05 >> 16)
	dst[23] = byte(v05 >> 24)

	dst[24] = byte(v06)
	dst[25] = byte(v06 >> 8)
	dst[26] = byte(v06 >> 16)
	dst[27] = byte(v06 >> 24)

	dst[28] = byte(v07)
	dst[29] = byte(v07 >> 8)
	dst[30] = byte(v07 >> 16)
	dst[31] = byte(v07 >> 24)

	dst[32] = byte(v08)
	dst[33] = byte(v08 >> 8)
	dst[34] = byte(v08 >> 16)
	dst[35] = byte(v08 >> 24)

	dst[36] = byte(v09)
	dst[37] = byte(v09 >> 8)
	dst[38] = byte(v09 >> 16)
	dst[39] = byte(v09 >> 24)

	dst[40] = byte(v10)
	dst[41] = byte(v10 >> 8)
	dst[42] = byte(v10 >> 16)
	dst[43] = byte(v10 >> 24)

	dst[44] = byte(v11)
	dst[45] = byte(v11 >> 8)
	dst[46] = byte(v11 >> 16)
	dst[47] = byte(v11 >> 24)

	dst[48] = byte(v12)
	dst[49] = byte(v12 >> 8)
	dst[50] = byte(v12 >> 16)
	dst[51] = byte(v12 >> 24)

	dst[52] = byte(v13)
	dst[53] = byte(v13 >> 8)
	dst[54] = byte(v13 >> 16)
	dst[55] = byte(v13 >> 24)

	dst[56] = byte(v14)
	dst[57] = byte(v14 >> 8)
	dst[58] = byte(v14 >> 16)
	dst[59] = byte(v14 >> 24)

	dst[60] = byte(v15)
	dst[61] = byte(v15 >> 8)
	dst[62] = byte(v15 >> 16)
	dst[63] = byte(v15 >> 24)
}
