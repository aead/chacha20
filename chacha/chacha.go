// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package chacha implements some low-level functions of the
// ChaCha cipher family.
package chacha // import "github.com/aead/chacha20/chacha"

import "encoding/binary"

// NonceSize is the size of the ChaCha20 nonce in bytes.
const NonceSize = 8

// INonceSize is the size of the IETF-ChaCha20 nonce in bytes.
const INonceSize = 12

// XNonceSize is the size of the XChaCha20 nonce in bytes.
const XNonceSize = 24

var (
	useSSE2  bool
	useSSSE3 bool
	useAVX2  bool
)

// XORKeyStream crypts bytes from src to dst using the given key, nonce and counter.
// The rounds argument specifies the number of rounds performed for keystream
// generation - valid values are 8, 12 or 20. The src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) this function panics.
func XORKeyStream(dst, src, nonce []byte, key *[32]byte, rounds int) {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: rounds must be a 8, 12, or 20")
	}
	if len(dst) < len(src) {
		panic("chacha20/chacha: dst buffer is to small")
	}

	var Nonce [16]byte
	switch len(nonce) {
	case NonceSize:
		copy(Nonce[8:], nonce)
	case INonceSize:
		copy(Nonce[4:], nonce)
		if uint64(len(src)) > (1 << 38) {
			panic("chacha20/chacha: src is too large")
		}
	case XNonceSize:
		copy(Nonce[:], nonce[:16])
		HChaCha20(key, &Nonce, key)
		copy(Nonce[8:], nonce[16:])
	default: // TODO (add error handling)
	}

	var block, state [64]byte
	initialize(&state, key, &Nonce)
	xorKeyStream(dst, src, &block, &state, rounds)
}

// Cipher implements ChaCha/X for a given number of rounds X.
type Cipher struct {
	state, block [64]byte
	off          int
	rounds       int // 20 for ChaCha20
}

// NewCipher returns a new *chacha.Cipher implementing the ChaCha/X (X = 8, 12 or 20)
// stream cipher. The nonce must be unique for one key for all time.
func NewCipher(nonce []byte, key *[32]byte, rounds int) *Cipher {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: rounds must be a 8, 12, or 20")
	}

	var Nonce [16]byte
	switch len(nonce) {
	case NonceSize:
		copy(Nonce[8:], nonce)
	case INonceSize:
		copy(Nonce[4:], nonce)
	case XNonceSize:
		copy(Nonce[:], nonce[:16])
		HChaCha20(key, &Nonce, key)
		copy(Nonce[8:], nonce[16:])
	default: // TODO (add error handling)
	}

	c := new(Cipher)
	c.rounds = rounds
	initialize(&(c.state), key, &Nonce)

	return c
}

// XORKeyStream crypts bytes from src to dst. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the function panics.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("chacha20/chacha: dst buffer is to small")
	}

	if c.off > 0 {
		n := len(c.block[c.off:])
		if len(src) < n {
			for i, v := range src {
				dst[i] = v ^ c.block[c.off]
				c.off++
			}
			return
		}

		for i, v := range c.block[c.off:] {
			dst[i] = src[i] ^ v
		}
		src = src[n:]
		dst = dst[n:]
		c.off = 0
	}

	c.off += xorKeyStream(dst, src, &(c.block), &(c.state), c.rounds)
}

func (c *Cipher) SetCounter(ctr uint64) {
	binary.LittleEndian.PutUint64(c.state[48:], ctr)
}
