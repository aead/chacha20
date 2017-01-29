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

func setup(state *[64]byte, nonce []byte, key *[32]byte) {
	var Nonce [16]byte
	switch len(nonce) {
	case NonceSize:
		copy(Nonce[8:], nonce)
		initialize(state, key, &Nonce)
	case INonceSize:
		copy(Nonce[4:], nonce)
		initialize(state, key, &Nonce)
	case XNonceSize:
		var tmpKey [32]byte
		var hNonce [16]byte

		copy(hNonce[:], nonce[:16])
		hChaCha20(&tmpKey, &hNonce, key)
		copy(Nonce[8:], nonce[16:])
		initialize(state, &tmpKey, &Nonce)

		// BUG(aead): A "good" compiler will remove this (optimizations)
		//			  But using the provided key instead of tmpKey,
		//			  will change the key (-> probably confuses users)
		for i := range tmpKey {
			tmpKey[i] = 0
		}
	default:
		panic("invalid nonce size") // TODO (add error handling)
	}
}

// XORKeyStream crypts bytes from src to dst using the given nonce and key.
// The length of the nonce determinds the version of ChaCha20:
// - NonceSize:  ChaCha20/r with a 64 bit nonce and a 2^64 * 64 byte period.
// - INonceSize: ChaCha20/r as defined in RFC 7539 and a 2^32 * 64 byte period.
// - XNonceSize: XChaCha20/r with a 192 bit nonce and a 2^64 * 64 byte period.
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
	if len(nonce) == INonceSize && uint64(len(src)) > (1<<38) {
		panic("chacha20/chacha: src is too large")
	}

	var block, state [64]byte
	setup(&state, nonce, key)
	xorKeyStream(dst, src, &block, &state, rounds)
}

// Cipher implements ChaCha20/r (XChaCha20/r) for a given number of rounds r.
type Cipher struct {
	state, block [64]byte
	off          int
	rounds       int // 20 for ChaCha20
	noncesize    int
}

// NewCipher returns a new *chacha.Cipher implementing the ChaCha20/r or XChaCha20/r
// (r = 8, 12 or 20) stream cipher. The nonce must be unique for one key for all time.
// The length of the nonce determinds the version of ChaCha20:
// - NonceSize:  ChaCha20/r with a 64 bit nonce and a 2^64 * 64 byte period.
// - INonceSize: ChaCha20/r as defined in RFC 7539 and a 2^32 * 64 byte period.
// - XNonceSize: XChaCha20/r with a 192 bit nonce and a 2^64 * 64 byte period.
func NewCipher(nonce []byte, key *[32]byte, rounds int) *Cipher {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: rounds must be a 8, 12, or 20")
	}

	c := new(Cipher)
	setup(&(c.state), nonce, key)
	c.rounds = rounds

	if len(nonce) == INonceSize {
		c.noncesize = INonceSize
	} else {
		c.noncesize = NonceSize
	}

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
		if len(src) <= n {
			for i, v := range src {
				dst[i] = v ^ c.block[c.off]
				c.off++
			}
			if c.off == 64 {
				c.off = 0
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

// SetCounter skips ctr * 64 byte blocks. SetCounter(0) resets the cipher.
// This function always skips the unused keystream of the current 64 byte block.
func (c *Cipher) SetCounter(ctr uint64) {
	if c.noncesize == INonceSize {
		binary.LittleEndian.PutUint32(c.state[48:], uint32(ctr))
	} else {
		binary.LittleEndian.PutUint64(c.state[48:], ctr)
	}
	c.off = 0
}
