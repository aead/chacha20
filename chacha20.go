// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package chacha20 implements the ChaCha stream cipher and
// the ChaCha20Poly1305 AEAD construction described in RFC 7539.
//
// ChaCha20 uses a 32 bit counter and produces 64 byte keystream per
// iteration. Following ChaCha20 can en/decrypt up to 2^32 * 64 byte
// for one key-nonce combination. Notice that one specific key-nonce
// combination must be unique for all time.
package chacha20

import (
	"crypto/cipher"

	"github.com/aead/chacha20/chacha"
)

// NonceSize is the size of the ChaCha20 nonce in bytes.
const NonceSize = 12

// XORKeyStream crypts bytes from src to dst using the given key, nonce and counter. Src
// and dst may be the same slice but otherwise should not overlap. If len(dst) < len(src)
// this function panics.
func XORKeyStream(dst, src []byte, nonce *[NonceSize]byte, key *[32]byte, counter uint32) {
	chacha.XORKeyStream(dst, src, nonce, key, counter, 20)
}

// NewCipher returns a new cipher.Stream implementing the ChaCha20
// stream cipher. The nonce must be unique for one
// key for all time.
func NewCipher(nonce *[NonceSize]byte, key *[32]byte) cipher.Stream {
	return chacha.NewCipher(nonce, key, 20)
}
