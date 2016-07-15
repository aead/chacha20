// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/aead/chacha20/chacha"
	"github.com/aead/poly1305"
)

// TagSize is the max. size of the auth. tag for the ChaCha20Poly1305 AEAD in bytes.
const TagSize = poly1305.TagSize

var (
	errDstToSmall       = errors.New("dst buffer to small")
	errAuthFailed       = errors.New("authentication failed")
	errInvalidNonceSize = errors.New("nonce size is invalid")
)

// NewChaCha20Poly1305 returns a cipher.AEAD implementing the
// ChaCha20Poly1305 construction specified in RFC 7539 with a
// 128 bit auth. tag.
func NewChaCha20Poly1305(key *[32]byte) cipher.AEAD {
	c := &aead{tagsize: TagSize}
	c.key = *key
	return c
}

// NewChaCha20Poly1305WithTagSize returns a cipher.AEAD implementing the
// ChaCha20Poly1305 construction specified in RFC 7539 with arbitrary tag size.
// The tagsize must be between 1 and the TagSize constant.
func NewChaCha20Poly1305WithTagSize(key *[32]byte, tagsize int) (cipher.AEAD, error) {
	if tagsize < 1 || tagsize > TagSize {
		return nil, errors.New("tag size must be between 1 and 16")
	}
	c := &aead{tagsize: tagsize}
	c.key = *key
	return c, nil
}

// The AEAD cipher ChaCha20Poly1305
type aead struct {
	key     [32]byte
	tagsize int
}

func (c *aead) Overhead() int { return c.tagsize }

func (c *aead) NonceSize() int { return NonceSize }

func (c *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != NonceSize {
		panic("chacha20: " + errInvalidNonceSize.Error())
	}
	if len(dst) < len(plaintext)+c.tagsize {
		panic("chacha20: " + errDstToSmall.Error())
	}

	var Nonce [12]byte
	copy(Nonce[:], nonce)

	// create the poly1305 key
	var polyKey [32]byte
	chacha.XORKeyStream(polyKey[:], polyKey[:], &Nonce, &(c.key), 0, 20)

	// encrypt the plaintext
	n := len(plaintext)
	chacha.XORKeyStream(dst, plaintext, &Nonce, &(c.key), 1, 20)

	// authenticate the ciphertext
	var tag [poly1305.TagSize]byte
	authenticate(&tag, dst[:n], additionalData, &polyKey)
	return append(dst[:n], tag[:c.tagsize]...)
}

func (c *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != NonceSize {
		return nil, errInvalidNonceSize
	}
	if len(ciphertext) < c.tagsize {
		return nil, errAuthFailed
	}
	if len(dst) < len(ciphertext)-c.tagsize {
		return nil, errDstToSmall
	}

	var Nonce [12]byte
	copy(Nonce[:], nonce)

	hash := ciphertext[len(ciphertext)-c.tagsize:]
	ciphertext = ciphertext[:len(ciphertext)-c.tagsize]

	// create the poly1305 key
	var polyKey [32]byte
	chacha.XORKeyStream(polyKey[:], polyKey[:], &Nonce, &(c.key), 0, 20)

	// authenticate the ciphertext
	var tag [poly1305.TagSize]byte
	authenticate(&tag, ciphertext, additionalData, &polyKey)
	if subtle.ConstantTimeCompare(tag[:c.tagsize], hash[:c.tagsize]) != 1 {
		return nil, errAuthFailed
	}

	// decrypt ciphertext
	chacha.XORKeyStream(dst, ciphertext, &Nonce, &(c.key), 1, 20)
	return dst[:len(ciphertext)], nil
}

// authenticate calculates the poly1305 tag from
// the given ciphertext and additional data.
func authenticate(out *[TagSize]byte, ciphertext, additionalData []byte, key *[32]byte) {
	ctLen := uint64(len(ciphertext))
	adLen := uint64(len(additionalData))
	padAD, padCT := adLen%TagSize, ctLen%TagSize

	var buf [16]byte
	buf[0] = byte(adLen)
	buf[1] = byte(adLen >> 8)
	buf[2] = byte(adLen >> 16)
	buf[3] = byte(adLen >> 24)
	buf[4] = byte(adLen >> 32)
	buf[5] = byte(adLen >> 40)
	buf[6] = byte(adLen >> 48)
	buf[7] = byte(adLen >> 56)
	buf[8] = byte(ctLen)
	buf[9] = byte(ctLen >> 8)
	buf[10] = byte(ctLen >> 16)
	buf[11] = byte(ctLen >> 24)
	buf[12] = byte(ctLen >> 32)
	buf[13] = byte(ctLen >> 40)
	buf[14] = byte(ctLen >> 48)
	buf[15] = byte(ctLen >> 56)

	poly := poly1305.New(key)
	poly.Write(additionalData)
	if padAD > 0 {
		poly.Write(make([]byte, 16-padAD))
	}
	poly.Write(ciphertext)
	if padCT > 0 {
		poly.Write(make([]byte, 16-padCT))
	}
	poly.Write(buf[:])
	poly.Sum(out)
}
