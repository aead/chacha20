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
	errAuthFailed       = errors.New("authentication failed")
	errCtxtTooLarge     = errors.New("ciphertext is too large")
	errInvalidNonceSize = errors.New("nonce size is invalid")
	errInvalidTagSize   = errors.New("tag size must be between 1 and 16")
)

// NewChaCha20Poly1305 returns a cipher.AEAD implementing the
// ChaCha20Poly1305 construction specified in RFC 7539 with a
// 128 bit auth. tag.
func NewChaCha20Poly1305(key *[32]byte) cipher.AEAD {
	var defaultNonce [12]byte
	c := &aead{
		engine:  chacha.NewCipher(&defaultNonce, key, 20),
		tagsize: TagSize,
	}
	return c
}

// NewChaCha20Poly1305WithTagSize returns a cipher.AEAD implementing the
// ChaCha20Poly1305 construction specified in RFC 7539 with arbitrary tag size.
// The tagsize must be between 1 and the TagSize constant.
func NewChaCha20Poly1305WithTagSize(key *[32]byte, tagsize int) (cipher.AEAD, error) {
	if tagsize < 1 || tagsize > TagSize {
		return nil, errInvalidTagSize
	}
	var defaultNonce [12]byte
	c := &aead{
		engine: chacha.NewCipher(&defaultNonce, key, 20),
	}
	c.tagsize = tagsize
	return c, nil
}

// The AEAD cipher ChaCha20Poly1305
type aead struct {
	engine  *chacha.Cipher
	tagsize int
}

func (c *aead) Overhead() int { return c.tagsize }

func (c *aead) NonceSize() int { return NonceSize }

func (c *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != NonceSize {
		panic("chacha20: nonce size is invalid")
	}

	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20: plaintext too large")
	}

	// create the poly1305 key
	var (
		Nonce   [12]byte
		polyKey [32]byte
	)
	copy(Nonce[:], nonce)
	c.engine.SetCounter(0)
	c.engine.SetNonce(&Nonce)
	c.engine.XORKeyStream(polyKey[:], polyKey[:])
	c.engine.SetCounter(1)

	// encrypt the plaintext
	n := len(plaintext)
	ret, ciphertext := sliceForAppend(dst, n+c.tagsize)
	c.engine.XORKeyStream(ciphertext, plaintext)

	// authenticate the ciphertext
	tag := authenticate(ciphertext[:n], additionalData, &polyKey)
	copy(ciphertext[n:], tag[:c.tagsize])

	return ret
}

func (c *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != NonceSize {
		return nil, errInvalidNonceSize
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		return nil, errCtxtTooLarge
	}
	if len(ciphertext) < c.tagsize {
		return nil, errAuthFailed
	}

	// create the poly1305 key
	var (
		Nonce   [12]byte
		polyKey [32]byte
	)
	copy(Nonce[:], nonce)
	c.engine.SetCounter(0)
	c.engine.SetNonce(&Nonce)
	c.engine.XORKeyStream(polyKey[:], polyKey[:])
	c.engine.SetCounter(1)

	// authenticate the ciphertext
	n := len(ciphertext) - c.tagsize
	sum := ciphertext[n:]
	tag := authenticate(ciphertext[:n], additionalData, &polyKey)
	if subtle.ConstantTimeCompare(tag[:c.tagsize], sum[:c.tagsize]) != 1 {
		return nil, errAuthFailed
	}

	// decrypt ciphertext
	ret, plaintext := sliceForAppend(dst, n)
	c.engine.XORKeyStream(plaintext, ciphertext[:n])

	return ret, nil
}

// authenticate calculates the poly1305 tag from
// the given ciphertext and additional data.
func authenticate(ciphertext, additionalData []byte, key *[32]byte) [TagSize]byte {
	ctLen := uint64(len(ciphertext))
	adLen := uint64(len(additionalData))

	var tag, buf, pad [TagSize]byte
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

	if adLen > 0 {
		poly.Write(additionalData)
	}
	if padAD := adLen % TagSize; padAD > 0 {
		poly.Write(pad[:16-padAD])
	}

	poly.Write(ciphertext)
	if padCT := ctLen % TagSize; padCT > 0 {
		poly.Write(pad[:16-padCT])
	}

	poly.Write(buf[:])
	poly.Sum(&tag)
	return tag
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
