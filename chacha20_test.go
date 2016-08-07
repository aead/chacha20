// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

import (
	"bytes"
	"testing"
)

func TestAEADVectors(t *testing.T) {
	for i, v := range testVectorsAEAD {
		key := fromHex(v.key)
		nonce := fromHex(v.nonce)
		msg := fromHex(v.msg)
		data := fromHex(v.data)
		ciphertext := fromHex(v.ciphertext)

		var Key [32]byte
		copy(Key[:], key)
		c, err := NewChaCha20Poly1305WithTagSize(&Key, v.tagSize)
		if err != nil {
			t.Errorf("Test vector %d: Failed to create AEAD instance: %s", i, err)
		}

		buf := make([]byte, len(ciphertext))
		c.Seal(buf[:0], nonce, msg, data)

		if !bytes.Equal(buf, ciphertext) {
			t.Errorf("TestVector %d Seal failed:\nFound   : %s\nExpected: %s", i, toHex(buf), toHex(ciphertext))
		}

		buf, err = c.Open(buf[:0], nonce, buf, data)

		if err != nil {
			t.Errorf("TestVector %d: Open failed - Cause: %s", i, err)
		}
		if !bytes.Equal(msg, buf) {
			t.Errorf("TestVector %d Open failed:\nFound   : %s\nExpected: %s", i, toHex(buf), toHex(msg))
		}
	}
}

func TestVectorsIETF(t *testing.T) {
	for i, v := range testVectorsIETF {
		key := fromHex(v.key)
		nonce := fromHex(v.nonce)
		msg := fromHex(v.msg)
		ciphertext := fromHex(v.ciphertext)

		var (
			Key   [32]byte
			Nonce [12]byte
		)
		copy(Key[:], key)
		copy(Nonce[:], nonce)
		buf := make([]byte, len(ciphertext))

		XORKeyStream(buf, msg, &Nonce, &Key, v.ctr)
		if !bytes.Equal(buf, ciphertext) {
			t.Errorf("Test vector %d :\nXORKeyStream() produces unexpected keystream:\nXORKeyStream(): %s\nExpected:             %s", i, toHex(buf), toHex(ciphertext))
		}

		c := NewCipher(&Nonce, &Key)
		var trash [64]byte
		for i := 0; i < int(v.ctr); i++ {
			c.XORKeyStream(trash[:], trash[:])
		}
		c.XORKeyStream(buf[:], msg[:])
		if !bytes.Equal(buf, ciphertext) {
			t.Errorf("Test vector %d :\nc.XORKeyStream() produces unexpected keystream:\nc.XORKeyStream(): %s\nExpected:         %s", i, toHex(buf), toHex(ciphertext))
		}
	}
}

func TestVectors8Nonce(t *testing.T) {
	for i, v := range testVectors8Nonce {
		key := fromHex(v.key)
		nonce := fromHex(v.nonce)
		keystream := fromHex(v.stream)

		var (
			Key   [32]byte
			Nonce [12]byte
		)
		copy(Key[:], key)
		copy(Nonce[4:], nonce)
		buf := make([]byte, len(keystream))

		XORKeyStream(buf, make([]byte, len(buf)), &Nonce, &Key, 0)
		if !bytes.Equal(buf, keystream) {
			t.Errorf("Test vector %d :\nXORKeyStream() produces unexpected keystream:\nXORKeyStream(): %s\nExpected:             %s", i, toHex(buf), toHex(keystream))
		}

		c := NewCipher(&Nonce, &Key)
		c.XORKeyStream(buf[:], make([]byte, len(buf)))
		if !bytes.Equal(buf, keystream) {
			t.Errorf("Test vector %d :\nc.XORKeyStream() produces unexpected keystream:\nc.XORKeyStream(): %s\nExpected:         %s", i, toHex(buf), toHex(keystream))
		}
	}
}

func benchmarkCipher(b *testing.B, size int) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(&nonce, &key)
	buf := make([]byte, size)

	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func benchmarkXORKeyStream(b *testing.B, size int) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	buf := make([]byte, size)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &nonce, &key, 0)
	}
}

func BenchmarkCipher64(b *testing.B)        { benchmarkCipher(b, 64) }
func BenchmarkCipher16K(b *testing.B)       { benchmarkCipher(b, 16*1024) }
func BenchmarkXORKeyStream64(b *testing.B)  { benchmarkXORKeyStream(b, 64) }
func BenchmarkXORKeyStream16K(b *testing.B) { benchmarkXORKeyStream(b, 16*1024) }
