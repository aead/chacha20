// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

import (
	"fmt"
	"testing"
)

func TestNewChaCha20Poly1305WithTagSize(t *testing.T) {
	var key [32]byte
	_, err := NewChaCha20Poly1305WithTagSize(&key, 0)
	if err == nil {
		t.Errorf("NewChaCha20Poly1305WithTagSize accepted invalid tagsize: %d", 0)
	}

	_, err = NewChaCha20Poly1305WithTagSize(&key, 17)
	if err == nil {
		t.Errorf("NewChaCha20Poly1305WithTagSize accepted invalid tagsize: %d", 0)
	}
}

func TestOverhead(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)

	if o := c.Overhead(); o != TagSize {
		t.Errorf("Expected %d but Overhead() returned %d", TagSize, o)
	}

	c, err := NewChaCha20Poly1305WithTagSize(&key, 12)
	if err != nil {
		t.Errorf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	if o := c.Overhead(); o != 12 {
		t.Errorf("Expected %d but Overhead() returned %d", 12, o)
	}
}

func TestNonceSize(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)
	if n := c.NonceSize(); n != NonceSize {
		t.Errorf("Expected %d but NonceSize() returned %d", TagSize, n)
	}
}

func TestSeal(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)

	var (
		nonce [NonceSize]byte
		src   [64]byte
		dst   [64 + TagSize]byte
	)
	mustFail := func(t *testing.T, f func(), err string) {
		defer func() {
			if recover() == nil {
				t.Errorf("Function expected to fail: Expected: %s", err)
			}
		}()
		f()
	}

	mustFail(t, func() { c.Seal(dst[:0], nonce[:NonceSize-1], src[:], nil) }, "nonce size invalid")
}

func TestOpen(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)

	var (
		nonce [NonceSize]byte
		src   [64]byte
		dst   [64 + TagSize]byte
	)

	_, err := c.Open(dst[:], nonce[:NonceSize-1], src[:], nil)
	if err == nil {
		t.Error("Open() accepted invalid nonce size")
	}

	_, err = c.Open(dst[:], nonce[:], src[:TagSize-1], nil)
	if err == nil {
		t.Error("Open() accepted invalid ciphertext length")
	}

	_, err = c.Open(dst[:], nonce[:], src[:TagSize-1], nil)
	if err == nil {
		t.Error("Open() accepted invalid ciphertext length")
	}

	_, err = c.Open(dst[:len(src)-TagSize-1], nonce[:], src[:], nil)
	if err == nil {
		t.Error("Open() accepted invalid dst length")
	}

	// Check tag verification
	c.Seal(dst[:], nonce[:], src[:], nil)
	dst[len(src)+1]++ // modify tag

	_, err = c.Open(src[:], nonce[:], dst[:], nil)
	if err == nil {
		t.Error("Open() accepted invalid auth. tag")
	}
}

// Examples

func ExampleNewChaCha20Poly1305() {
	var secretKey [32]byte           // The secret 256 bit key - may derived from a password
	nonce := make([]byte, NonceSize) // The more or less random nonce - only used once for all time.

	plaintext := []byte("My secret diary: ...")        // The plaintext for encryption
	ciphertext := make([]byte, len(plaintext)+TagSize) // The +Tagsize avoids slice allocs - See cipher.AEAD
	addData := []byte("Send at 12.00")                 // Some meta data, not encrypted, but authenticated

	aead := NewChaCha20Poly1305(&secretKey)
	ciphertext = aead.Seal(ciphertext[:0], nonce, plaintext, addData)

	// now ciphertext holds the encrypted plaintext + the 16 byte authentication tag.

	plaintext, err := aead.Open(plaintext[:0], nonce, ciphertext, addData)
	if err != nil {
		fmt.Printf("Something went wrong: %s", err)
		return
	}
	fmt.Println(string(plaintext))
	// Output: My secret diary: ...
}

// Benchmarks

func benchmarkSeal(b *testing.B, size int) {
	var key [32]byte
	var nonce [12]byte
	c := NewChaCha20Poly1305(&key)

	msg := make([]byte, size)
	dst := make([]byte, len(msg)+TagSize)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst[:0], nonce[:], msg, nil)
	}
}

func benchmarkOpen(b *testing.B, size int) {
	var key [32]byte
	var nonce [12]byte
	c := NewChaCha20Poly1305(&key)

	msg := make([]byte, size)
	dst := make([]byte, size)
	ciphertext := make([]byte, size+TagSize)
	ciphertext = c.Seal(ciphertext[:0], nonce[:], msg, nil)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst[:0], nonce[:], ciphertext, nil)
	}
}

func BenchmarkSeal64B(b *testing.B) { benchmarkSeal(b, 64) }
func BenchmarkSeal1K(b *testing.B)  { benchmarkSeal(b, 1024) }

func BenchmarkOpen64B(b *testing.B) { benchmarkOpen(b, 64) }
func BenchmarkOpen1K(b *testing.B)  { benchmarkOpen(b, 1024) }
