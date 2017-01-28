// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

import "testing"

func benchmarkCipher(b *testing.B, size int) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(nonce[:], &key)
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
		XORKeyStream(buf, buf, nonce[:], &key)
	}
}

func BenchmarkCipher64(b *testing.B)       { benchmarkCipher(b, 64) }
func BenchmarkCipher1K(b *testing.B)       { benchmarkCipher(b, 1024) }
func BenchmarkXORKeyStream64(b *testing.B) { benchmarkXORKeyStream(b, 64) }
func BenchmarkXORKeyStream1K(b *testing.B) { benchmarkXORKeyStream(b, 1024) }
