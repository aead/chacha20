// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package chacha implements some low level functions of the
// ChaCha cipher family.
package chacha // import "github.com/aead/chacha20/chacha"

var constants = [16]byte{
	0x65, 0x78, 0x70, 0x61,
	0x6e, 0x64, 0x20, 0x33,
	0x32, 0x2d, 0x62, 0x79,
	0x74, 0x65, 0x20, 0x6b,
}

// Cipher is the ChaCha/X struct.
// X is the number of rounds (e.g. ChaCha20 for 20 rounds)
type Cipher struct {
	state, block [64]byte
	off          int
	rounds       int
}

// Sets the counter of the cipher.
// Notice that this function skips the unused
// keystream of the current 64 byte block.
func (c *Cipher) SetCounter(ctr uint32) {
	c.state[48] = byte(ctr)
	c.state[49] = byte(ctr >> 8)
	c.state[50] = byte(ctr >> 16)
	c.state[51] = byte(ctr >> 24)
	c.off = 0
}
