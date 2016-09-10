// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func toHex(b []byte) string {
	return hex.EncodeToString(b)
}

func testCore(t *testing.T, n int) {
	var rounds = []int{8, 12, 20}
	var key [32]byte
	var nonce [12]byte

	for i := range key {
		key[i] = byte(i) ^ byte(n)
		nonce[i%12] += byte(n) + byte(i)
	}

	var dst0, dst1, state0, state1 [64]byte
	setState(&state0, &key, &nonce, 0)
	setState(&state1, &key, &nonce, 0)

	for _, r := range rounds {
		for i := 0; i < n; i++ {
			Core(&dst0, &state0, r)
			core(&dst1, &state1, r)
			if !bytes.Equal(dst0[:], dst1[:]) {
				t.Fatalf("Rounds: %d - Iteration %d: Core differs from generic core:\nCore dst: %s\ncore dst: %s", r, i, toHex(dst0[:]), toHex(dst1[:]))
			}
			if !bytes.Equal(state0[:], state1[:]) {
				t.Fatalf("Rounds: %d - Iteration %d: Core differs from generic core:\nCore state: %s\ncore state: %s", r, i, toHex(state0[:]), toHex(state1[:]))
			}
		}
	}
}

func TestCore(t *testing.T) {
	testCore(t, 1)
	testCore(t, 2)
	testCore(t, 4)
	testCore(t, 8)
	testCore(t, 16)
}

func TestSetCounter(t *testing.T) {
	var key [32]byte
	var nonce [12]byte
	for i := range key {
		key[i] = byte(i)
	}
	buf0, buf1 := make([]byte, 128), make([]byte, 128)

	c := NewCipher(&nonce, &key, 20)
	c.XORKeyStream(buf0[:1], buf0[:1])
	c.SetCounter(20)
	c.XORKeyStream(buf0[1:], buf0[1:])

	XORKeyStream(buf1[:1], buf1[:1], &nonce, &key, 0, 20)
	XORKeyStream(buf1[1:], buf1[1:], &nonce, &key, 20, 20)

	if !bytes.Equal(buf0, buf1) {
		t.Fatalf("XORKeyStream differ from chacha.XORKeyStream\n XORKeyStream: %s \n chacha.XORKeyStream: %s", toHex(buf1), toHex(buf0))
	}
}

func TestSetNonce(t *testing.T) {
	var key [32]byte
	var nonce [12]byte
	for i := range key {
		key[i] = byte(i)
	}
	buf0, buf1 := make([]byte, 128), make([]byte, 128)

	c := NewCipher(&nonce, &key, 20)
	c.XORKeyStream(buf0[:1], buf0[:1])
	nonce[0] = 1
	c.SetNonce(&nonce)
	c.XORKeyStream(buf0[1:], buf0[1:])

	nonce[0] = 0
	XORKeyStream(buf1[:1], buf1[:1], &nonce, &key, 0, 20)
	nonce[0] = 1
	XORKeyStream(buf1[1:], buf1[1:], &nonce, &key, 1, 20)

	if !bytes.Equal(buf0, buf1) {
		t.Fatalf("XORKeyStream differ from chacha.XORKeyStream\n XORKeyStream: %s \n chacha.XORKeyStream: %s", toHex(buf1), toHex(buf0))
	}
}

func TestXORKeyStream(t *testing.T) {
	var key [32]byte
	var nonce [12]byte
	for i := range key {
		key[i] = byte(i)
	}
	buf0, buf1 := make([]byte, 1023), make([]byte, 1023)

	c := NewCipher(&nonce, &key, 20)
	c.XORKeyStream(buf0[:1], buf0[:1])
	c.XORKeyStream(buf0[1:65], buf0[1:65])
	c.XORKeyStream(buf0[65:193], buf0[65:193])
	c.XORKeyStream(buf0[193:200], buf0[193:200])
	c.XORKeyStream(buf0[200:800], buf0[200:800])
	c.XORKeyStream(buf0[800:], buf0[800:])

	XORKeyStream(buf1, buf1, &nonce, &key, 0, 20)

	if !bytes.Equal(buf0, buf1) {
		t.Fatalf("XORKeyStream differ from chacha.XORKeyStream\n XORKeyStream: %s \n chacha.XORKeyStream: %s", toHex(buf1), toHex(buf0))
	}
}

func testXorBlocks(t *testing.T, size int) {
	var rounds = []int{8, 12, 20}

	var key [32]byte
	var nonce [12]byte

	for i := range key {
		key[i] = byte(i) ^ byte(size)
		nonce[i%12] += byte(size) + byte(i)
	}

	var dst0, state [64]byte
	dst1, src1 := make([]byte, size), make([]byte, size)

	for _, r := range rounds {
		XORKeyStream(dst1, src1, &nonce, &key, 0, 20)
		for i := 0; i < size; i += 64 {
			setState(&state, &key, &nonce, uint32(i/64))
			Core(&dst0, &state, 20)
			if !bytes.Equal(dst0[:], dst1[i:i+64]) {
				t.Fatalf("Rounds: %d - Index %d Size: %d: XORKeyStream produce unexpected keystream", r, i, size)
			}
		}
	}
}

func TestXorBlocks(t *testing.T) {
	testXorBlocks(t, 64)
	testXorBlocks(t, 128)
	testXorBlocks(t, 192)
	testXorBlocks(t, 256)
	testXorBlocks(t, 320)
	testXorBlocks(t, 384)
	testXorBlocks(t, 448)
	testXorBlocks(t, 512)
	testXorBlocks(t, 768)
	testXorBlocks(t, 1024)
	testXorBlocks(t, 1280)
}
