// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha

import (
	"bytes"
	"testing"
)

var mustFail = func(t *testing.T, f func(), err string) {
	defer func() {
		if recover() == nil {
			t.Errorf("Function expected to fail: Expected: %s", err)
		}
	}()
	f()
}

func TestCore(t *testing.T) {
	var (
		key        [32]byte
		nonce      [12]byte
		state, dst [64]byte
	)

	for i, v := range coreTestVectors {
		copy(key[:], fromHex(v.key))
		copy(nonce[:], fromHex(v.nonce))

		setState(&state, &key, &nonce, v.counter)

		Core(&dst, &state, v.rounds)
		if stream := fromHex(v.keystream); !bytes.Equal(dst[:], stream) {
			t.Fatalf("Test vector %d: Core computes unexpected keystream\nFound: %s\nExpected: %s", i, toHex(dst[:]), toHex(stream))
		}
	}
}

func TestNewCipher(t *testing.T) {
	key := new([32]byte)
	nonce := new([12]byte)

	mustFail(t, func() { NewCipher(nonce, key, 0) }, "rounds is 0")
	mustFail(t, func() { NewCipher(nonce, key, 21) }, "rounds is not even")
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
	buf0, buf1 := make([]byte, 256), make([]byte, 256)

	c := NewCipher(&nonce, &key, 20)
	c.XORKeyStream(buf0[:1], buf0[:1])
	c.XORKeyStream(buf0[1:65], buf0[1:65])
	c.XORKeyStream(buf0[65:193], buf0[65:193])
	c.XORKeyStream(buf0[193:200], buf0[193:200])
	c.XORKeyStream(buf0[200:], buf0[200:])

	XORKeyStream(buf1, buf1, &nonce, &key, 0, 20)

	if !bytes.Equal(buf0, buf1) {
		t.Fatalf("XORKeyStream differ from chacha.XORKeyStream\n XORKeyStream: %s \n chacha.XORKeyStream: %s", toHex(buf1), toHex(buf0))
	}
}

func TestXORKeyStreamPanic(t *testing.T) {
	key := new([32]byte)
	nonce := new([12]byte)
	src, dst := make([]byte, 65), make([]byte, 65)

	mustFail(t, func() { XORKeyStream(dst, src, nonce, key, 0, 0) }, "rounds is 0")
	mustFail(t, func() { XORKeyStream(dst, src, nonce, key, 0, 21) }, "rounds is not even")
	mustFail(t, func() { XORKeyStream(dst[:len(src)-1], src, nonce, key, 0, 21) }, "len(dst) < len(src)")

	c := NewCipher(nonce, key, 20)

	mustFail(t, func() { c.XORKeyStream(dst[:len(src)-1], src) }, "len(dst) < len(src)")
}

func testXorBlocks(t *testing.T, size int) {
	var key [32]byte
	var nonce [12]byte
	for i := range nonce {
		nonce[i] = byte(i)
		key[2*i] = byte(i)
	}

	var dst0, state [64]byte
	dst1, src1 := make([]byte, size), make([]byte, size)

	XORKeyStream(dst1, src1, &nonce, &key, 0, 20)
	for i := 0; i < size; i += 64 {
		setState(&state, &key, &nonce, uint32(i/64))
		Core(&dst0, &state, 20)
		if !bytes.Equal(dst0[:], dst1[i:i+64]) {
			t.Fatalf("Index %d Size: %d: XORKeyStream produce unexpected keystream", i, size)
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
	testXorBlocks(t, 1024)
}
