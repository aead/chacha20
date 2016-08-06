// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var coreTestVectors = []struct {
	key, nonce string
	counter    uint32
	keystream  string
	rounds     int
}{
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		keystream: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
			"da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
		counter: 0,
		rounds:  20,
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		keystream: "c5d30a7ce1ec119378c84f487d775a8542f13ece238a9455e8229e888de85bbd" +
			"29eb63d0a17a5b999b52da22be4023eb07620a54f6fa6ad8737b71eb0464dac0",
		counter: 0,
		rounds:  20,
	},
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000100000000000000",
		keystream: "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32" +
			"111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b",
		counter: 0,
		rounds:  20,
	},
	{
		key:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		nonce: "00000000ffffffffffffffff",
		keystream: "d9bf3f6bce6ed0b54254557767fb57443dd4778911b606055c39cc25e674b836" +
			"3feabc57fde54f790c52c8ae43240b79d49042b777bfd6cb80e931270b7f50eb",
		counter: 0,
		rounds:  20,
	},
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
			t.Fatal("Test vector %d: Core computes unexpected keystream\nFound: %s\nExpected: %s", i, hex.EncodeToString(dst[:]), hex.EncodeToString(stream))
		}
	}
}

var recFail = func(t *testing.T, msg string) {
	if err := recover(); err == nil {
		t.Fatalf("Expected error: %s", msg)
	}
}

func TestNewCipher(t *testing.T) {
	mustFail := func(t *testing.T, msg string, nonce *[12]byte, key *[32]byte, rounds int) {
		defer recFail(t, msg)
		NewCipher(nonce, key, rounds)
	}

	key := new([32]byte)
	nonce := new([12]byte)

	mustFail(t, "rounds is 0", nonce, key, 0)

	mustFail(t, "rounds is not even", nonce, key, 21)
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
		t.Fatalf("XORKeyStream differ from chacha.XORKeyStream\n XORKeyStream: %s \n chacha.XORKeyStream: %s", hex.EncodeToString(buf1), hex.EncodeToString(buf0))
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
		t.Fatalf("XORKeyStream differ from chacha.XORKeyStream\n XORKeyStream: %s \n chacha.XORKeyStream: %s", hex.EncodeToString(buf1), hex.EncodeToString(buf0))
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
		t.Fatalf("XORKeyStream differ from chacha.XORKeyStream\n XORKeyStream: %s \n chacha.XORKeyStream: %s", hex.EncodeToString(buf1), hex.EncodeToString(buf0))
	}
}

func TestXORKeyStreamPanic(t *testing.T) {
	mustFail := func(t *testing.T, msg string, dst, src []byte, nonce *[12]byte, key *[32]byte, counter uint32, rounds int) {
		defer recFail(t, msg)
		XORKeyStream(dst, src, nonce, key, counter, rounds)
	}

	key := new([32]byte)
	nonce := new([12]byte)
	src, dst := make([]byte, 65), make([]byte, 65)

	mustFail(t, "rounds is 0", dst, src, nonce, key, 0, 0)

	mustFail(t, "rounds is not even", dst, src, nonce, key, 0, 21)

	mustFail(t, "len(dst) < len(src)", dst[:len(src)-1], src, nonce, key, 0, 20)

	c := NewCipher(nonce, key, 20)

	mustFail2 := func(t *testing.T, msg string, dst, src []byte) {
		defer recFail(t, msg)
		c.XORKeyStream(dst, src)
	}

	mustFail2(t, "len(dst) < len(src)", dst[:len(src)-1], src)

}

func testXORBlocks(t *testing.T, size int) {
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
	testXORBlocks(t, 64)
	testXORBlocks(t, 128)
	testXORBlocks(t, 192)
	testXORBlocks(t, 256)
	testXORBlocks(t, 320)
	testXORBlocks(t, 384)
	testXORBlocks(t, 448)
	testXORBlocks(t, 512)
	testXORBlocks(t, 1024)
}
