// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

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

func toHex(b []byte) string {
	return hex.EncodeToString(b)
}

// Test vector from:
// https://tools.ietf.org/html/rfc7539#section-2.8.1
var testVectorsIETF = []struct {
	key, nonce      string
	msg, ciphertext string
	ctr             uint32
}{
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		msg: "0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000",
		ciphertext: "76b8e0ada0f13d90405d6ae55386bd28" +
			"bdd219b8a08ded1aa836efcc8b770dc7" +
			"da41597c5157488d7724e03fb8d84a37" +
			"6a43b8f41518a11cc387b669b2ee6586",
		ctr: 0,
	},
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000001",
		nonce: "000000000000000000000002",
		msg: "416e79207375626d697373696f6e2074" +
			"6f20746865204945544620696e74656e" +
			"6465642062792074686520436f6e7472" +
			"696275746f7220666f72207075626c69" +
			"636174696f6e20617320616c6c206f72" +
			"2070617274206f6620616e2049455446" +
			"20496e7465726e65742d447261667420" +
			"6f722052464320616e6420616e792073" +
			"746174656d656e74206d616465207769" +
			"7468696e2074686520636f6e74657874" +
			"206f6620616e20494554462061637469" +
			"7669747920697320636f6e7369646572" +
			"656420616e20224945544620436f6e74" +
			"7269627574696f6e222e205375636820" +
			"73746174656d656e747320696e636c75" +
			"6465206f72616c2073746174656d656e" +
			"747320696e2049455446207365737369" +
			"6f6e732c2061732077656c6c20617320" +
			"7772697474656e20616e6420656c6563" +
			"74726f6e696320636f6d6d756e696361" +
			"74696f6e73206d61646520617420616e" +
			"792074696d65206f7220706c6163652c" +
			"20776869636820617265206164647265" +
			"7373656420746f",
		ciphertext: "a3fbf07df3fa2fde4f376ca23e827370" +
			"41605d9f4f4f57bd8cff2c1d4b7955ec" +
			"2a97948bd3722915c8f3d337f7d37005" +
			"0e9e96d647b7c39f56e031ca5eb6250d" +
			"4042e02785ececfa4b4bb5e8ead0440e" +
			"20b6e8db09d881a7c6132f420e527950" +
			"42bdfa7773d8a9051447b3291ce1411c" +
			"680465552aa6c405b7764d5e87bea85a" +
			"d00f8449ed8f72d0d662ab052691ca66" +
			"424bc86d2df80ea41f43abf937d3259d" +
			"c4b2d0dfb48a6c9139ddd7f76966e928" +
			"e635553ba76c5c879d7b35d49eb2e62b" +
			"0871cdac638939e25e8a1e0ef9d5280f" +
			"a8ca328b351c3c765989cbcf3daa8b6c" +
			"cc3aaf9f3979c92b3720fc88dc95ed84" +
			"a1be059c6499b9fda236e7e818b04b0b" +
			"c39c1e876b193bfe5569753f88128cc0" +
			"8aaa9b63d1a16f80ef2554d7189c411f" +
			"5869ca52c5b83fa36ff216b9c1d30062" +
			"bebcfd2dc5bce0911934fda79a86f6e6" +
			"98ced759c3ff9b6477338f3da4f9cd85" +
			"14ea9982ccafb341b2384dd902f3d1ab" +
			"7ac61dd29c6f21ba5b862f3730e37cfd" +
			"c4fd806c22f221",
		ctr: 1,
	},
	{
		key:   "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
		nonce: "000000000000000000000002",
		msg: "2754776173206272696c6c69672c2061" +
			"6e642074686520736c6974687920746f" +
			"7665730a446964206779726520616e64" +
			"2067696d626c6520696e207468652077" +
			"6162653a0a416c6c206d696d73792077" +
			"6572652074686520626f726f676f7665" +
			"732c0a416e6420746865206d6f6d6520" +
			"7261746873206f757467726162652e",
		ciphertext: "62e6347f95ed87a45ffae7426f27a1df" +
			"5fb69110044c0d73118effa95b01e5cf" +
			"166d3df2d721caf9b21e5fb14c616871" +
			"fd84c54f9d65b283196c7fe4f60553eb" +
			"f39c6402c42234e32a356b3e764312a6" +
			"1a5532055716ead6962568f87d3f3f77" +
			"04c6a8d1bcd1bf4d50d6154b6da731b1" +
			"87b58dfd728afa36757a797ac188d1",
		ctr: 42,
	},
}

// From https://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-01
var testVectors8Nonce = []struct {
	key, nonce, stream string
}{
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "0000000000000000",
		stream: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
			"da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586" +
			"9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed" +
			"29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "0000000000000000",
		stream: "c5d30a7ce1ec119378c84f487d775a8542f13ece238a9455e8229e888de85bbd" +
			"29eb63d0a17a5b999b52da22be4023eb07620a54f6fa6ad8737b71eb0464dac0" +
			"10f656e6d1fd55053e50c4875c9930a33f6d0263bd14dfd6ab8c70521c19338b" +
			"2308b95cf8d0bb7d202d2102780ea3528f1cb48560f76b20f382b942500fceac",
	},
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "0100000000000000",
		stream: "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32" +
			"111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b" +
			"5305e5e44aff19b235936144675efbe4409eb7e8e5f1430f5f5836aeb49bb532" +
			"8b017c4b9dc11f8a03863fa803dc71d5726b2b6b31aa32708afe5af1d6b69058",
	},
	{
		key:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		nonce: "ffffffffffffffff",
		stream: "d9bf3f6bce6ed0b54254557767fb57443dd4778911b606055c39cc25e674b836" +
			"3feabc57fde54f790c52c8ae43240b79d49042b777bfd6cb80e931270b7f50eb" +
			"5bac2acd86a836c5dc98c116c1217ec31d3a63a9451319f097f3b4d6dab07787" +
			"19477d24d24b403a12241d7cca064f790f1d51ccaff6b1667d4bbca1958c4306",
	},
}

// Test vector from:
// https://tools.ietf.org/html/rfc7539#section-2.8.2
var testVectorsAEAD = []struct {
	key, nonce, data string
	msg, ciphertext  string
	tagSize          int
}{
	{
		key: "808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
		nonce: "070000004041424344454647",
		data:  "50515253c0c1c2c3c4c5c6c7",
		msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069742e",
		ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116" +
			"1ae10b594f09e26a7e902ecbd0600691", // poly 1305 tag
		tagSize: TagSize,
	},
	{
		key: "808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
		nonce: "070000004041424344454647",
		data:  "50515253c0c1c2c3c4c5c6c7",
		msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069742e",
		ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116" +
			"1ae10b594f09e26a7e902ecb", // poly 1305 tag
		tagSize: 12,
	},
}

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

func BenchmarkCipher64(b *testing.B)       { benchmarkCipher(b, 64) }
func BenchmarkCipher1K(b *testing.B)       { benchmarkCipher(b, 1024) }
func BenchmarkXORKeyStream64(b *testing.B) { benchmarkXORKeyStream(b, 64) }
func BenchmarkXORKeyStream1K(b *testing.B) { benchmarkXORKeyStream(b, 1024) }
