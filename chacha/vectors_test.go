// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha

import "encoding/hex"

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
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		keystream: "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e" +
			"984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42",
		counter: 0,
		rounds:  8,
	},
	{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		keystream: "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f" +
			"0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be",
		counter: 0,
		rounds:  12,
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		keystream: "cf5ee9a0494aa9613e05d5ed725b804b12f4a465ee635acc3a311de8740489ea" +
			"289d04f43c7518db56eb4433e498a1238cd8464d3763ddbb9222ee3bd8fae3c8",
		counter: 0,
		rounds:  8,
	},
	{
		key:   "0100000000000000000000000000000000000000000000000000000000000000",
		nonce: "000000000000000000000000",
		keystream: "12056e595d56b0f6eef090f0cd25a20949248c2790525d0f930218ff0b4ddd10" +
			"a6002239d9a454e29e107a7d06fefdfef0210feba044f9f29b1772c960dc29c0",
		counter: 0,
		rounds:  12,
	},
}
