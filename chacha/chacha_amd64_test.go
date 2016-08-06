// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64

package chacha

import (
	"runtime"
	"strings"
)

var testFuncs = map[string]func(*testing.T){
	"TestCore":         TestCore,
	"TestXorBlocks":    TestXorBlocks,
	"TestXORKeyStream": TestXORKeyStream,
}

func TestSSE2(t *testing.T) {
	SSSE3 := useSSSE3
	AVX2 := useAVX2
	useSSSE3, AVX2 = false, false
	for _, v := range testFuncs {
		v(t)
	}
	useSSSE3, useAVX2 = SSSE3, AVX2
}

func TestSSSE3(t *testing.T) {
	if !useSSSE3 {
		t.Log("CPU does not support SSSE3 - cannot test SSSE3")
	}
	AVX2 := useAVX2
	AVX2 = false
	for _, v := range testFuncs {
		v(t)
	}
	useAVX2 = AVX2
}

func TestAVX2(t *testing.T) {
	if !useAVX2 {
		t.Log("CPU does not support AVX2 - cannot test AVX2")
	}
	if v := runtime.Version(); !strings.HasPrefix(v, "go1.7") {
		t.Logf("Go version: %s < go1.7 - cannot test AVX2", v)
	}
	// if useAVX2 && version >= 1.7 -> AVX2 is always used.
}
