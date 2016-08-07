// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// This file declares all functions (implemented in assembly), necessary for amd64 systems.

package chacha

// setState builds the ChaCha state from the key, the nonce and the counter.
//go:noescape
func setState(state *[64]byte, key *[32]byte, nonce *[12]byte, counter uint32)

// cpuid returns the cx register after the CPUID instruction is executed.
//go:noescape
func cpuid() (cx uint32)

// xorBlocksSSE2 crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state.
//go:noescape
func xorBlocksSSE2(dst, src []byte, state *[64]byte, rounds int)

// xorBlocksSSSE3 crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state.
//go:noescape
func xorBlocksSSSE3(dst, src []byte, state *[64]byte, rounds int)

// coreSSE2 generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst.
func coreSSE2(dst *[64]byte, state *[64]byte, rounds int)

// coreSSSE3 generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst.
func coreSSSE3(dst *[64]byte, state *[64]byte, rounds int)
