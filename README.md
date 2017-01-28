[![Godoc Reference](https://godoc.org/github.com/aead/chacha20?status.svg)](https://godoc.org/github.com/aead/chacha20)

## The ChaCha20 stream cipher

ChaCha is a stream cipher family created by Daniel J. Bernstein. The most common ChaCha cipher is ChaCha20 (20 rounds). 
ChaCha20 is standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539").

This package implements the three ChaCha versions:  
    - ChaCha20 with a 64 bit nonce (can en/decrypt up to 2^64 * 64 bytes for one key-nonce combination)  
    - ChaCha20 with a 96 bit nonce (can en/decrypt up to 2^32 * 64 bytes ~ 256 GB for one key-nonce combination)  
    - XChaCha20 with a 192 bit nonce (can en/decrypt up to 2^64 * 64 bytes for one key-nonce combination)  

Furthermore the chacha subpackage implements ChaCha20/12 and ChaCha20/8.
These versions use 12 or 8 rounds instead of 20.
But it's recommended to use ChaCha20 (with 20 rounds) - it will be fast enough for almost all purposes. 

### Installation 
Install in your GOPATH: `go get -u github.com/aead/chacha20`

### Requirements
All go versions >= 1.5.3 are supported.
Please notice, that the AVX2 implementation requires go1.7 or newer.

The code is tested on amd64, x86 and arm.

### What about AEAD?
Whenever possible authenticated encryption should be preferred to non-auth. encryption.
ChaCha20 (and all variants), as a stream cipher, performs non-auth. encryption.

But good news: There's an AEAD scheme using ChaCha20. It's called ChaCha20Poly1305 and is
specified in [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539").

The offical golang sub-repo [x/crypto](https://godoc.org/golang.org/x/crypto/chacha20poly1305 "x/crypto")
implements ChaCha20Poly1305 - so I recommend to use this AEAD implementation instead of this "plain"
ChaCha20 implementation whenever possible. 
