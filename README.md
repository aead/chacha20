[![Godoc Reference](https://godoc.org/github.com/aead/chacha20?status.svg)](https://godoc.org/github.com/aead/chacha20)

## The ChaCha20 stream cipher

ChaCha is a stream cipher family created by Daniel J. Bernstein. The most common ChaCha cipher is
ChaCha20 (20 rounds). ChaCha20 is standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539").

## The ChaCha20Poly1305 AEAD construction

[RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539") describes the combination
of the ChaCha20 stream cipher and the Poly1305 MAC to an AEAD cipher.

This code is now stable and can be used in productive environments.
Backward compatibility is now guaranteed.

### Requirements
Following Go versions are supported:
 - 1.5.3
 - 1.5.4
 - 1.6.x
 - 1.7.x

Notice, that the code is only tested on amd64 and x86.

### Installation
Install in your GOPATH: `go get -u github.com/aead/chacha20`  

### Performance
Benchmarks are run on a Intel i7-6500U (Sky Lake) on linux/amd64 with Go 1.7  
AVX2 is only available for Go 1.7 and upper. See [Go 1.7 release notes](https://tip.golang.org/doc/go1.7) 
```
Using AVX2
name                    time/op      name                       speed
Seal64B-4            359ns ± 0%      Seal64B-4          178 MB/s ± 0%
Seal1K-4            1.10µs ± 0%      Seal1K-4           928 MB/s ± 0%
Open64B-4            372ns ± 0%      Open64B-4          172 MB/s ± 0%
Open1K-4            1.12µs ± 0%      Open1K-4           914 MB/s ± 0%
Cipher64-4           110ns ± 0%      Cipher64-4         580 MB/s ± 0%
Cipher1K-4           470ns ± 0%      Cipher1K-4        2.17 GB/s ± 0%
XORKeyStream64-4     156ns ± 0%      XORKeyStream64-4   408 MB/s ± 1%
XORKeyStream1K-4     521ns ± 0%      XORKeyStream1K-4  1.96 GB/s ± 0%

Using SSSE3:
name              	    time/op      name                       speed
Seal64B-4            358ns ± 0%      Seal64B-4          178 MB/s ± 0%
Seal1K-4            1.55µs ± 0%      Seal1K-4           660 MB/s ± 0%
Open64B-4            372ns ± 0%      Open64B-4          172 MB/s ± 0%
Open1K-4            1.58µs ± 0%      Open1K-4           649 MB/s ± 0%
Cipher64-4           110ns ± 0%      Cipher64-4         580 MB/s ± 0%
Cipher1K-4           924ns ± 0%      Cipher1K-4        1.11 GB/s ± 0%
XORKeyStream64-4     156ns ± 0%      XORKeyStream64-4   410 MB/s ± 0%
XORKeyStream1K-4     972ns ± 0%      XORKeyStream1K-4  1.05 GB/s ± 0%

Using SSE2:
name                   time/op       name                       speed
Seal64B-4           388ns ± 0%       Seal64B-4          164 MB/s ± 0%
Seal1K-4           1.89µs ± 4%       Seal1K-4           543 MB/s ± 4%
Open64B-4           403ns ± 0%       Open64B-4          159 MB/s ± 0%
Open1K-4           1.83µs ± 0%       Open1K-4           558 MB/s ± 0%
Cipher64-4          125ns ± 0%       Cipher64-4         509 MB/s ± 0%
Cipher1K-4         1.18µs ± 0%       Cipher1K-4         868 MB/s ± 0%
XORKeyStream64-4    172ns ± 0%       XORKeyStream64-4   371 MB/s ± 0%
XORKeyStream1K-4   1.23µs ± 0%       XORKeyStream1K-4   835 MB/s ± 0%
```
