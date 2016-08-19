[![Godoc Reference](https://godoc.org/github.com/aead/chacha20?status.svg)](https://godoc.org/github.com/aead/chacha20)

## The ChaCha20 stream cipher

ChaCha is a stream cipher family created by Daniel J. Bernstein. The most common ChaCha cipher is
ChaCha20 (20 rounds). ChaCha20 is standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539").

## The ChaCha20Poly1305 AEAD construction

[RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539") describes the combination
of the ChaCha20 stream cipher and the Poly1305 MAC to an AEAD cipher.

This code is now stable (reached v1.0) and can be used in productive environments.
Backward compatibility is now guaranteed.

### Requirements
Following Go versions are supported:
 - 1.5.3
 - 1.5.4
 - 1.6.x
 - 1.7

Notice, that the code is only tested on amd64 and x86.
On amd64 machines the CPU feature [SSE2](https://en.wikipedia.org/wiki/SSE2 "Wikipedia") is required. 

### Installation
Install in your GOPATH: `go get -u github.com/aead/chacha20`  

### Performance
Benchmarks are run on a Intel i7-6500U (Sky Lake) on linux/amd64 with Go 1.6.3 / 1.7  
AVX2 is only available for Go 1.7 and upper. See [Go 1.7 release notes](https://tip.golang.org/doc/go1.7) 
```
Using AVX2 (Go 1.7)
BenchmarkSeal64B-4           170.64 MB/s
BenchmarkSeal1K-4            865.49 MB/s
BenchmarkOpen64B-4           164.63 MB/s
BenchmarkOpen1K-4            857.50 MB/s
BenchmarkCipher64-4          587.61 MB/s
BenchmarkCipher1K-4         1878.63 MB/s
BenchmarkXORKeyStream64-4    408.73 MB/s
BenchmarkXORKeyStream1K-4   1718.45 MB/s

Using SSSE3:
BenchmarkSeal64B-4           171.23 MB/s
BenchmarkSeal1K-4            658.43 MB/s
BenchmarkOpen64B-4           165.42 MB/s
BenchmarkOpen1K-4            654.14 MB/s
BenchmarkCipher64-4          584.47 MB/s
BenchmarkCipher1K-4         1120.61 MB/s
BenchmarkXORKeyStream64-4    407.23 MB/s
BenchmarkXORKeyStream1K-4   1059.94 MB/s

Using only SSE2:
BenchmarkSeal64B-4           157.92 MB/s
BenchmarkSeal1K-4            573.21 MB/s
BenchmarkOpen64B-4           152.90 MB/s
BenchmarkOpen1K-4            570.28 MB/s
BenchmarkCipher64-4          511.47 MB/s
BenchmarkCipher1K-4          906.00 MB/s
BenchmarkXORKeyStream64-4    368.72 MB/s
BenchmarkXORKeyStream1K-4    860.98 MB/s
```
