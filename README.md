[![Godoc Reference](https://godoc.org/github.com/aead/chacha20?status.svg)](https://godoc.org/github.com/aead/chacha20)

## The ChaCha20 stream cipher

ChaCha is a stream cipher family created by Daniel J. Bernstein. The most common ChaCha cipher is
ChaCha20 (20 rounds). ChaCha20 is standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539").

## The ChaCha20Poly1305 AEAD construction

[RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539") describes the combination
of the ChaCha20 stream cipher and the Poly1305 MAC to an AEAD cipher.

### Requirements
Following Go versions are supported:
 - 1.5.3
 - 1.5.4
 - 1.6.x
 - 1.7 (currently rc5) 

Notice, that the code is only tested on amd64 and x86.
On amd64 machines the CPU feature [SSE2](https://en.wikipedia.org/wiki/SSE2 "Wikipedia") is required. 

### Installation
Install in your GOPATH: `go get -u github.com/aead/chacha20`  

### Performance
Benchmarks are run on a Intel i7-6500U (Sky Lake) on linux/amd64 with Go 1.6.3 / 1.7rc5
AVX2 is only available for Go 1.7 and upper. See [Go 1.7rc5 release notes](https://tip.golang.org/doc/go1.7) 
```
Using AVX2 (Go 1.7rc5)
BenchmarkSeal64B-4            167.98 MB/s
BenchmarkSeal1K-4             821.10 MB/s
BenchmarkOpen64B-4            164.77 MB/s
BenchmarkOpen1K-4             824.25 MB/s
BenchmarkCipher64-4           577.03 MB/s
BenchmarkCipher16K-4         1926.29 MB/s
BenchmarkXORKeyStream64-4     403.98 MB/s
BenchmarkXORKeyStream16K-4   1911.63 MB/s

Using SSSE3:
BenchmarkSeal64B-4        	  160.13 MB/s
BenchmarkSeal1K-4         	  637.11 MB/s
BenchmarkOpen64B-4        	  152.56 MB/s
BenchmarkOpen1K-4         	  624.52 MB/s
BenchmarkCipher64-4       	  592.42 MB/s
BenchmarkCipher16K-4      	 1130.34 MB/s
BenchmarkXORKeyStream64-4 	  409.88 MB/s
BenchmarkXORKeyStream16K-4	 1125.41 MB/s

Using only SSE2:
BenchmarkSeal64B-4        	  147.87 MB/s
BenchmarkSeal1K-4         	  556.16 MB/s
BenchmarkOpen64B-4        	  142.78 MB/s
BenchmarkOpen1K-4         	  549.39 MB/s
BenchmarkCipher64-4       	  519.70 MB/s
BenchmarkCipher16K-4      	  912.12 MB/s
BenchmarkXORKeyStream64-4 	  369.23 MB/s
BenchmarkXORKeyStream16K-4	  909.42 MB/s
```
