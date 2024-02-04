# `go.b8s.dev/argon2`

This package provides a user-friendly interface to generate argon2 hashes and
digests, often useful for hashing secret values for safer storage.

## Installation

```
go get -u go.b8s.dev/argon2
```

## Usage

```go
var d *argon2.Argon2Digest
var err error

// Hash a string value
h = argon2.NewFromString("passw0rd123")

h.String()
// => $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG

// Hash bytes directly, such as from `crypto/rand`
h = argon2.NewFromBytes([]byte{1,2,3})

// Restore an *Argon2Digest from its hash
d, err = argon2.NewFromEncoded("$argon2i$v=19$m=....")

// Compare a raw value against its hash
h.Compare("passw0rd123") // => true
h.Compare("s3cr3t!") // => false
```
