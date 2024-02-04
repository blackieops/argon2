package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("the encoded value is not in a supported format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

// Argon2Digest stores the parameters and hash digest for a password.
type Argon2Digest struct {
	iterations uint32
	memory     uint32
	threads    uint8
	keyLength  uint32
	saltLength uint32
	Digest     []byte
	Salt       []byte
}

func (a *Argon2Digest) generateSalt() error {
	salt := make([]byte, a.saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}
	a.Salt = salt
	return nil
}

func (a *Argon2Digest) GenerateDigest(raw []byte) error {
	err := a.generateSalt()
	if err != nil {
		return err
	}
	a.Digest = argon2.IDKey(raw, a.Salt, a.iterations, a.memory, a.threads, a.keyLength)
	return nil
}

func (a *Argon2Digest) Compare(raw string) bool {
	return a.CompareBytes([]byte(raw))
}

func (a *Argon2Digest) CompareBytes(raw []byte) bool {
	provided := argon2.IDKey(raw, a.Salt, a.iterations, a.memory, a.threads, a.keyLength)
	return subtle.ConstantTimeCompare(a.Digest, provided) == 1
}

// String encodes the Argon2 hash using the standard encoded representation, as
// per the official CLI:
// https://github.com/P-H-C/phc-winner-argon2/tree/f57e61e19229e23c4445b85494dbf7c07de721cb#command-line-utility
func (a *Argon2Digest) String() string {
	saltDigest := base64.RawStdEncoding.EncodeToString(a.Salt)
	hashDigest := base64.RawStdEncoding.EncodeToString(a.Digest)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.memory,
		a.iterations,
		a.threads,
		saltDigest,
		hashDigest,
	)
}

// NewArgon2Digest generates an Argon2Digest struct using default params.
func New() *Argon2Digest {
	return &Argon2Digest{
		iterations: 3,
		saltLength: 16,
		memory:     32 * 1024,
		threads:    4,
		keyLength:  32,
	}
}

func NewFromString(raw string) *Argon2Digest {
	return NewFromBytes([]byte(raw))
}

func NewFromBytes(raw []byte) *Argon2Digest {
	d := New()
	d.GenerateDigest(raw)
	return d
}

func NewFromEncoded(encoded string) (*Argon2Digest, error) {
	vals := strings.Split(encoded, "$")
	if len(vals) != 6 {
		return nil, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, err
	}
	if version != argon2.Version {
		return nil, ErrIncompatibleVersion
	}

	d := New()
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &d.memory, &d.iterations, &d.threads)
	if err != nil {
		return nil, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, err
	}
	d.Salt = salt
	d.saltLength = uint32(len(salt))

	digest, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, err
	}
	d.Digest = digest
	d.keyLength = uint32(len(digest))

	return d, nil
}
