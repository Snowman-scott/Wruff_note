package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	argonMem    uint32 = 64 * 1024
	argonTime   uint32 = 3
	argonThread uint8  = 4
	KeyLen      uint32 = 32
	SaltLen     uint32 = 16
)

func GenSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("puppy Says... It bwoke %v", err)
	}
	return salt, nil
}

func DeriveKey(password []byte, salt []byte) []byte {
	hash := argon2.IDKey(password, salt, argonTime, argonMem, argonThread, KeyLen)
	return hash
}

func Encrypt(data, password []byte) ([]byte, error) {

}
