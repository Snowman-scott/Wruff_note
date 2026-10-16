package crypto

import (
	"bytes"
	"testing"
)

var (
	password = []byte("password123")
	ogData   = []byte("Hello World")
)

func TestSaltLen(t *testing.T) {
	salt, err := GenSalt()
	if err != nil {
		t.Fatalf("FAIL: Salt Failed to salt.\n%v", err)
	}
	if len(salt) != int(SaltLen) {
		t.Fatal("FAIL: Salt length was not 16")
	}
}

func TestDeriveKey(t *testing.T) {
	salt1, err := GenSalt()
	if err != nil {
		t.Fatalf("FAIL: Salt Failed to salt.\n%v", err)
	}
	salt2, err := GenSalt()
	if err != nil {
		t.Fatalf("FAIL: Salt Failed to salt.\n%v", err)
	}

	key1 := DeriveKey(password, salt1)
	key2 := DeriveKey(password, salt1)

	if !bytes.Equal(key1, key2) {
		t.Fatal("FAIL: Identical inputs produced different keys!")
	}

	key3 := DeriveKey(password, salt2)

	if bytes.Equal(key1, key3) {
		t.Fatal("FAIL: Changing the salt did not change the key!")
	}
}

func TestCallsDiffer(t *testing.T) {
	salt1, err := GenSalt()
	if err != nil {
		t.Fatalf("FAIL: Salt Failed to salt.\n%v", err)
	}
	salt2, err := GenSalt()
	if err != nil {
		t.Fatalf("FAIL: Salt Failed to salt.\n%v", err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Fatal("FAIL: Salts were the Same!")
	}
}

func TestRoundTrip(t *testing.T) {
	usrSalt, err := GenSalt()
	if err != nil {
		t.Fatalf("FAIL: Salt failed to generate.\n%v", err)
	}

	derKey := DeriveKey(password, usrSalt)

	encrypted, err := Encrypt(ogData, derKey)
	if err != nil {
		t.Fatalf("FAIL: Encrypting data failed.\n%v", err)
	}

	decrypted, err := Decrypt(encrypted, derKey)
	if err != nil {
		t.Fatalf("FAIL: Decrypt failed.\n%v", err)
	}

	if bytes.Equal(decrypted, ogData) != true {
		t.Fatalf("FAIL: decrypted data is not the same as the original data.\n")
	}
}

func TestWrongKey(t *testing.T) {
	salt, err := GenSalt()
	if err != nil {
		t.Fatalf("salt failed to generate: %v", err)
	}

	goodKey := DeriveKey(password, salt)
	badKey := DeriveKey([]byte("not the password"), salt)

	encrypted, err := Encrypt(ogData, goodKey)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, badKey)
	if err == nil {
		t.Fatalf("expected an error with the wrong key, got plaintext %q", decrypted)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	salt, err := GenSalt()
	if err != nil {
		t.Fatalf("salt failed to generate: %v", err)
	}

	key := DeriveKey(password, salt)

	encrypted, err := Encrypt(ogData, key)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// nonce area, middle, and the tag at the very end
	positions := []int{0, len(encrypted) / 2, len(encrypted) - 1}

	for _, pos := range positions {
		tampered := make([]byte, len(encrypted))
		copy(tampered, encrypted)
		tampered[pos] ^= 0xFF

		if _, err := Decrypt(tampered, key); err == nil {
			t.Errorf("expected an error after flipping byte %d, got none", pos)
		}
	}
}

func TestTooShort(t *testing.T) {
	salt, err := GenSalt()
	if err != nil {
		t.Fatalf("salt failed to generate: %v", err)
	}

	key := DeriveKey(password, salt)

	// a panic here fails the test automatically
	for _, blob := range [][]byte{nil, {}, make([]byte, 5)} {
		if _, err := Decrypt(blob, key); err == nil {
			t.Errorf("expected an error for a %d byte blob, got none", len(blob))
		}
	}
}
