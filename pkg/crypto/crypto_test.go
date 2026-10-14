package crypto

import (
	"bytes"
	"testing"
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
	password := []byte("Password123")
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
