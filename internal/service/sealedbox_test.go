package service

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// Vector derived from RFC 7748's Alice X25519 key and a deterministic
// randomness reader; generated once and pinned to catch accidental changes to
// the sealed-box construction.
const (
	vectorPrivateKey = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	vectorPublicKey  = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
	vectorSealed     = "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF82ZqwhwoRUaRqBGrqJQ8xXiqAOxWe/yR3NMgs="
)

func TestSealSecretKnownVector(t *testing.T) {
	random := make([]byte, 64)
	for i := range random {
		random[i] = byte(i)
	}

	sealed, err := SealSecret(vectorPublicKey, []byte("hello world"), bytes.NewReader(random))
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	if sealed != vectorSealed {
		t.Fatalf("sealed = %q, want %q", sealed, vectorSealed)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := hex.DecodeString(vectorPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(vectorPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var privateKey, publicKey [32]byte
	copy(privateKey[:], privateBytes)
	copy(publicKey[:], publicBytes)

	opened, ok := box.OpenAnonymous(nil, ciphertext, &publicKey, &privateKey)
	if !ok {
		t.Fatal("known vector does not decrypt")
	}
	if string(opened) != "hello world" {
		t.Errorf("opened = %q", opened)
	}
}

func TestSealSecretRandomRoundTrip(t *testing.T) {
	publicKey, privateKey, err := box.GenerateKey(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	_ = privateKey
	encoded := base64.StdEncoding.EncodeToString(publicKey[:])

	sealed, err := SealSecret(encoded, []byte("value"), nil)
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	ciphertext, _ := base64.StdEncoding.DecodeString(sealed)
	if _, ok := box.OpenAnonymous(nil, ciphertext, publicKey, privateKey); !ok {
		t.Fatal("round-trip failed")
	}
}

func TestSealSecretRejectsBadKeys(t *testing.T) {
	if _, err := SealSecret("not base64", []byte("x"), nil); err == nil {
		t.Error("expected base64 error")
	}
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := SealSecret(short, []byte("x"), nil); err == nil {
		t.Error("expected length error")
	}
}
