package service

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// SealSecret implements libsodium crypto_box_seal: it encrypts plaintext to a
// GitHub repository public key (base64, 32 bytes) using an anonymous ephemeral
// keypair. randomness may be nil; tests inject a deterministic reader.
func SealSecret(publicKey string, plaintext []byte, randomness io.Reader) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil {
		return "", fmt.Errorf("decode repository public key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("repository public key must be 32 bytes (got %d)", len(raw))
	}
	var recipient [32]byte
	copy(recipient[:], raw)

	if randomness == nil {
		randomness = cryptorand.Reader
	}
	sealed, err := box.SealAnonymous(nil, plaintext, &recipient, randomness)
	if err != nil {
		return "", fmt.Errorf("seal secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}
