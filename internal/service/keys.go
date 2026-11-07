package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// InitKeys generates an age X25519 identity at keysPath with mode 0600 and
// returns the matching public recipient. It never prints or returns the
// secret identity itself.
func InitKeys(keysPath string, force bool) (string, error) {
	dir := filepath.Dir(keysPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create key directory: %w", err)
	}
	// #nosec G302 -- the key directory must be traversable only by its owner.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("secure key directory: %w", err)
	}

	if !force {
		if _, err := os.Stat(keysPath); err == nil {
			return "", ErrKeysExist
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("inspect identity file: %w", err)
		}
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generate age identity: %w", err)
	}
	content := []byte(identity.String() + "\n")
	if err := writeAtomic(keysPath, content, 0o600); err != nil {
		return "", fmt.Errorf("write identity file: %w", err)
	}
	return identity.Recipient().String(), nil
}

// LoadIdentity reads the age identity, refusing files that are readable by
// anyone other than the owner.
func LoadIdentity(keysPath string) (age.Identity, error) {
	info, err := os.Stat(keysPath)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("identity path %s is not a regular file", keysPath)
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("identity file %s must have mode 0600 (found %04o)", keysPath, info.Mode().Perm())
	}
	// #nosec G304 -- the path is the configured identity location.
	data, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	if len(identities) != 1 {
		return nil, fmt.Errorf("identity file must contain exactly one identity (found %d)", len(identities))
	}
	return identities[0], nil
}
