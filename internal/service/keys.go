package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// InitKeys generates an age X25519 identity at keysPath with mode 0600 and
// returns the matching public recipient. notice reports a non-fatal directory
// permission warning. The secret identity is never returned.
func InitKeys(keysPath string, force bool) (recipient, notice string, err error) {
	notice, err = ensureKeyDir(filepath.Dir(keysPath))
	if err != nil {
		return "", "", err
	}

	if !force {
		if _, statErr := os.Stat(keysPath); statErr == nil {
			return "", notice, ErrKeysExist
		} else if !os.IsNotExist(statErr) {
			return "", notice, fmt.Errorf("inspect identity file: %w", statErr)
		}
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", notice, fmt.Errorf("generate age identity: %w", err)
	}
	if err := WriteAtomic(keysPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		return "", notice, fmt.Errorf("write identity file: %w", err)
	}
	return identity.Recipient().String(), notice, nil
}

// ensureKeyDir creates the key directory with 0700 when missing. Existing
// directories are never chmodded (the parent may be the project directory);
// an overly open mode only produces a warning.
func ensureKeyDir(dir string) (string, error) {
	info, err := os.Stat(dir)
	switch {
	case err == nil:
		if !info.IsDir() {
			return "", fmt.Errorf("key path parent %s is not a directory", dir)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Sprintf("key directory %s is group/world accessible (%04o); chmod 700 %s",
				dir, info.Mode().Perm(), dir), nil
		}
		return "", nil
	case errors.Is(err, os.ErrNotExist):
		if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
			return "", fmt.Errorf("create key directory: %w", mkErr)
		}
		// Only directories created here are tightened.
		// #nosec G302 -- a key directory must be owner-only.
		if chErr := os.Chmod(dir, 0o700); chErr != nil {
			return "", fmt.Errorf("secure key directory: %w", chErr)
		}
		return "", nil
	default:
		return "", fmt.Errorf("inspect key directory: %w", err)
	}
}

// LoadIdentity reads the age identity, refusing files that are readable or
// executable by group or others. 0600 and 0400 are accepted.
func LoadIdentity(keysPath string) (age.Identity, error) {
	info, err := os.Stat(keysPath)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("identity path %s is not a regular file", keysPath)
	}
	switch perm := info.Mode().Perm(); perm {
	case 0o600, 0o400:
	default:
		return nil, fmt.Errorf("identity file %s must be 0600 or 0400 (found %04o)", keysPath, perm)
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

// LoadRecipient returns the public recipient for an existing identity file.
func LoadRecipient(keysPath string) (string, error) {
	identity, err := LoadIdentity(keysPath)
	if err != nil {
		return "", err
	}
	x25519, ok := identity.(*age.X25519Identity)
	if !ok {
		return "", fmt.Errorf("identity file does not contain an X25519 identity")
	}
	return x25519.Recipient().String(), nil
}

// BackupKey copies keysPath to a timestamped sibling with mode 0600 and
// returns the backup path.
func BackupKey(keysPath string) (string, error) {
	// #nosec G304 -- the path is the configured identity location.
	data, err := os.ReadFile(keysPath)
	if err != nil {
		return "", fmt.Errorf("read identity file: %w", err)
	}
	backup := keysPath + ".bak-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	if _, err := os.Stat(backup); err == nil {
		return "", fmt.Errorf("backup %s already exists", backup)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect backup path: %w", err)
	}
	if err := WriteAtomic(backup, data, 0o600); err != nil {
		return "", fmt.Errorf("write key backup: %w", err)
	}
	return backup, nil
}

// RestoreKey replaces keysPath with the contents of backupPath.
func RestoreKey(backupPath, keysPath string) error {
	// #nosec G304 -- both paths are chosen by the caller in the key directory.
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read key backup: %w", err)
	}
	if err := WriteAtomic(keysPath, data, 0o600); err != nil {
		return fmt.Errorf("restore identity file: %w", err)
	}
	return nil
}
