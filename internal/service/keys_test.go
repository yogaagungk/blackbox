package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitKeysCreatesSecureIdentity(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), ".blackbox", "keys.txt")

	recipient, err := InitKeys(keysPath, false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	if !strings.HasPrefix(recipient, "age1") {
		t.Errorf("recipient = %q, want an age1 public key", recipient)
	}

	info, err := os.Stat(keysPath)
	if err != nil {
		t.Fatalf("stat keys: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("keys mode = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(keysPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("key dir mode = %04o, want 0700", got)
	}

	identity, err := LoadIdentity(keysPath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if identity == nil {
		t.Fatal("nil identity")
	}
}

func TestInitKeysRefusesExistingWithoutForce(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), "keys.txt")
	first, err := InitKeys(keysPath, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := InitKeys(keysPath, false); err == nil {
		t.Fatal("expected ErrKeysExist")
	}
	second, err := InitKeys(keysPath, true)
	if err != nil {
		t.Fatalf("force InitKeys: %v", err)
	}
	if second == first {
		t.Error("forced init did not rotate the identity")
	}
}

func TestLoadIdentityRejectsPermissiveMode(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), "keys.txt")
	if _, err := InitKeys(keysPath, false); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- the test deliberately weakens the mode.
	if err := os.Chmod(keysPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(keysPath); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("error = %v, want a 0600 mode rejection", err)
	}
}

func TestLoadIdentityRejectsGarbage(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(keysPath, []byte("not an identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(keysPath); err == nil {
		t.Fatal("expected parse error")
	}
}
