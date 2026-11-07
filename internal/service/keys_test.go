package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitKeysCreatesSecureIdentity(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), ".blackbox", "keys.txt")

	recipient, notice, err := InitKeys(keysPath, false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	if notice != "" {
		t.Errorf("unexpected notice: %s", notice)
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
	first, _, err := InitKeys(keysPath, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := InitKeys(keysPath, false); err == nil {
		t.Fatal("expected ErrKeysExist")
	}
	second, _, err := InitKeys(keysPath, true)
	if err != nil {
		t.Fatalf("force InitKeys: %v", err)
	}
	if second == first {
		t.Error("forced init did not rotate the identity")
	}
}

func TestInitKeysLeavesExistingDirectoryModeAlone(t *testing.T) {
	dir := t.TempDir()
	// #nosec G302 -- the test deliberately uses an open project directory.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, "keys.txt")

	_, notice, err := InitKeys(keysPath, false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	if !strings.Contains(notice, "group/world") {
		t.Errorf("notice = %q, want a permission warning", notice)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Errorf("pre-existing dir mode changed to %04o", got)
	}
}

func TestLoadIdentityAcceptsReadOnlyKey(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), "keys.txt")
	if _, _, err := InitKeys(keysPath, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keysPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(keysPath); err != nil {
		t.Errorf("0400 identity rejected: %v", err)
	}
	if _, err := LoadRecipient(keysPath); err != nil {
		t.Errorf("LoadRecipient: %v", err)
	}
}

func TestLoadIdentityRejectsPermissiveMode(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), "keys.txt")
	if _, _, err := InitKeys(keysPath, false); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- the test deliberately weakens the mode.
	if err := os.Chmod(keysPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(keysPath); err == nil || !strings.Contains(err.Error(), "0600 or 0400") {
		t.Fatalf("error = %v, want a mode rejection", err)
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

func TestBackupKeyKeepsUsableCopy(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), "keys.txt")
	recipient, _, err := InitKeys(keysPath, false)
	if err != nil {
		t.Fatal(err)
	}

	backup, err := BackupKey(keysPath)
	if err != nil {
		t.Fatalf("BackupKey: %v", err)
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("backup mode = %04o, want 0600", got)
	}
	oldRecipient, err := LoadRecipient(backup)
	if err != nil {
		t.Fatalf("LoadRecipient backup: %v", err)
	}
	if oldRecipient != recipient {
		t.Error("backup does not hold the old identity")
	}

	newRecipient, _, err := InitKeys(keysPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if newRecipient == recipient {
		t.Error("rotation reused the same key")
	}
	if err := RestoreKey(backup, keysPath); err != nil {
		t.Fatalf("RestoreKey: %v", err)
	}
	restored, err := LoadRecipient(keysPath)
	if err != nil || restored != recipient {
		t.Errorf("restored recipient = %q, err = %v", restored, err)
	}
}
