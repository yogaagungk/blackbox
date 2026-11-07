package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func sealFixture(t *testing.T) (dir, keysPath, recipient, envPath, lockPath string) {
	t.Helper()
	dir = t.TempDir()
	keysPath = filepath.Join(dir, "keys.txt")
	var err error
	recipient, _, err = InitKeys(keysPath, false)
	if err != nil {
		t.Fatal(err)
	}
	return dir, keysPath, recipient, filepath.Join(dir, ".env"), filepath.Join(dir, ".env.lock")
}

func TestSealUnsealRoundTrip(t *testing.T) {
	dir, keysPath, recipient, envPath, lockPath := sealFixture(t)
	plaintext := []byte("A=1\nSECRET_TOKEN=super-secret\n")
	if err := os.WriteFile(envPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	size, err := SealFile(envPath, lockPath, recipient, false)
	if err != nil {
		t.Fatalf("SealFile: %v", err)
	}
	if size != int64(len(plaintext)) {
		t.Errorf("sealed size = %d, want %d", size, len(plaintext))
	}

	// #nosec G304 -- path is built by the test itself.
	locked, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(locked, []byte("super-secret")) {
		t.Error("ciphertext contains plaintext")
	}
	lockInfo, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := lockInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("lock mode = %04o, want 0644", got)
	}

	outPath := filepath.Join(dir, "restored.env")
	n, err := UnsealFile(lockPath, outPath, keysPath, false, false)
	if err != nil {
		t.Fatalf("UnsealFile: %v", err)
	}
	if n != int64(len(plaintext)) {
		t.Errorf("unsealed size = %d, want %d", n, len(plaintext))
	}
	// #nosec G304 -- path is built by the test itself.
	restored, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Errorf("round-trip mismatch: %q", restored)
	}
	outInfo, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := outInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("output mode = %04o, want 0600", got)
	}

	otherKeys := filepath.Join(dir, "other-keys.txt")
	if _, _, err := InitKeys(otherKeys, false); err != nil {
		t.Fatal(err)
	}
	if _, err := UnsealFile(lockPath, filepath.Join(dir, "wrong.env"), otherKeys, false, false); err == nil {
		t.Error("expected decryption to fail with the wrong identity")
	}
}

func TestSealUnsealDryRunWritesNothing(t *testing.T) {
	dir, keysPath, recipient, envPath, lockPath := sealFixture(t)
	plaintext := []byte("A=1\n")
	if err := os.WriteFile(envPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	size, err := SealFile(envPath, lockPath, recipient, true)
	if err != nil {
		t.Fatalf("dry-run seal: %v", err)
	}
	if size != int64(len(plaintext)) {
		t.Errorf("size = %d", size)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("dry-run seal wrote the lock file")
	}

	if _, err := SealFile(envPath, lockPath, recipient, false); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "dry.env")
	n, err := UnsealFile(lockPath, outPath, keysPath, true, false)
	if err != nil {
		t.Fatalf("dry-run unseal: %v", err)
	}
	if n != int64(len(plaintext)) {
		t.Errorf("dry-run unseal size = %d", n)
	}
	if _, err := os.Stat(outPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("dry-run unseal wrote the output file")
	}
}

func TestUnsealRefusesOverwriteWithoutForce(t *testing.T) {
	dir, keysPath, recipient, envPath, lockPath := sealFixture(t)
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SealFile(envPath, lockPath, recipient, false); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "existing.env")
	if err := os.WriteFile(outPath, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UnsealFile(lockPath, outPath, keysPath, false, false); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("error = %v, want ErrDestinationExists", err)
	}
	if _, err := UnsealFile(lockPath, outPath, keysPath, false, true); err != nil {
		t.Fatalf("forced unseal: %v", err)
	}
}

func TestSealRejectsBadInputs(t *testing.T) {
	dir, _, _, envPath, lockPath := sealFixture(t)
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SealFile(envPath, lockPath, "not-a-recipient", false); err == nil {
		t.Error("expected invalid recipient error")
	}
	if _, err := SealFile(envPath, envPath, "age1xyz", false); err == nil {
		t.Error("expected same-path error")
	}
	if _, err := SealFile(filepath.Join(dir, "missing.env"), lockPath, "age1xyz", false); err == nil {
		t.Error("expected missing source error")
	}
}
