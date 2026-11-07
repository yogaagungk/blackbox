package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	application := newApp(strings.NewReader(""), &stdout, &stderr)
	cmd := newRootCmd(application)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestCLIInitSealUnseal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())

	stdout, stderr, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(stdout, "recipient: age1") || !strings.Contains(stdout, "keys:") {
		t.Errorf("init output = %q", stdout)
	}
	if strings.Contains(stdout, "AGE-SECRET-KEY") || strings.Contains(stderr, "AGE-SECRET-KEY") {
		t.Fatal("init printed private key material")
	}

	keysPath := filepath.Join(home, ".blackbox", "keys.txt")
	info, err := os.Stat(keysPath)
	if err != nil {
		t.Fatalf("stat keys: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("keys mode = %04o, want 0600", got)
	}

	config, err := os.ReadFile(".blackbox.yaml")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(config), "recipient: age1") || !strings.Contains(string(config), "version: 1") {
		t.Errorf("config = %q", config)
	}
	gitignore, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatalf("read gitignore: %v", err)
	}
	if !strings.Contains(string(gitignore), ".env") {
		t.Errorf("gitignore = %q", gitignore)
	}

	plaintext := []byte("SECRET_TOKEN=super-secret\n")
	if err := os.WriteFile(".env", plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "seal"); err != nil {
		t.Fatalf("seal: %v", err)
	}
	locked, err := os.ReadFile(".env.lock")
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	if bytes.Contains(locked, []byte("super-secret")) {
		t.Fatal("sealed file contains plaintext")
	}

	if err := os.Remove(".env"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "unseal"); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	restored, err := os.ReadFile(".env")
	if err != nil {
		t.Fatalf("read restored env: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Errorf("restored = %q, want %q", restored, plaintext)
	}
}

func TestCLIInitRefusesOverwrite(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())

	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "init")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second init error = %v", err)
	}
}

func TestCLIDryRunWritesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())

	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "seal", "--dry-run")
	if err != nil {
		t.Fatalf("seal --dry-run: %v", err)
	}
	if !strings.Contains(stdout, "would seal") {
		t.Errorf("output = %q", stdout)
	}
	if _, err := os.Stat(".env.lock"); !os.IsNotExist(err) {
		t.Error("dry-run created .env.lock")
	}
}

func TestCLIUnsealForceAndOverwrite(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())

	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "seal"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := runCLI(t, "unseal"); err == nil {
		t.Fatal("unseal overwrote an existing .env without --force")
	}
	if _, _, err := runCLI(t, "unseal", "--force"); err != nil {
		t.Fatalf("unseal --force: %v", err)
	}
}

func TestCLIUnsealWithWrongHomeFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())

	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "seal"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(".env"); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir())
	if _, _, err := runCLI(t, "unseal"); err == nil {
		t.Fatal("unseal succeeded without the identity")
	}
}

func TestCLIUnsealRejectsPermissiveKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())

	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "seal"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(".env"); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- the test deliberately weakens the mode.
	if err := os.Chmod(filepath.Join(home, ".blackbox", "keys.txt"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, "unseal")
	if err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("error = %v, want a 0600 rejection", err)
	}
}

func TestCLIInitNoGitignore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())

	if _, _, err := runCLI(t, "init", "--no-gitignore"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(".gitignore"); !os.IsNotExist(err) {
		t.Error("--no-gitignore still wrote .gitignore")
	}
}

func TestCLIInitReusesIdentityAcrossProjects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	base := t.TempDir()
	t.Chdir(base)

	for _, dir := range []string{"project-a", "project-b"} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chdir("project-a"); err != nil {
		t.Fatal(err)
	}
	first, _, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init A: %v", err)
	}
	keysPath := filepath.Join(home, ".blackbox", "keys.txt")
	// #nosec G304 -- path is built by the test itself.
	keyBefore, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	configA, err := os.ReadFile(".blackbox.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir("../project-b"); err != nil {
		t.Fatal(err)
	}
	second, _, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init B: %v", err)
	}
	if !strings.Contains(second, "reusing existing identity") {
		t.Errorf("second init output = %q", second)
	}
	// #nosec G304 -- path is built by the test itself.
	keyAfter, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("second init rotated the shared identity")
	}
	configB, err := os.ReadFile(".blackbox.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(configA, recipientLine(configB)) {
		t.Errorf("projects use different recipients:\nA=%s\nB=%s", configA, configB)
	}
	_ = first
}

func recipientLine(config []byte) []byte {
	for _, line := range bytes.Split(config, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("recipient:")) {
			return line
		}
	}
	return nil
}

func TestCLIInitForceLeavesUsableBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())

	if _, _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SECRET=old-value\n")
	if err := os.WriteFile(".env", plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "seal"); err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(home, ".blackbox", "keys.txt")
	// #nosec G304 -- path is built by the test itself.
	oldKey, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "init", "--force")
	if err != nil {
		t.Fatalf("init --force: %v", err)
	}
	if !strings.Contains(stdout, "previous key backup:") {
		t.Errorf("output = %q", stdout)
	}
	backups, err := filepath.Glob(keysPath + ".bak-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, err = %v", backups, err)
	}
	info, err := os.Stat(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("backup mode = %04o, want 0600", got)
	}
	// #nosec G304 -- path is built by the test itself.
	newKey, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldKey, newKey) {
		t.Fatal("--force did not rotate the identity")
	}

	if _, _, err := runCLI(t, "unseal", "--keys", backups[0], "--out", "old.env"); err != nil {
		t.Fatalf("unseal with backup: %v", err)
	}
	restored, err := os.ReadFile("old.env")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Errorf("backup decrypted %q, want %q", restored, plaintext)
	}
}

func TestCLIInitWarnsOnOpenHomeDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())

	keyDir := filepath.Join(home, ".blackbox")
	// #nosec G301 -- the test deliberately creates an open key directory.
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- the test deliberately opens the directory.
	if err := os.Chmod(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(stdout, "group/world") {
		t.Errorf("output = %q, want a permission warning", stdout)
	}
	info, err := os.Stat(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Errorf("key dir mode changed to %04o", got)
	}
}
