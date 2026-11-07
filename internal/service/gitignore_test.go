package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureGitignore(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitignore")
	if err := os.WriteFile(path, []byte("node_modules\n.env.local"), 0o600); err != nil {
		t.Fatal(err)
	}

	added, err := EnsureGitignore(path, []string{".env", ".env.local"})
	if err != nil {
		t.Fatalf("EnsureGitignore: %v", err)
	}
	if len(added) != 1 || added[0] != ".env" {
		t.Errorf("added = %v, want [.env]", added)
	}
	// #nosec G304 -- path is built by the test itself.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "node_modules\n.env.local\n.env\n"
	if string(data) != want {
		t.Errorf("gitignore = %q, want %q", data, want)
	}

	added, err = EnsureGitignore(path, []string{".env"})
	if err != nil || len(added) != 0 {
		t.Errorf("second call = %v, %v", added, err)
	}
}

func TestEnsureGitignoreCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitignore")
	added, err := EnsureGitignore(path, []string{".env"})
	if err != nil || !strings.Contains(strings.Join(added, ","), ".env") {
		t.Fatalf("added = %v, err = %v", added, err)
	}
	// #nosec G304 -- path is built by the test itself.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != ".env\n" {
		t.Errorf("content = %q", data)
	}
}
