package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestCLISyncGitHubApply(t *testing.T) {
	t.Chdir(t.TempDir())
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "key-456"

	var mu sync.Mutex
	received := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/actions/secrets/public-key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": keyID,
				"key":    base64.StdEncoding.EncodeToString(publicKey[:]),
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/repos/owner/repo/actions/secrets/"):
			name := strings.TrimPrefix(r.URL.Path, "/repos/owner/repo/actions/secrets/")
			var body struct {
				EncryptedValue string `json:"encrypted_value"`
				KeyID          string `json:"key_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if body.KeyID != keyID {
				t.Errorf("key_id = %q", body.KeyID)
			}
			ciphertext, err := base64.StdEncoding.DecodeString(body.EncryptedValue)
			if err != nil {
				t.Errorf("ciphertext: %v", err)
			}
			opened, ok := box.OpenAnonymous(nil, ciphertext, publicKey, privateKey)
			if !ok {
				t.Error("sealed value did not decrypt")
			}
			mu.Lock()
			received[name] = string(opened)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("GITHUB_TOKEN", "test-token")
	if err := os.WriteFile(".env", []byte("export API_KEY=abc\nSECRET_VALUE=xyz\nlower=no\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runCLI(t, "sync", "--repo", "owner/repo", "--api", server.URL, "--apply")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !strings.Contains(stdout, "set API_KEY") || !strings.Contains(stdout, "set SECRET_VALUE") {
		t.Errorf("stdout = %q", stdout)
	}
	if strings.Contains(stdout, "abc") || strings.Contains(stdout, "xyz") {
		t.Errorf("stdout leaked a value: %q", stdout)
	}
	if !strings.Contains(stderr, "lower") {
		t.Errorf("stderr = %q, want the skipped key name", stderr)
	}

	mu.Lock()
	defer mu.Unlock()
	if received["API_KEY"] != "abc" || received["SECRET_VALUE"] != "xyz" {
		t.Errorf("received = %v", received)
	}
}

func TestCLISyncDefaultsToDryRun(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("GITHUB_TOKEN", "test-token")
	if err := os.WriteFile(".env", []byte("A=1\nB=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "sync", "--repo", "owner/repo")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !strings.Contains(stdout, "dry run: would set 2 secrets") || !strings.Contains(stdout, "A, B") {
		t.Errorf("stdout = %q", stdout)
	}
	if strings.Contains(stdout, "=1") || strings.Contains(stdout, "=2") {
		t.Errorf("stdout leaked a value: %q", stdout)
	}
}

func TestCLISyncRequiresToken(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "sync", "--repo", "owner/repo", "--apply")
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("error = %v, want a token error", err)
	}
}

func TestCLISyncRejectsConflictingFlags(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "sync", "--repo", "owner/repo", "--apply", "--dry-run"); err == nil {
		t.Fatal("expected --apply/--dry-run conflict")
	}
	if _, _, err := runCLI(t, "sync", "--target", "lander"); err == nil {
		t.Fatal("expected unsupported target error")
	}
}

func TestGitHubTokenFromStdin(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	application := newApp(strings.NewReader("stdin-token\n"), io.Discard, io.Discard)
	token, err := application.githubToken()
	if err != nil {
		t.Fatalf("githubToken: %v", err)
	}
	if token != "stdin-token" {
		t.Errorf("token = %q", token)
	}
}

func TestCLISyncDryRunDoesNotNeedToken(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "sync", "--repo", "owner/repo"); err != nil {
		t.Fatalf("dry-run without token: %v", err)
	}
}
