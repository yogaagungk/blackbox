package main

import (
	"bytes"
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

func TestValidateAPIURL(t *testing.T) {
	valid := []string{
		"https://api.github.com",
		"https://ghe.example.com/api/v3",
		"http://127.0.0.1:8080",
		"http://localhost:9000",
		"http://[::1]:8080",
	}
	for _, raw := range valid {
		if _, err := validateAPIURL(raw); err != nil {
			t.Errorf("%q rejected: %v", raw, err)
		}
	}

	invalid := []string{
		"http://example.com",
		"http://127.0.0.1.evil.com",
		"https://user:pass@github.com",
		"https://github.com?token=1",
		"https://github.com#frag",
		"ftp://github.com",
		"not a url",
	}
	for _, raw := range invalid {
		if _, err := validateAPIURL(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestCLISyncFromFile(t *testing.T) {
	t.Chdir(t.TempDir())
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": "kid",
				"key":    base64.StdEncoding.EncodeToString(publicKey[:]),
			})
		case r.Method == http.MethodPut:
			var body struct {
				EncryptedValue string `json:"encrypted_value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode: %v", err)
			}
			ciphertext, err := base64.StdEncoding.DecodeString(body.EncryptedValue)
			if err != nil {
				t.Errorf("ciphertext: %v", err)
			}
			opened, ok := box.OpenAnonymous(nil, ciphertext, publicKey, privateKey)
			if !ok {
				t.Error("decrypt failed")
			}
			captured = opened
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	pem := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----\n")
	if err := os.WriteFile("deploy.pem", pem, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_TOKEN", "token")

	stdout, _, err := runCLI(t, "sync", "--repo", "owner/repo", "--api", server.URL,
		"--from-file", "DEPLOY_SSH_KEY=deploy.pem", "--apply")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !bytes.Equal(captured, pem) {
		t.Errorf("uploaded bytes = %q, want the PEM file", captured)
	}
	if strings.Contains(stdout, "BEGIN OPENSSH") {
		t.Errorf("stdout leaked the PEM: %q", stdout)
	}
}

func TestCLISyncSkipsReservedAndOversized(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("GITHUB_TOKEN", "token")
	content := "GITHUB_TOKEN=reserved\nOK=1\nHUGE=" + strings.Repeat("x", 48*1024+1) + "\n"
	if err := os.WriteFile(".env", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runCLI(t, "sync", "--repo", "owner/repo")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !strings.Contains(stdout, "would set 1 secrets") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "GITHUB_TOKEN (reserved") || !strings.Contains(stderr, "HUGE") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCLISyncPartialFailureReportsKeys(t *testing.T) {
	t.Chdir(t.TempDir())
	publicKey, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": "kid",
				"key":    base64.StdEncoding.EncodeToString(publicKey[:]),
			})
		case strings.HasSuffix(r.URL.Path, "/A"):
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	if err := os.WriteFile(".env", []byte("A=1\nB=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_TOKEN", "token")

	_, stderr, err := runCLI(t, "sync", "--repo", "owner/repo", "--api", server.URL, "--apply")
	if err == nil {
		t.Fatal("expected the upload to fail")
	}
	if !strings.Contains(stderr, "uploaded: A") || !strings.Contains(stderr, "not uploaded: B") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCLISyncLanderApply(t *testing.T) {
	t.Chdir(t.TempDir())
	var gotAuth string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/env" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"app": "my-api", "keys": []string{"A", "B"}})
	}))
	defer server.Close()

	content := "A=1\nB=2\nMULTI=\"line1\nline2\"\n"
	if err := os.WriteFile(".env", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANDER_TOKEN", "lander-token")

	stdout, stderr, err := runCLI(t, "sync", "--target", "lander", "--url", server.URL, "--app", "my-api", "--apply")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if gotAuth != "Bearer lander-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	vars, _ := gotBody["vars"].(map[string]any)
	if vars["A"] != "1" || vars["B"] != "2" || len(vars) != 2 {
		t.Errorf("vars = %v", vars)
	}
	if gotBody["app"] != "my-api" || gotBody["mode"] != "merge" {
		t.Errorf("body = %v", gotBody)
	}
	if !strings.Contains(stdout, "sent 2 env vars") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "MULTI (multi-line") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCLISyncLanderDryRunNeedsNoToken(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("LANDER_TOKEN", "")
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runCLI(t, "sync", "--target", "lander", "--url", "https://lander.example.com", "--app", "my-api")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(stdout, "would send 1 env vars to my-api") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestCLISyncLanderRequiresToken(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("LANDER_TOKEN", "")
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "sync", "--target", "lander", "--url", "https://lander.example.com", "--app", "my-api", "--apply")
	if err == nil || !strings.Contains(err.Error(), "LANDER_TOKEN") {
		t.Fatalf("error = %v, want a token error", err)
	}
}
