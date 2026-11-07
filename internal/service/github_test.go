package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestGitHubClientUploadsSealedSecrets(t *testing.T) {
	publicKey, privateKey, err := box.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	keyID := "key-123"

	var mu sync.Mutex
	received := map[string]string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
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

	client := &GitHubClient{BaseURL: server.URL, Token: "test-token", HTTPClient: server.Client()}
	gotKeyID, publicKeyB64, err := client.RepoPublicKey(t.Context(), "owner", "repo")
	if err != nil {
		t.Fatalf("RepoPublicKey: %v", err)
	}
	if gotKeyID != keyID || publicKeyB64 == "" {
		t.Fatalf("keyID = %q, key = %q", gotKeyID, publicKeyB64)
	}

	encrypted, err := SealSecret(publicKeyB64, []byte("super-secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.PutRepoSecret(t.Context(), "owner", "repo", "API_KEY", encrypted, gotKeyID); err != nil {
		t.Fatalf("PutRepoSecret: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if received["API_KEY"] != "super-secret" {
		t.Errorf("received = %v", received)
	}
}

func TestGitHubClientReportsHTTPErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &GitHubClient{BaseURL: server.URL, Token: "bad", HTTPClient: server.Client()}
	_, _, err := client.RepoPublicKey(t.Context(), "owner", "repo")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("error = %v, want a 401 error", err)
	}
}
