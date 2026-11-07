package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLanderClientPutEnv(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/env" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"app": "my-api", "keys": []string{"A", "B"}})
	}))
	defer server.Close()

	client := &LanderClient{BaseURL: server.URL + "/", Token: "token", HTTPClient: server.Client()}
	result, err := client.PutEnv(t.Context(), "my-api", "merge", map[string]string{"A": "1", "B": "2"})
	if err != nil {
		t.Fatalf("PutEnv: %v", err)
	}
	if gotAuth != "Bearer token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody["app"] != "my-api" || gotBody["mode"] != "merge" {
		t.Errorf("body = %v", gotBody)
	}
	vars, _ := gotBody["vars"].(map[string]any)
	if vars["A"] != "1" || vars["B"] != "2" {
		t.Errorf("vars = %v", vars)
	}
	if len(result.Keys) != 2 || result.App != "my-api" {
		t.Errorf("result = %+v", result)
	}
}

func TestLanderClientErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &LanderClient{BaseURL: server.URL, Token: "bad", HTTPClient: server.Client()}
	_, err := client.PutEnv(t.Context(), "my-api", "merge", map[string]string{"A": "1"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("error = %v, want a 401 error", err)
	}
}
