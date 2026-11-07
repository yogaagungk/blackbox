package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LanderClient posts write-only env sets to a lander daemon.
type LanderClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// LanderEnvResult is lander's acknowledged app and key names.
type LanderEnvResult struct {
	App  string   `json:"app"`
	Keys []string `json:"keys"`
}

func (c *LanderClient) endpoint() string {
	return strings.TrimRight(c.BaseURL, "/") + "/api/v1/env"
}

func (c *LanderClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// PutEnv sends an env upsert for one app and returns the acknowledged keys.
func (c *LanderClient) PutEnv(ctx context.Context, app, mode string, vars map[string]string) (LanderEnvResult, error) {
	var result LanderEnvResult

	body := struct {
		App  string            `json:"app"`
		Mode string            `json:"mode,omitempty"`
		Vars map[string]string `json:"vars"`
	}{App: app, Mode: mode, Vars: vars}
	payload, err := json.Marshal(body)
	if err != nil {
		return result, fmt.Errorf("encode env request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(payload))
	if err != nil {
		return result, fmt.Errorf("build env request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return result, fmt.Errorf("lander request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorSnippet))
		return result, fmt.Errorf("lander api: %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, fmt.Errorf("decode lander response: %w", err)
	}
	return result, nil
}
