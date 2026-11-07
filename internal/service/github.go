package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultGitHubAPI = "https://api.github.com"
	maxErrorSnippet  = 512
)

// GitHubClient is the minimal REST surface blackbox needs to upload
// repository secrets. BaseURL is overridable for tests and GitHub Enterprise.
type GitHubClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

type repoPublicKeyResponse struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

func (c *GitHubClient) baseURL() string {
	if strings.TrimSpace(c.BaseURL) == "" {
		return defaultGitHubAPI
	}
	return strings.TrimRight(c.BaseURL, "/")
}

func (c *GitHubClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *GitHubClient) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("github request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorSnippet))
		return fmt.Errorf("github api %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(snippet)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode github response: %w", err)
		}
	}
	return nil
}

// RepoPublicKey returns the key id and base64 public key used to seal secrets
// for a repository.
func (c *GitHubClient) RepoPublicKey(ctx context.Context, owner, repo string) (keyID, publicKey string, err error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/secrets/public-key", url.PathEscape(owner), url.PathEscape(repo))
	var response repoPublicKeyResponse
	if err := c.do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return "", "", err
	}
	if response.KeyID == "" || response.Key == "" {
		return "", "", fmt.Errorf("github returned an empty repository public key")
	}
	return response.KeyID, response.Key, nil
}

// PutRepoSecret creates or updates one repository secret with a sealed value.
func (c *GitHubClient) PutRepoSecret(ctx context.Context, owner, repo, name, encryptedValue, keyID string) error {
	path := fmt.Sprintf("/repos/%s/%s/actions/secrets/%s",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(name))
	body := struct {
		EncryptedValue string `json:"encrypted_value"`
		KeyID          string `json:"key_id"`
	}{
		EncryptedValue: encryptedValue,
		KeyID:          keyID,
	}
	return c.do(ctx, http.MethodPut, path, body, nil)
}
