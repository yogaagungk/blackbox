package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/yogaagungk/blackbox/internal/service"
)

var appNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (a *app) syncCmd() *cobra.Command {
	var target, repo, envPath, apiURL, landerURL, landerToken, appName, mode string
	var apply, dryRun bool
	var fromFiles []string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync .env values to GitHub secrets or a lander daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if apply && dryRun {
				return errors.New("--apply and --dry-run are mutually exclusive")
			}
			switch target {
			case "github":
				return a.syncGitHub(cmd, repo, envPath, apiURL, fromFiles, apply, dryRun)
			case "lander":
				if len(fromFiles) > 0 {
					return errors.New("--from-file is only supported for --target github")
				}
				return a.syncLander(cmd, landerURL, landerToken, appName, mode, envPath, apply, dryRun)
			default:
				return fmt.Errorf("unsupported sync target %q (expected github or lander)", target)
			}
		},
	}

	cmd.Flags().StringVar(&target, "target", "github", "sync target: github or lander")
	cmd.Flags().StringVar(&repo, "repo", "", "repository as owner/name (default: origin remote)")
	cmd.Flags().StringVar(&envPath, "env", ".env", "plaintext env file to read")
	cmd.Flags().StringVar(&apiURL, "api", "https://api.github.com", "GitHub API base URL (https, or http on loopback)")
	cmd.Flags().StringArrayVar(&fromFiles, "from-file", nil, "extra secret as NAME=path (repeatable, github only)")
	cmd.Flags().BoolVar(&apply, "apply", false, "perform the upload (default only lists key names)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "list key names without uploading")

	cmd.Flags().StringVar(&landerURL, "url", "", "lander base URL for --target lander")
	cmd.Flags().StringVar(&landerToken, "token", "", "lander bearer token (prefer LANDER_TOKEN)")
	cmd.Flags().StringVar(&appName, "app", "", "app name for lander (default: origin repo name)")
	cmd.Flags().StringVar(&mode, "mode", "merge", "lander env mode: merge or replace")
	return cmd
}

func (a *app) syncGitHub(cmd *cobra.Command, repo, envPath, apiURL string, fromFiles []string, apply, dryRun bool) error {
	baseURL, err := validateAPIURL(apiURL)
	if err != nil {
		return fmt.Errorf("--api: %w", err)
	}
	owner, name, err := resolveRepo(repo)
	if err != nil {
		return err
	}

	// #nosec G304 -- CLI-provided env path.
	data, err := os.ReadFile(envPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read %s: %w", envPath, err)
		}
		if len(fromFiles) == 0 {
			return fmt.Errorf("read %s: file does not exist; run 'blackbox unseal' first", envPath)
		}
		data = nil
	}

	overrides, err := readFromFiles(fromFiles)
	if err != nil {
		return err
	}
	parsed := service.ParseEnvFile(data)
	plan := service.PrepareSecrets(parsed.Secrets, overrides)

	skipped := append(append([]string{}, parsed.Skipped...), plan.Skipped...)
	if len(skipped) > 0 {
		_, _ = fmt.Fprintf(a.stderr, "skipped %d entries: %s\n", len(skipped), strings.Join(skipped, ", "))
	}
	if plan.OverLimit {
		_, _ = fmt.Fprintf(a.stderr, "warning: %d secrets; GitHub allows at most %d per repository\n",
			len(plan.Secrets), service.MaxRepoSecrets)
	}
	if len(plan.Secrets) == 0 {
		return fmt.Errorf("no valid secrets found in %s", envPath)
	}

	names := secretNames(plan.Secrets)
	if dryRun || !apply {
		_, _ = fmt.Fprintf(a.stdout, "dry run: would set %d secrets in %s/%s: %s\n",
			len(names), owner, name, strings.Join(names, ", "))
		return nil
	}

	token, err := a.githubToken()
	if err != nil {
		return err
	}
	client := &service.GitHubClient{BaseURL: baseURL, Token: token}
	keyID, publicKey, err := client.RepoPublicKey(cmd.Context(), owner, name)
	if err != nil {
		return err
	}

	var uploaded []string
	for i, secret := range plan.Secrets {
		encrypted, err := service.SealSecret(publicKey, []byte(secret.Value), nil)
		if err != nil {
			return fmt.Errorf("seal %s: %w", secret.Key, err)
		}
		if err := client.PutRepoSecret(cmd.Context(), owner, name, secret.Key, encrypted, keyID); err != nil {
			notUploaded := names[i:]
			_, _ = fmt.Fprintf(a.stderr, "uploaded: %s\n", joinOrNone(uploaded))
			_, _ = fmt.Fprintf(a.stderr, "not uploaded: %s\n", strings.Join(notUploaded, ", "))
			return fmt.Errorf("upload %s failed after %d of %d secrets", secret.Key, len(uploaded), len(plan.Secrets))
		}
		uploaded = append(uploaded, secret.Key)
		_, _ = fmt.Fprintf(a.stdout, "set %s\n", secret.Key)
	}
	return nil
}

func (a *app) syncLander(cmd *cobra.Command, rawURL, tokenFlag, appName, mode, envPath string, apply, dryRun bool) error {
	if strings.TrimSpace(rawURL) == "" {
		return errors.New("--url is required for --target lander")
	}
	baseURL, err := validateAPIURL(rawURL)
	if err != nil {
		return fmt.Errorf("--url: %w", err)
	}
	switch mode {
	case "", "merge", "replace":
	default:
		return fmt.Errorf("--mode must be merge or replace")
	}
	if appName == "" {
		_, name, err := inferRepo()
		if err != nil {
			return errors.New("--app is required when the origin remote cannot be inferred")
		}
		appName = name
	}
	if !appNameRE.MatchString(appName) {
		return fmt.Errorf("--app %q must match ^[a-z0-9][a-z0-9-]{0,62}$", appName)
	}

	// #nosec G304 -- CLI-provided env path.
	data, err := os.ReadFile(envPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", envPath, err)
	}
	parsed := service.ParseEnvFile(data)
	secrets, skipped := landerSecrets(parsed.Secrets)
	skipped = append(parsed.Skipped, skipped...)
	if len(skipped) > 0 {
		_, _ = fmt.Fprintf(a.stderr, "skipped %d entries: %s\n", len(skipped), strings.Join(skipped, ", "))
	}
	if len(secrets) == 0 {
		return fmt.Errorf("no valid env vars found in %s", envPath)
	}
	if len(secrets) > 256 {
		return fmt.Errorf("%d env vars exceeds the lander limit of 256", len(secrets))
	}

	names := secretNames(secrets)
	if dryRun || !apply {
		_, _ = fmt.Fprintf(a.stdout, "dry run: would send %d env vars to %s at %s: %s\n",
			len(names), appName, baseURL, strings.Join(names, ", "))
		return nil
	}

	token := strings.TrimSpace(tokenFlag)
	if token == "" {
		token, err = a.promptToken("LANDER_TOKEN", "Lander token")
		if err != nil {
			return err
		}
	}
	vars := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		vars[secret.Key] = secret.Value
	}
	client := &service.LanderClient{BaseURL: baseURL, Token: token}
	result, err := client.PutEnv(cmd.Context(), appName, mode, vars)
	if err != nil {
		return err
	}
	acked := result.Keys
	if len(acked) == 0 {
		acked = names
	}
	_, _ = fmt.Fprintf(a.stdout, "sent %d env vars to %s: %s\n", len(names), appName, strings.Join(acked, ", "))
	return nil
}

func readFromFiles(specs []string) ([]service.Secret, error) {
	var secrets []service.Secret
	for _, spec := range specs {
		name, path, ok := strings.Cut(spec, "=")
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("--from-file must be NAME=path, got %q", spec)
		}
		if !service.IsValidSecretKey(name) {
			return nil, fmt.Errorf("--from-file name %q must match ^[A-Z_][A-Z0-9_]*$", name)
		}
		// #nosec G304 -- CLI-provided secret file path.
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		secrets = append(secrets, service.Secret{Key: name, Value: string(data)})
	}
	return secrets, nil
}

func landerSecrets(secrets []service.Secret) ([]service.Secret, []string) {
	var kept []service.Secret
	var skipped []string
	for _, secret := range secrets {
		switch {
		case strings.ContainsAny(secret.Value, "\r\n"):
			skipped = append(skipped, secret.Key+" (multi-line value not allowed by lander env)")
		case len(secret.Value) > 8192:
			skipped = append(skipped, secret.Key+" (value exceeds the lander 8 KiB limit)")
		default:
			kept = append(kept, secret)
		}
	}
	return kept, skipped
}

func secretNames(secrets []service.Secret) []string {
	names := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		names = append(names, secret.Key)
	}
	return names
}

func joinOrNone(names []string) string {
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

// validateAPIURL prevents a copied command from sending a token to a plain
// HTTP or unrelated endpoint. HTTPS is required; HTTP is allowed only on
// loopback for local tests.
func validateAPIURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("URL must be absolute with a scheme and host")
	}
	if parsed.User != nil {
		return "", errors.New("URL must not contain userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("URL must not contain a query or fragment")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("http is only allowed for loopback hosts; use https")
		}
	default:
		return "", errors.New("URL scheme must be https")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

func resolveRepo(explicit string) (string, string, error) {
	if explicit != "" {
		return splitRepo(explicit)
	}
	return inferRepo()
}

func (a *app) githubToken() (string, error) {
	return a.promptToken("GITHUB_TOKEN", "GitHub token")
}

// promptToken reads envName, or prompts like gh. The token is never accepted
// as a flag for GitHub and is never echoed.
func (a *app) promptToken(envName, label string) (string, error) {
	if token := strings.TrimSpace(os.Getenv(envName)); token != "" {
		return token, nil
	}

	if !a.interactive {
		line, err := bufio.NewReader(a.stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("%s is not set and no token was provided on stdin", envName)
		}
		token := strings.TrimSpace(line)
		if token == "" {
			return "", fmt.Errorf("%s is not set and the stdin token was empty", envName)
		}
		return token, nil
	}

	file, ok := a.stdin.(*os.File)
	if !ok {
		return "", fmt.Errorf("cannot prompt for a token without a terminal; set %s", envName)
	}
	_, _ = fmt.Fprint(a.stderr, label+": ")
	data, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(a.stderr)
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("empty token")
	}
	return token, nil
}
