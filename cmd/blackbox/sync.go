package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/yogaagungk/blackbox/internal/service"
)

func (a *app) syncCmd() *cobra.Command {
	var target, repo, envPath, apiURL string
	var apply, dryRun bool

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync .env values to GitHub repository secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target != "github" {
				return fmt.Errorf("unsupported sync target %q (only github is implemented)", target)
			}
			if apply && dryRun {
				return errors.New("--apply and --dry-run are mutually exclusive")
			}

			owner, name, err := resolveRepo(repo)
			if err != nil {
				return err
			}

			// #nosec G304 -- CLI-provided env path.
			data, err := os.ReadFile(envPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("read %s: file does not exist; run 'blackbox unseal' first", envPath)
				}
				return fmt.Errorf("read %s: %w", envPath, err)
			}

			parsed := service.ParseEnvFile(data)
			if len(parsed.Secrets) == 0 {
				return fmt.Errorf("no valid secrets found in %s", envPath)
			}
			if len(parsed.Skipped) > 0 {
				_, _ = fmt.Fprintf(a.stderr, "skipped %d invalid entries: %s\n",
					len(parsed.Skipped), strings.Join(parsed.Skipped, ", "))
			}

			names := make([]string, 0, len(parsed.Secrets))
			for _, secret := range parsed.Secrets {
				names = append(names, secret.Key)
			}

			if dryRun || !apply {
				_, _ = fmt.Fprintf(a.stdout, "dry run: would set %d secrets in %s/%s: %s\n",
					len(names), owner, name, strings.Join(names, ", "))
				return nil
			}

			token, err := a.githubToken()
			if err != nil {
				return err
			}
			client := &service.GitHubClient{BaseURL: apiURL, Token: token}
			keyID, publicKey, err := client.RepoPublicKey(cmd.Context(), owner, name)
			if err != nil {
				return err
			}

			for _, secret := range parsed.Secrets {
				encrypted, err := service.SealSecret(publicKey, []byte(secret.Value), nil)
				if err != nil {
					return fmt.Errorf("seal %s: %w", secret.Key, err)
				}
				if err := client.PutRepoSecret(cmd.Context(), owner, name, secret.Key, encrypted, keyID); err != nil {
					return fmt.Errorf("upload %s: %w", secret.Key, err)
				}
				_, _ = fmt.Fprintf(a.stdout, "set %s\n", secret.Key)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "github", "sync target (only github)")
	cmd.Flags().StringVar(&repo, "repo", "", "repository as owner/name (default: origin remote)")
	cmd.Flags().StringVar(&envPath, "env", ".env", "plaintext env file to read")
	cmd.Flags().StringVar(&apiURL, "api", "https://api.github.com", "GitHub API base URL")
	cmd.Flags().BoolVar(&apply, "apply", false, "upload secrets (default only lists key names)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "list key names without uploading")
	return cmd
}

func resolveRepo(explicit string) (string, string, error) {
	if explicit != "" {
		return splitRepo(explicit)
	}
	return inferRepo()
}

// githubToken reads GITHUB_TOKEN, or prompts like gh. The token is never
// accepted as a flag and is never echoed.
func (a *app) githubToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		return token, nil
	}

	if !a.interactive {
		line, err := bufio.NewReader(a.stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("GITHUB_TOKEN is not set and no token was provided on stdin")
		}
		token := strings.TrimSpace(line)
		if token == "" {
			return "", errors.New("GITHUB_TOKEN is not set and the stdin token was empty")
		}
		return token, nil
	}

	file, ok := a.stdin.(*os.File)
	if !ok {
		return "", errors.New("cannot prompt for a token without a terminal; set GITHUB_TOKEN")
	}
	_, _ = fmt.Fprint(a.stderr, "GitHub token: ")
	data, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(a.stderr)
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("empty GitHub token")
	}
	return token, nil
}
