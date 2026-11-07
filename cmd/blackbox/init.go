package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/yogaagungk/blackbox/internal/domain"
	"github.com/yogaagungk/blackbox/internal/service"
)

func (a *app) initCmd() *cobra.Command {
	var force, noGitignore bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate an age keypair and .blackbox.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			keysPath, err := a.keysFile()
			if err != nil {
				return err
			}
			if !force {
				if _, err := os.Stat(a.configPath); err == nil {
					return fmt.Errorf("%s already exists; use --force to overwrite", a.configPath)
				} else if !os.IsNotExist(err) {
					return fmt.Errorf("inspect config: %w", err)
				}
			}

			recipient, err := service.InitKeys(keysPath, force)
			if err != nil {
				return err
			}

			cfg := domain.Config{
				Version:   domain.ConfigVersion,
				Recipient: recipient,
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
			}
			data, err := yaml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("encode config: %w", err)
			}
			if dir := filepath.Dir(a.configPath); dir != "." {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					return fmt.Errorf("create config directory: %w", err)
				}
			}
			if err := os.WriteFile(a.configPath, data, 0o600); err != nil {
				return fmt.Errorf("write config: %w", err)
			}

			_, _ = fmt.Fprintf(a.stdout, "Initialized blackbox\n  keys: %s (0600)\n  recipient: %s\n  config: %s\n",
				keysPath, recipient, a.configPath)

			if noGitignore || !a.confirmGitignore(cmd) {
				return nil
			}
			added, err := service.EnsureGitignore(".gitignore", []string{".env"})
			if err != nil {
				return err
			}
			if len(added) > 0 {
				_, _ = fmt.Fprintf(a.stdout, "  .gitignore: added %s\n", strings.Join(added, ", "))
			} else {
				_, _ = fmt.Fprintln(a.stdout, "  .gitignore: .env already ignored")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing identity and config")
	cmd.Flags().BoolVar(&noGitignore, "no-gitignore", false, "do not modify .gitignore")
	return cmd
}

// confirmGitignore prompts only on a terminal; non-interactive runs default
// to the safe choice (add the entry).
func (a *app) confirmGitignore(cmd *cobra.Command) bool {
	if !a.interactive {
		return true
	}
	_, _ = fmt.Fprint(a.stdout, "Add .env to .gitignore? [Y/n] ")
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "n", "no":
		return false
	default:
		return true
	}
}
