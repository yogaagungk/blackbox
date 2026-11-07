package main

import (
	"bufio"
	"errors"
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
			configExists, err := fileExists(a.configPath)
			if err != nil {
				return err
			}
			if configExists && !force {
				return fmt.Errorf("%s already exists; use --force to overwrite", a.configPath)
			}

			keysExist, err := fileExists(keysPath)
			if err != nil {
				return err
			}

			var recipient, notice, backup string
			reused := false
			switch {
			case keysExist && !force:
				// A second repo must reuse the machine identity, never rotate it.
				recipient, err = service.LoadRecipient(keysPath)
				reused = true
			case keysExist && force:
				backup, err = service.BackupKey(keysPath)
				if err == nil {
					recipient, notice, err = service.InitKeys(keysPath, true)
				}
			default:
				recipient, notice, err = service.InitKeys(keysPath, false)
			}
			if err != nil {
				return err
			}
			if notice != "" {
				_, _ = fmt.Fprintf(a.stdout, "  warning: %s\n", notice)
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
			if err := service.WriteAtomic(a.configPath, data, 0o600); err != nil {
				// Keep a failed init from destroying the previous identity.
				if backup != "" {
					_ = service.RestoreKey(backup, keysPath)
				} else if !keysExist {
					_ = os.Remove(keysPath)
				}
				return fmt.Errorf("write config: %w", err)
			}

			header := "Initialized blackbox"
			if reused {
				header = "Initialized blackbox (reusing existing identity)"
			}
			_, _ = fmt.Fprintf(a.stdout, "%s\n  keys: %s (0600)\n  recipient: %s\n  config: %s\n",
				header, keysPath, recipient, a.configPath)
			if backup != "" {
				_, _ = fmt.Fprintf(a.stdout, "  previous key backup: %s (0600)\n", backup)
			}

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

	cmd.Flags().BoolVar(&force, "force", false, "rotate the identity (with backup) and overwrite the config")
	cmd.Flags().BoolVar(&noGitignore, "no-gitignore", false, "do not modify .gitignore")
	return cmd
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("inspect %s: %w", path, err)
	}
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
