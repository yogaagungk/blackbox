// Package config resolves blackbox's file paths and reads .blackbox.yaml.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/yogaagungk/blackbox/internal/domain"
)

// DefaultConfigFile is looked up in the working directory.
const DefaultConfigFile = ".blackbox.yaml"

// Paths holds the resolved file locations.
type Paths struct {
	KeysPath   string
	ConfigPath string
}

// Load resolves the identity path under the user's home directory.
func Load() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve home directory: %w", err)
	}
	if home == "" {
		return Paths{}, fmt.Errorf("resolve home directory: empty path")
	}
	return Paths{
		KeysPath:   filepath.Join(home, ".blackbox", "keys.txt"),
		ConfigPath: DefaultConfigFile,
	}, nil
}

// LoadConfig reads and validates a .blackbox.yaml file.
func LoadConfig(path string) (domain.Config, error) {
	var cfg domain.Config
	// #nosec G304 -- the path comes from a CLI flag or the default name.
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Version != domain.ConfigVersion {
		return cfg, fmt.Errorf("%s: unsupported version %d", path, cfg.Version)
	}
	if cfg.Recipient == "" {
		return cfg, fmt.Errorf("%s: recipient is required; run 'blackbox init'", path)
	}
	return cfg, nil
}
