// Package domain holds blackbox's data models.
package domain

// ConfigVersion is the .blackbox.yaml schema version.
const ConfigVersion = 1

// Config is the repository-level blackbox configuration. It contains only the
// public age recipient; the private identity stays in ~/.blackbox/keys.txt.
type Config struct {
	Version   int    `yaml:"version"`
	Recipient string `yaml:"recipient"`
	CreatedAt string `yaml:"created_at"`
}
