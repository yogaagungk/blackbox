package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	paths, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join(home, ".blackbox", "keys.txt")
	if paths.KeysPath != want {
		t.Errorf("KeysPath = %q, want %q", paths.KeysPath, want)
	}
	if paths.ConfigPath != DefaultConfigFile {
		t.Errorf("ConfigPath = %q", paths.ConfigPath)
	}
}

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".blackbox.yaml")
	content := "version: 1\nrecipient: age1example\ncreated_at: 2026-11-07T00:00:00Z\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Version != 1 || cfg.Recipient != "age1example" {
		t.Errorf("config = %+v", cfg)
	}
}

func TestLoadConfigRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"bad yaml":          "version: [\n",
		"wrong version":     "version: 2\nrecipient: age1example\n",
		"missing recipient": "version: 1\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Errorf("expected an error for %s", name)
			}
		})
	}

	if _, err := LoadConfig(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
}
