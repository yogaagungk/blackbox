// Command blackbox manages age-encrypted environment files.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/yogaagungk/blackbox/internal/config"
)

// version is injected at build time.
var version = "dev"

type app struct {
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	interactive bool
	configPath  string
	keysPath    string
}

func newApp(stdin io.Reader, stdout, stderr io.Writer) *app {
	return &app{
		stdin:       stdin,
		stdout:      stdout,
		stderr:      stderr,
		interactive: isTerminal(stdin),
	}
}

func (a *app) keysFile() (string, error) {
	if a.keysPath != "" {
		return a.keysPath, nil
	}
	paths, err := config.Load()
	if err != nil {
		return "", err
	}
	return paths.KeysPath, nil
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:           "blackbox",
		Short:         "Encrypt and manage .env files with age",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.configPath, "config", config.DefaultConfigFile, "path to .blackbox.yaml")
	root.PersistentFlags().StringVar(&a.keysPath, "keys", "", "age identity file (default ~/.blackbox/keys.txt)")
	root.SetIn(a.stdin)
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)

	root.AddCommand(a.initCmd(), a.sealCmd(), a.unsealCmd(), a.syncCmd(), a.versionCmd())
	return root
}

func isTerminal(r io.Reader) bool {
	file, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func main() {
	a := newApp(os.Stdin, os.Stdout, os.Stderr)
	if err := newRootCmd(a).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "blackbox:", err)
		os.Exit(1)
	}
}
