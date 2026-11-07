package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yogaagungk/blackbox/internal/service"
)

func (a *app) unsealCmd() *cobra.Command {
	var inPath, outPath string
	var dryRun, force bool

	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Decrypt .env.lock to .env using the local identity",
		RunE: func(_ *cobra.Command, _ []string) error {
			keysPath, err := a.keysFile()
			if err != nil {
				return err
			}
			size, err := service.UnsealFile(inPath, outPath, keysPath, dryRun, force)
			if err != nil {
				return err
			}
			verb := "unsealed"
			if dryRun {
				verb = "would unseal"
			}
			_, _ = fmt.Fprintf(a.stdout, "%s %s -> %s (%d bytes)\n", verb, inPath, outPath, size)
			return nil
		},
	}

	cmd.Flags().StringVar(&inPath, "in", ".env.lock", "encrypted input file")
	cmd.Flags().StringVar(&outPath, "out", ".env", "plaintext output file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decrypt in memory without writing")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing output file")
	return cmd
}
