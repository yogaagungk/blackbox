package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yogaagungk/blackbox/internal/config"
	"github.com/yogaagungk/blackbox/internal/service"
)

func (a *app) sealCmd() *cobra.Command {
	var inPath, outPath string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Encrypt .env to .env.lock with the configured recipient",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := config.LoadConfig(a.configPath)
			if err != nil {
				return err
			}
			size, err := service.SealFile(inPath, outPath, cfg.Recipient, dryRun)
			if err != nil {
				return err
			}
			verb := "sealed"
			if dryRun {
				verb = "would seal"
			}
			_, _ = fmt.Fprintf(a.stdout, "%s %s -> %s (%d bytes)\n", verb, inPath, outPath, size)
			return nil
		},
	}

	cmd.Flags().StringVar(&inPath, "in", ".env", "plaintext env file")
	cmd.Flags().StringVar(&outPath, "out", ".env.lock", "encrypted output file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate inputs without writing")
	return cmd
}
