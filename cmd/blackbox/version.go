package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the blackbox version",
		Run: func(_ *cobra.Command, _ []string) {
			_, _ = fmt.Fprintf(a.stdout, "blackbox %s\n", version)
		},
	}
}
