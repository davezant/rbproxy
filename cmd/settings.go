/*
Copyright © 2026 RBProxy
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"rbproxy/internal/config"
)

var settingsOpts struct {
	write string
	force bool
	check string
}

var settingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Print, write or check a configuration file",
	Example: `  rbproxy settings                      # print every option with its default
  rbproxy settings --write rbproxy.json # start a config file
  rbproxy settings --check rbproxy.json # validate a config file`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if settingsOpts.check != "" {
			cfg, err := config.Load(settingsOpts.check)
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}
			fmt.Printf("%s is valid: %d site(s), mode %s\n", settingsOpts.check, len(cfg.Sites), cfg.Mode)
			return nil
		}

		b, err := json.MarshalIndent(config.Example(), "", "  ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if settingsOpts.write == "" {
			_, err = os.Stdout.Write(b)
			return err
		}
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if settingsOpts.force {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		f, err := os.OpenFile(settingsOpts.write, flags, 0o640)
		if err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("%s already exists (use --force to overwrite)", settingsOpts.write)
			}
			return err
		}
		defer f.Close()
		if _, err := f.Write(b); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", settingsOpts.write)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(settingsCmd)
	settingsCmd.Flags().StringVarP(&settingsOpts.write, "write", "w", "", "write the default config to this file")
	settingsCmd.Flags().BoolVar(&settingsOpts.force, "force", false, "overwrite an existing file")
	settingsCmd.Flags().StringVar(&settingsOpts.check, "check", "", "validate this config file")
}
