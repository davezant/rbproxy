/*
Copyright © 2026 RBProxy
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"rbproxy/pkg/terminal"
)

var rootCmd = &cobra.Command{
	Use:   "rbproxy",
	Short: "Reverse proxy that detects attacks, profiles clients and grows its own honeypots",
	Long: `RBProxy sits in front of a web application and watches every request.

  • Detects attack payloads (SQLi, XSS, command injection, traversal, SSTI,
    Log4Shell, XXE, SSRF...) and leaks in the backend's responses.
  • Profiles every client: request rate, 404 enumeration, brute force,
    scanner user agents. Scores decay over time; high scores get throttled,
    blocked, and eventually blacklisted.
  • Answers probes with honeypots: fake .env, .git, phpMyAdmin, WordPress,
    database dumps... filled with canary credentials unique to each client.
    When a canary comes back, the thief is identified across IPs. Paths that
    several suspicious clients probe become new traps on their own.

Start with:  rbproxy host --target http://127.0.0.1:3000`,
	Version:       terminal.Version,
	SilenceUsage:  true,
	SilenceErrors: false,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
