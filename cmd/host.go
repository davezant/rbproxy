/*
Copyright © 2026 RBProxy
*/
package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"rbproxy/internal/config"
	"rbproxy/pkg/proxy"
)

var hostOpts struct {
	config     string
	listen     string
	target     string
	cert       string
	key        string
	mode       string
	admin      string
	adminToken string
	eventLog   string
	verbose    bool
	noHoneypot bool
}

var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "Start the proxy in front of a backend",
	Long: `Start the proxy in front of a backend.

Modes:
  monitor  score and log everything, block nothing (start here)
  protect  block attacks (403) and abusive clients (403/429)
  deceive  like protect, but attackers get convincing fake answers and
           honeypots instead of error pages (default)

Flags override the config file.`,
	Example: `  rbproxy host --target http://127.0.0.1:3000
  rbproxy host --target http://127.0.0.1:3000 --listen :443 --cert cert.pem --key key.pem
  rbproxy host --target http://127.0.0.1:3000 --mode monitor --admin 127.0.0.1:9090
  rbproxy host --config rbproxy.json`,
	Args: cobra.NoArgs,
	RunE: runHost,
}

func runHost(cmd *cobra.Command, _ []string) error {
	cfg := config.Default()
	if hostOpts.config != "" {
		var err error
		if cfg, err = config.Load(hostOpts.config); err != nil {
			return err
		}
	}

	f := cmd.Flags()
	if f.Changed("target") {
		cfg.Sites = []config.Site{{Listen: hostOpts.listen, Target: hostOpts.target, Cert: hostOpts.cert, Key: hostOpts.key}}
	} else if len(cfg.Sites) == 1 {
		if f.Changed("listen") {
			cfg.Sites[0].Listen = hostOpts.listen
		}
		if f.Changed("cert") {
			cfg.Sites[0].Cert = hostOpts.cert
		}
		if f.Changed("key") {
			cfg.Sites[0].Key = hostOpts.key
		}
	}
	if f.Changed("mode") {
		cfg.Mode = hostOpts.mode
	}
	if f.Changed("admin") {
		cfg.Admin.Listen = hostOpts.admin
	}
	if f.Changed("admin-token") {
		cfg.Admin.Token = hostOpts.adminToken
	}
	if f.Changed("log") {
		cfg.EventLog = hostOpts.eventLog
	}
	if f.Changed("verbose") {
		cfg.Verbose = hostOpts.verbose
	}
	if hostOpts.noHoneypot {
		cfg.Honeypot.Enabled = false
	}

	px, sites, err := proxy.FromConfig(cfg)
	if err != nil {
		return err
	}
	defer px.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return px.Run(ctx, sites, proxy.AdminOptions{Listen: cfg.Admin.Listen, Token: cfg.Admin.Token})
}

func init() {
	rootCmd.AddCommand(hostCmd)
	f := hostCmd.Flags()
	f.StringVarP(&hostOpts.config, "config", "c", "", "JSON config file (see `rbproxy settings`)")
	f.StringVarP(&hostOpts.target, "target", "t", "", "backend URL, e.g. http://127.0.0.1:3000")
	f.StringVarP(&hostOpts.listen, "listen", "l", ":8080", "address to listen on")
	f.StringVar(&hostOpts.cert, "cert", "", "TLS certificate (PEM) to serve HTTPS")
	f.StringVar(&hostOpts.key, "key", "", "TLS private key (PEM)")
	f.StringVarP(&hostOpts.mode, "mode", "m", "deceive", "monitor | protect | deceive")
	f.StringVar(&hostOpts.admin, "admin", "", "address for the admin JSON API, e.g. 127.0.0.1:9090")
	f.StringVar(&hostOpts.adminToken, "admin-token", "", "bearer token required by the admin API")
	f.StringVar(&hostOpts.eventLog, "log", "rbproxy-events.jsonl", "event log file (JSON lines); empty to disable")
	f.BoolVarP(&hostOpts.verbose, "verbose", "v", false, "print every request and info-level event")
	f.BoolVar(&hostOpts.noHoneypot, "no-honeypot", false, "disable honeypots and decoys")
}
