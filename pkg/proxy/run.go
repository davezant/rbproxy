package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"rbproxy/internal/config"
	"rbproxy/internal/events"
	"rbproxy/internal/honeypot"
	"rbproxy/internal/profile"
	"rbproxy/pkg/terminal"
)

// Site is one listener in front of one backend.
type Site struct {
	Listen   string
	Target   *url.URL
	CertFile string
	KeyFile  string
}

type AdminOptions struct {
	Listen string
	Token  string
}

// FromConfig builds a proxy and its sites from a validated configuration.
func FromConfig(cfg config.Config) (*Proxy, []Site, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	sink, err := events.Open(cfg.EventLog, 2000)
	if err != nil {
		return nil, nil, fmt.Errorf("event log: %w", err)
	}
	sink.OnEvent = consolePrinter(cfg.Verbose)

	var honey *honeypot.Engine
	if cfg.Honeypot.Enabled {
		honey = honeypot.New(cfg.HoneypotConfig())
	}
	trusted, _ := cfg.TrustedNets() // validated above

	opts := Options{
		Mode:              Mode(cfg.Mode),
		Verbose:           cfg.Verbose,
		TrustedProxies:    trusted,
		PreserveHost:      cfg.PreserveHost,
		ForwardClientInfo: cfg.ForwardClientInfo,
		MaxRequestBytes:   cfg.MaxRequestBytes,
		MaxScanBytes:      cfg.MaxScanBytes,
		BlockFindingScore: cfg.BlockFindingScore,
		DetectLeaks:       cfg.Leaks.Detect,
		RedactLeaks:       cfg.Leaks.Redact,
		ProbeMinScore:     cfg.Honeypot.ProbeMinScore,
	}
	sites := make([]Site, len(cfg.Sites))
	for i, s := range cfg.Sites {
		u, _ := url.Parse(s.Target) // validated above
		sites[i] = Site{Listen: s.Listen, Target: u, CertFile: s.Cert, KeyFile: s.Key}
	}
	return New(opts, profile.NewTracker(cfg.ProfileConfig()), honey, sink), sites, nil
}

// consolePrinter prints notable events as they happen. Info-level events
// (decoys served, etc.) only show up in verbose mode; all of them go to the log.
func consolePrinter(verbose bool) func(events.Event) {
	return func(e events.Event) {
		if !verbose && events.Rank(e.Severity) < events.Rank(events.Low) {
			return
		}
		uri := e.URI
		if len(uri) > 80 {
			uri = uri[:80] + "…"
		}
		fmt.Fprintf(os.Stderr, "%s %s %-20s %-22s %s %s %s\n",
			terminal.Dim(e.Time.Local().Format("15:04:05")), terminal.Severity(e.Severity), e.Type,
			terminal.Highlight(e.Client), e.Method, uri, terminal.Dim(e.Message))
	}
}

// Run serves every site (and the admin API) until ctx is cancelled.
func (p *Proxy) Run(ctx context.Context, sites []Site, admin AdminOptions) error {
	var servers []*http.Server
	errc := make(chan error, len(sites)+1)
	quiet := log.New(&filteredLog{}, "", 0)

	start := func(addr string, h http.Handler, certFile, keyFile string) error {
		var tlsCfg *tls.Config
		if certFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return fmt.Errorf("loading certificate %s: %w", certFile, err)
			}
			tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return listenError(addr, err)
		}
		srv := &http.Server{
			Handler:           h,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second, // slowloris
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    1 << 20,
			ErrorLog:          quiet,
		}
		servers = append(servers, srv)
		go func() {
			var err error
			if tlsCfg != nil {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
		return nil
	}
	stopAll := func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(sctx)
		}
	}

	terminal.Info("rbproxy %s — mode %s, %d detection rules, honeypots %s",
		terminal.Version, p.opts.Mode, p.detector.Rules(), onOff(p.honey != nil))
	for _, s := range sites {
		if err := start(s.Listen, p.Handler(s.Target), s.CertFile, s.KeyFile); err != nil {
			stopAll()
			return err
		}
		scheme := "http"
		if s.CertFile != "" {
			scheme = "https"
		}
		terminal.Info("listening on %s://%s → %s", scheme, s.Listen, s.Target)
		go waitForTarget(ctx, s.Target)
	}
	if admin.Listen != "" {
		if err := start(admin.Listen, p.AdminHandler(admin.Token), "", ""); err != nil {
			stopAll()
			return err
		}
		terminal.Info("admin API on http://%s/api/", admin.Listen)
	}

	go p.sweep(ctx)

	var err error
	select {
	case <-ctx.Done():
		terminal.Info("shutting down")
	case err = <-errc:
	}
	stopAll()
	return err
}

func (p *Proxy) sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tracker.Sweep()
			if p.honey != nil {
				p.honey.Sweep()
			}
		}
	}
}

func listenError(addr string, err error) error {
	switch {
	case errors.Is(err, syscall.EACCES):
		return fmt.Errorf("cannot listen on %s: ports below 1024 need root or CAP_NET_BIND_SERVICE (sudo setcap 'cap_net_bind_service=+ep' ./rbproxy)", addr)
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf("cannot listen on %s: address already in use", addr)
	}
	return fmt.Errorf("cannot listen on %s: %w", addr, err)
}

// waitForTarget checks the backend is reachable and warns if it is not. The
// proxy keeps running either way: backends restart.
func waitForTarget(ctx context.Context, target *url.URL) {
	addr := target.Host
	if target.Port() == "" {
		if target.Scheme == "https" {
			addr = net.JoinHostPort(target.Hostname(), "443")
		} else {
			addr = net.JoinHostPort(target.Hostname(), "80")
		}
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	for attempt := 1; attempt <= 10; attempt++ {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			c.Close()
			if attempt > 1 {
				terminal.Info("backend %s is up", target)
			}
			return
		}
		if attempt == 1 {
			terminal.Warn("backend %s not reachable yet (%v), retrying…", target, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	terminal.Warn("backend %s still unreachable; requests will get 502 until it is up", target)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// filteredLog drops the TLS handshake noise every internet-facing server gets.
type filteredLog struct{}

func (filteredLog) Write(b []byte) (int, error) {
	s := string(b)
	if strings.Contains(s, "TLS handshake error") || strings.Contains(s, "URL query contains semicolon") {
		return len(b), nil
	}
	terminal.Warn("%s", strings.TrimSpace(s))
	return len(b), nil
}
