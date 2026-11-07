// Package config loads the rbproxy JSON configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"rbproxy/internal/honeypot"
	"rbproxy/internal/profile"
)

// Duration reads "90s", "15m", "24h" from JSON.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string like \"15m\": %s", b)
	}
	*d = Duration(time.Duration(n * float64(time.Second)))
	return nil
}

// Site is one listener in front of one backend.
type Site struct {
	Listen string `json:"listen"`
	Target string `json:"target"`
	Cert   string `json:"cert,omitempty"`
	Key    string `json:"key,omitempty"`
}

type Admin struct {
	Listen string `json:"listen"`
	Token  string `json:"token,omitempty"`
}

type Leaks struct {
	Detect bool `json:"detect"`
	Redact bool `json:"redact"`
}

type Profile struct {
	Window         Duration `json:"window"`
	MaxRequests    int      `json:"max_requests"`
	WatchScore     float64  `json:"watch_score"`
	BlockScore     float64  `json:"block_score"`
	BlockDuration  Duration `json:"block_duration"`
	BlacklistAfter int      `json:"blacklist_after"`
	HalfLife       Duration `json:"score_half_life"`
	LoginAttempts  int      `json:"login_attempts"`
}

type Honeypot struct {
	Enabled        bool     `json:"enabled"`
	Tarpit         bool     `json:"tarpit"`
	TarpitMin      Duration `json:"tarpit_min"`
	TarpitMax      Duration `json:"tarpit_max"`
	LearnThreshold int      `json:"learn_threshold"`
	ProbeMinScore  float64  `json:"probe_min_score"`
	LogPasswords   bool     `json:"log_passwords"`
	CanaryTTL      Duration `json:"canary_ttl"`
}

type Config struct {
	Sites             []Site   `json:"sites"`
	Mode              string   `json:"mode"`
	Verbose           bool     `json:"verbose"`
	EventLog          string   `json:"event_log"`
	Admin             Admin    `json:"admin"`
	TrustedProxies    []string `json:"trusted_proxies"`
	PreserveHost      bool     `json:"preserve_host"`
	ForwardClientInfo bool     `json:"forward_client_info"`
	MaxRequestBytes   int64    `json:"max_request_bytes"`
	MaxScanBytes      int      `json:"max_scan_bytes"`
	BlockFindingScore int      `json:"block_finding_score"`
	Leaks             Leaks    `json:"leaks"`
	Profile           Profile  `json:"profile"`
	Honeypot          Honeypot `json:"honeypot"`
}

func Default() Config {
	p := profile.DefaultConfig()
	h := honeypot.DefaultConfig()
	return Config{
		Mode:              "deceive",
		TrustedProxies:    []string{},
		EventLog:          "rbproxy-events.jsonl",
		MaxRequestBytes:   10 << 20,
		MaxScanBytes:      64 << 10,
		BlockFindingScore: 8,
		Leaks:             Leaks{Detect: true, Redact: false},
		Profile: Profile{
			Window: Duration(p.Window), MaxRequests: p.MaxRequests, WatchScore: p.WatchScore,
			BlockScore: p.BlockScore, BlockDuration: Duration(p.BlockDuration), BlacklistAfter: p.BlacklistAfter,
			HalfLife: Duration(p.HalfLife), LoginAttempts: p.LoginAttempts,
		},
		Honeypot: Honeypot{
			Enabled: true, Tarpit: h.Tarpit, TarpitMin: Duration(h.TarpitMin), TarpitMax: Duration(h.TarpitMax),
			LearnThreshold: h.LearnThreshold, ProbeMinScore: 5, CanaryTTL: Duration(h.CanaryTTL),
		},
	}
}

// Example is Default with one site filled in, for `rbproxy settings`.
func Example() Config {
	c := Default()
	c.Sites = []Site{{Listen: ":8080", Target: "http://127.0.0.1:3000"}}
	c.Admin.Listen = "127.0.0.1:9090"
	return c
}

// Load reads path over the defaults. Unknown keys are an error, so a typo in
// an option name does not silently fall back to the default.
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c Config) Validate() error {
	switch c.Mode {
	case "monitor", "protect", "deceive":
	default:
		return fmt.Errorf("mode must be monitor, protect or deceive (got %q)", c.Mode)
	}
	if len(c.Sites) == 0 {
		return fmt.Errorf("no sites configured: pass --target or add \"sites\" to the config file")
	}
	for i, s := range c.Sites {
		if s.Listen == "" {
			return fmt.Errorf("sites[%d]: listen is empty", i)
		}
		u, err := url.Parse(s.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("sites[%d]: target must be an http(s) URL like http://127.0.0.1:3000 (got %q)", i, s.Target)
		}
		if (s.Cert == "") != (s.Key == "") {
			return fmt.Errorf("sites[%d]: cert and key must be set together", i)
		}
	}
	if _, err := c.TrustedNets(); err != nil {
		return err
	}
	if c.Admin.Listen != "" && c.Admin.Token == "" {
		host, _, err := net.SplitHostPort(c.Admin.Listen)
		if err == nil {
			ip := net.ParseIP(host)
			if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				return fmt.Errorf("admin API on %s is reachable from the network: set admin.token or bind it to 127.0.0.1", c.Admin.Listen)
			}
		}
	}
	return nil
}

// TrustedNets parses trusted_proxies (CIDRs or single IPs).
func (c Config) TrustedNets() ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range c.TrustedProxies {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %q is not an IP or CIDR", s)
		}
		out = append(out, n)
	}
	return out, nil
}

func (c Config) ProfileConfig() profile.Config {
	p := c.Profile
	return profile.Config{
		Window: time.Duration(p.Window), MaxRequests: p.MaxRequests, WatchScore: p.WatchScore,
		BlockScore: p.BlockScore, BlockDuration: time.Duration(p.BlockDuration), BlacklistAfter: p.BlacklistAfter,
		HalfLife: time.Duration(p.HalfLife), LoginAttempts: p.LoginAttempts,
	}
}

func (c Config) HoneypotConfig() honeypot.Config {
	h := c.Honeypot
	return honeypot.Config{
		Tarpit: h.Tarpit, TarpitMin: time.Duration(h.TarpitMin), TarpitMax: time.Duration(h.TarpitMax),
		LearnThreshold: h.LearnThreshold, LogPasswords: h.LogPasswords, CanaryTTL: time.Duration(h.CanaryTTL),
	}
}
