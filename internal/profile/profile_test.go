package profile

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestTracker(cfg Config) (*Tracker, *clock) {
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	tr := NewTracker(cfg)
	tr.now = clk.now
	return tr, clk
}

func hasTag(sigs []Signal, tag string) bool {
	for _, s := range sigs {
		if s.Tag == tag {
			return true
		}
	}
	return false
}

func TestScannerUserAgent(t *testing.T) {
	tr, _ := newTestTracker(DefaultConfig())
	sigs := tr.Observe("1.1.1.1", Request{Method: "GET", Path: "/", UserAgent: "sqlmap/1.7#stable (https://sqlmap.org)"})
	if !hasTag(sigs, "scanner:sqlmap") {
		t.Fatalf("scanner not detected: %+v", sigs)
	}
	// Fires once per window, not on every request.
	if sigs := tr.Observe("1.1.1.1", Request{Method: "GET", Path: "/", UserAgent: "sqlmap/1.7"}); len(sigs) != 0 {
		t.Fatalf("signal repeated: %+v", sigs)
	}
	if d := tr.Decide("1.1.1.1"); d.Action != Watch {
		t.Fatalf("expected watch, got %v (score %.1f)", d.Action, d.Score)
	}
}

func TestEnumeration(t *testing.T) {
	tr, _ := newTestTracker(DefaultConfig())
	var fired bool
	for i := 0; i < 20; i++ {
		tr.Observe("2.2.2.2", Request{Method: "GET", Path: fmt.Sprintf("/x%d", i), UserAgent: "Mozilla/5.0"})
		if hasTag(tr.RecordStatus("2.2.2.2", 404), "enumeration") {
			fired = true
		}
	}
	if !fired {
		t.Fatal("enumeration not detected")
	}
}

func TestBruteforce(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LoginAttempts = 3
	tr, _ := newTestTracker(cfg)
	var fired bool
	for i := 0; i < 5; i++ {
		if hasTag(tr.Observe("3.3.3.3", Request{Method: "POST", Path: "/login", UserAgent: "Mozilla/5.0", IsLogin: true}), "bruteforce") {
			fired = true
		}
	}
	if !fired {
		t.Fatal("bruteforce not detected")
	}
}

func TestRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRequests = 5
	tr, clk := newTestTracker(cfg)
	for i := 0; i < 6; i++ {
		tr.Observe("4.4.4.4", Request{Method: "GET", Path: "/", UserAgent: "Mozilla/5.0"})
	}
	if d := tr.Decide("4.4.4.4"); d.Action != Throttle {
		t.Fatalf("expected throttle, got %v", d.Action)
	}
	clk.advance(2 * time.Minute)
	if d := tr.Decide("4.4.4.4"); d.Action == Throttle {
		t.Fatal("throttle did not expire with the window")
	}
}

func TestBlockEscalatesToBlacklist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BlacklistAfter = 2
	tr, clk := newTestTracker(cfg)

	tr.Attack("5.5.5.5", []string{"sqli"}, 70)
	d := tr.Decide("5.5.5.5")
	if d.Action != Block || !d.NewlyBlocked {
		t.Fatalf("expected new block, got %+v", d)
	}
	if blocked, _ := tr.CheckBlocked("5.5.5.5"); !blocked {
		t.Fatal("CheckBlocked disagrees with Decide")
	}

	clk.advance(cfg.BlockDuration + time.Second)
	if blocked, _ := tr.CheckBlocked("5.5.5.5"); blocked {
		t.Fatal("block did not expire")
	}

	tr.Attack("5.5.5.5", []string{"sqli"}, 70)
	d = tr.Decide("5.5.5.5")
	if !d.NewlyBlacklisted {
		t.Fatalf("expected blacklist on second block, got %+v", d)
	}
	clk.advance(48 * time.Hour)
	if blocked, reason := tr.CheckBlocked("5.5.5.5"); !blocked || reason != "blacklisted" {
		t.Fatal("blacklist expired")
	}
	tr.Unblock("5.5.5.5")
	if blocked, _ := tr.CheckBlocked("5.5.5.5"); blocked {
		t.Fatal("unblock failed")
	}
}

func TestScoreDecays(t *testing.T) {
	tr, clk := newTestTracker(DefaultConfig())
	tr.Add("6.6.6.6", 40, "test")
	clk.advance(10 * time.Minute)
	if s := tr.Score("6.6.6.6"); s < 19.9 || s > 20.1 {
		t.Fatalf("expected ~20 after one half-life, got %.2f", s)
	}
}

func TestSweep(t *testing.T) {
	tr, clk := newTestTracker(DefaultConfig())
	tr.Observe("7.7.7.7", Request{Method: "GET", Path: "/"})
	tr.Block("8.8.8.8", 0)
	clk.advance(2 * time.Hour)
	tr.Sweep()
	if _, ok := tr.Get("7.7.7.7"); ok {
		t.Fatal("idle client not evicted")
	}
	if _, ok := tr.Get("8.8.8.8"); !ok {
		t.Fatal("blacklisted client evicted")
	}
}
