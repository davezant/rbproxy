package honeypot

import (
	"archive/zip"
	"bytes"
	"net/url"
	"strings"
	"testing"
)

func testEngine() *Engine {
	cfg := DefaultConfig()
	cfg.Tarpit = false
	return New(cfg)
}

func TestMatch(t *testing.T) {
	e := testEngine()
	cases := map[string]Kind{
		"/.env":                    KindEnv,
		"//api/../.ENV.production": KindEnv,
		"/.git/config":             KindGit,
		"/wp-login.php":            KindWordPress,
		"/phpMyAdmin/index.php":    KindDBAdmin,
		"/backup.sql":              KindDatabaseDump,
		"/wp-config.php.bak":       KindConfigBackup,
		"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": KindExploit,
		"/.aws/credentials": KindCloudCreds,
	}
	for p, want := range cases {
		tr, ok := e.Match(p)
		if !ok || tr.Kind != want {
			t.Errorf("Match(%q) = %v %v, want %v", p, tr.Kind, ok, want)
		}
	}
	for _, p := range []string{"/", "/index.html", "/api/users", "/static/app.js", "/environment"} {
		if tr, ok := e.Match(p); ok {
			t.Errorf("Match(%q) unexpectedly hit %s", p, tr.Name)
		}
	}
}

func TestCanaryRoundTrip(t *testing.T) {
	e := testEngine()
	tr, _ := e.Match("/.env")
	d := e.Respond(tr, Request{Method: "GET", Path: "/.env", Host: "shop.example"}, "203.0.113.5")
	if d == nil || d.Status != 200 {
		t.Fatalf("bad decoy: %+v", d)
	}
	s := e.Secrets("203.0.113.5")
	if !bytes.Contains(d.Body, []byte(s.DBPassword)) || !bytes.Contains(d.Body, []byte(s.AWSAccessKey)) {
		t.Fatal("decoy does not contain the client's canaries")
	}

	// Later, from a different IP, someone logs in with the stolen password.
	got := e.FindCanaries("username=admin&password=" + s.AdminPassword)
	if len(got) != 1 || got[0].Client != "203.0.113.5" || got[0].Kind != "admin-password" {
		t.Fatalf("canary not attributed: %+v", got)
	}
	if e.FindCanaries("username=admin&password=hunter2hunter2") != nil {
		t.Fatal("false canary match")
	}

	// Secrets are stable per client, different between clients.
	if e.Secrets("203.0.113.5") != s {
		t.Fatal("secrets changed between requests")
	}
	if e.Secrets("198.51.100.1").DBPassword == s.DBPassword {
		t.Fatal("two clients share a canary")
	}
}

func TestLearning(t *testing.T) {
	e := testEngine()
	for i, c := range []string{"a", "b"} {
		if _, created := e.RecordProbe("/old-api/export", c); created {
			t.Fatalf("created after %d probes", i+1)
		}
	}
	e.RecordProbe("/old-api/export", "a") // same client again doesn't count
	tr, created := e.RecordProbe("/OLD-API/export", "c")
	if !created || !tr.Learned {
		t.Fatal("trap not learned after 3 distinct clients")
	}
	if m, ok := e.Match("/old-api/export"); !ok || m.Kind != KindLearned {
		t.Fatal("learned trap does not match")
	}
	if _, created := e.RecordProbe("/favicon.ico", "x"); created {
		t.Fatal("learned an ignored path")
	}
}

func TestLoginCapture(t *testing.T) {
	e := testEngine()
	tr, _ := e.Match("/wp-login.php")
	form := url.Values{"log": {"admin"}, "pwd": {"Summer2024!"}}
	d := e.Respond(tr, Request{Method: "POST", Path: "/wp-login.php", Host: "x", Form: form}, "c")
	if d.Captured["username"] != "admin" || strings.Contains(d.Captured["password"], "Summer2024!") {
		t.Fatalf("bad capture: %+v", d.Captured)
	}
	if !bytes.Contains(d.Body, []byte("is incorrect")) {
		t.Fatal("login error not shown")
	}
}

func TestSpontaneous(t *testing.T) {
	e := testEngine()
	if d := e.Spontaneous(Request{Path: "/img/logo.png"}, "c"); d != nil {
		t.Fatal("faked a static asset")
	}
	d := e.Spontaneous(Request{Path: "/backups/", Host: "x"}, "c")
	if d == nil || !bytes.Contains(d.Body, []byte("Index of /backups/")) {
		t.Fatalf("no directory listing: %+v", d)
	}
	d = e.Spontaneous(Request{Path: "/files/site.zip", Host: "x"}, "c")
	zr, err := zip.NewReader(bytes.NewReader(d.Body), int64(len(d.Body)))
	if err != nil || len(zr.File) != 1 {
		t.Fatalf("invalid zip decoy: %v", err)
	}
}
