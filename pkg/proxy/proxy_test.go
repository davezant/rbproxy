package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"rbproxy/internal/events"
	"rbproxy/internal/honeypot"
	"rbproxy/internal/profile"
)

type harness struct {
	px      *Proxy
	h       http.Handler
	backend atomic.Int32
}

func newHarness(t *testing.T, mode Mode) *harness {
	t.Helper()
	hs := &harness{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hs.backend.Add(1)
		switch r.URL.Path {
		case "/":
			io.WriteString(w, "home")
		case "/admin":
			io.WriteString(w, "real admin")
		case "/leaky":
			io.WriteString(w, "debug dump: key=AKIAABCDEFGHIJKLMNOP")
		case "/echo-headers":
			io.WriteString(w, r.Header.Get("X-RBProxy-Score"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)

	sink, err := events.Open("", 500)
	if err != nil {
		t.Fatal(err)
	}
	hcfg := honeypot.DefaultConfig()
	hcfg.Tarpit = false
	hs.px = New(Options{
		Mode: mode, MaxScanBytes: 64 << 10, DetectLeaks: true, RedactLeaks: true, ProbeMinScore: 5,
	}, profile.NewTracker(profile.DefaultConfig()), honeypot.New(hcfg), sink)
	hs.h = hs.px.Handler(u)
	return hs
}

type reqOpt func(*http.Request)

func ua(s string) reqOpt { return func(r *http.Request) { r.Header.Set("User-Agent", s) } }
func form() reqOpt {
	return func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }
}

func (hs *harness) do(method, target, ip, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	hs.h.ServeHTTP(w, r)
	return w
}

func (hs *harness) events(typ string) []events.Event {
	var out []events.Event
	for _, e := range hs.px.Events().Recent(500, "") {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestCleanRequestIsForwarded(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	w := hs.do("GET", "/", "203.0.113.1", "")
	if w.Code != 200 || w.Body.String() != "home" || hs.backend.Load() != 1 {
		t.Fatalf("got %d %q, backend hits %d", w.Code, w.Body.String(), hs.backend.Load())
	}
	if n := len(hs.px.Events().Recent(100, "low")); n != 0 {
		t.Fatalf("clean request produced %d events", n)
	}
}

func TestShadowTrapNeverReachesBackend(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	w := hs.do("GET", "/.env", "203.0.113.2", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "DB_PASSWORD=") {
		t.Fatalf("no .env decoy: %d %q", w.Code, w.Body.String())
	}
	if hs.backend.Load() != 0 {
		t.Fatal(".env request reached the backend")
	}
	if len(hs.events("honeypot_hit")) != 1 {
		t.Fatal("honeypot hit not logged")
	}

	hs = newHarness(t, ModeProtect)
	if w := hs.do("GET", "/.git/config", "203.0.113.2", ""); w.Code != 404 || hs.backend.Load() != 0 {
		t.Fatalf("protect mode: got %d, backend hits %d", w.Code, hs.backend.Load())
	}
}

func TestCanaryReuseLinksClients(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	thief, user := "203.0.113.3", "198.51.100.7"
	hs.do("GET", "/.env", thief, "")
	secret := hs.px.Honeypot().Secrets(thief).AdminPassword

	hs.do("POST", "/login", user, "username=admin&password="+secret, form())

	evs := hs.events("canary_used")
	if len(evs) != 1 || evs[0].Client != user || evs[0].Details["issued_to"] != thief {
		t.Fatalf("canary reuse not attributed: %+v", evs)
	}
	v, _ := hs.px.Tracker().Get(user)
	if len(v.Linked) != 1 || v.Linked[0] != thief {
		t.Fatalf("clients not linked: %+v", v.Linked)
	}
}

func TestAttackHandlingPerMode(t *testing.T) {
	payload := "/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"

	hs := newHarness(t, ModeDeceive)
	w := hs.do("GET", payload, "203.0.113.4", "")
	if w.Code != 500 || !strings.Contains(w.Body.String(), "SQL syntax") || hs.backend.Load() != 0 {
		t.Fatalf("deceive: %d %q (backend %d)", w.Code, w.Body.String(), hs.backend.Load())
	}

	hs = newHarness(t, ModeProtect)
	if w := hs.do("GET", payload, "203.0.113.4", ""); w.Code != 403 || hs.backend.Load() != 0 {
		t.Fatalf("protect: %d (backend %d)", w.Code, hs.backend.Load())
	}

	hs = newHarness(t, ModeMonitor)
	hs.do("GET", payload, "203.0.113.4", "")
	if hs.backend.Load() != 1 || len(hs.events("attack")) != 1 {
		t.Fatalf("monitor: backend %d, attack events %d", hs.backend.Load(), len(hs.events("attack")))
	}
}

func TestForwardFirstTraps(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	// The backend really has /admin: it must be served untouched, no score.
	if w := hs.do("GET", "/admin", "203.0.113.5", ""); w.Body.String() != "real admin" {
		t.Fatalf("real /admin replaced: %q", w.Body.String())
	}
	if s := hs.px.Tracker().Score("203.0.113.5"); s != 0 {
		t.Fatalf("legit /admin visit scored %.1f", s)
	}
	// It does not have WordPress: the 404 becomes a login decoy.
	w := hs.do("GET", "/wp-login.php", "203.0.113.5", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="pwd"`) {
		t.Fatalf("no wp-login decoy: %d", w.Code)
	}
	w = hs.do("POST", "/wp-login.php", "203.0.113.5", "log=admin&pwd=letmein123", form())
	if len(hs.events("credentials_captured")) != 1 || !strings.Contains(w.Body.String(), "is incorrect") {
		t.Fatal("credentials not captured")
	}
}

func TestSpontaneousHoneypotForSuspiciousClients(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	if w := hs.do("GET", "/backups/", "203.0.113.6", ""); w.Code != 404 {
		t.Fatalf("normal client got a decoy: %d", w.Code)
	}
	w := hs.do("GET", "/backups/", "203.0.113.7", "", ua("Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Index of /backups/") {
		t.Fatalf("scanner did not get a spontaneous honeypot: %d %q", w.Code, w.Body.String())
	}
}

func TestLearnsNewTraps(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	for _, ip := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12"} {
		hs.do("GET", "/api/v0/debug", ip, "", ua("sqlmap/1.8"))
	}
	if evs := hs.events("honeypot_created"); len(evs) != 1 {
		t.Fatalf("trap not learned: %+v", evs)
	}
	if tr, ok := hs.px.Honeypot().Match("/api/v0/debug"); !ok || !tr.Learned {
		t.Fatal("learned trap not active")
	}
}

func TestLeakRedaction(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	w := hs.do("GET", "/leaky", "203.0.113.8", "")
	if strings.Contains(w.Body.String(), "AKIAABCDEFGHIJKLMNOP") {
		t.Fatal("leak not redacted")
	}
	if len(hs.events("leak")) != 1 {
		t.Fatal("leak not logged")
	}
}

func TestRepeatedAttacksGetBlocked(t *testing.T) {
	hs := newHarness(t, ModeDeceive)
	ip := "203.0.113.9"
	for i := 0; i < 8; i++ {
		hs.do("GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", ip, "")
	}
	if len(hs.events("blocked")) != 1 {
		t.Fatalf("not blocked; score %.1f", hs.px.Tracker().Score(ip))
	}
	before := hs.backend.Load()
	if w := hs.do("GET", "/", ip, ""); w.Code != 403 || hs.backend.Load() != before {
		t.Fatalf("blocked client still reaches backend: %d", w.Code)
	}
	if w := hs.do("GET", "/", "198.51.100.200", ""); w.Code != 200 {
		t.Fatal("other clients affected by block")
	}
}

func TestClientIdentity(t *testing.T) {
	hs := newHarness(t, ModeMonitor)
	hs.px.opts.ForwardClientInfo = true

	// Untrusted peers cannot choose their identity with X-Forwarded-For,
	// nor forge the headers sent to the backend.
	w := hs.do("GET", "/echo-headers", "203.0.113.20", "", func(r *http.Request) {
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("X-RBProxy-Score", "-100")
	})
	if w.Body.String() == "-100" {
		t.Fatal("spoofed X-RBProxy header reached the backend")
	}
	if _, ok := hs.px.Tracker().Get("1.2.3.4"); ok {
		t.Fatal("untrusted X-Forwarded-For was believed")
	}

	if got := clientKey(mustIP("2001:db8:1:2:aaaa::1")); got != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 key = %s", got)
	}
}

func mustIP(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		panic(s)
	}
	return ip
}
