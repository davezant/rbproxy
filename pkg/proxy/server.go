// Package proxy is the HTTP reverse proxy that ties everything together:
// every request is profiled (internal/profile), scanned for attack payloads
// (internal/security) and checked against honeypot traps and canaries
// (internal/honeypot) before it reaches the backend, and every response is
// checked for leaks and for 404s that can be turned into decoys.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"rbproxy/internal/events"
	"rbproxy/internal/honeypot"
	"rbproxy/internal/profile"
	"rbproxy/internal/security"
	"rbproxy/pkg/terminal"
)

// Mode decides what the proxy does about what it detects.
type Mode string

const (
	// ModeMonitor only scores and logs; everything is forwarded.
	ModeMonitor Mode = "monitor"
	// ModeProtect blocks attacks and abusive clients with 403/429.
	ModeProtect Mode = "protect"
	// ModeDeceive is protect, but attacks get convincing fake answers and
	// suspicious clients get honeypots instead of error pages.
	ModeDeceive Mode = "deceive"
)

type Options struct {
	Mode               Mode
	Verbose            bool
	TrustedProxies     []*net.IPNet
	PreserveHost       bool
	ForwardClientInfo  bool  // send X-RBProxy-Score/Action/Client to the backend
	MaxRequestBytes    int64 // 413 above this
	MaxScanBytes       int   // how much of each body is scanned
	MaxInspectResponse int64 // largest response checked for leaks
	BlockFindingScore  int   // a single finding this strong is never forwarded
	DetectLeaks        bool
	RedactLeaks        bool
	ProbeMinScore      float64 // score from which 404s teach the honeypot
}

type Proxy struct {
	opts     Options
	detector *security.Detector
	tracker  *profile.Tracker
	honey    *honeypot.Engine // nil when honeypots are disabled
	events   *events.Sink
	started  time.Time
}

func New(opts Options, tracker *profile.Tracker, honey *honeypot.Engine, sink *events.Sink) *Proxy {
	if opts.Mode == "" {
		opts.Mode = ModeDeceive
	}
	if opts.BlockFindingScore <= 0 {
		opts.BlockFindingScore = 8
	}
	if opts.MaxInspectResponse <= 0 {
		opts.MaxInspectResponse = 2 << 20
	}
	return &Proxy{
		opts:     opts,
		detector: security.NewDetector(),
		tracker:  tracker,
		honey:    honey,
		events:   sink,
		started:  time.Now(),
	}
}

func (p *Proxy) Tracker() *profile.Tracker  { return p.tracker }
func (p *Proxy) Honeypot() *honeypot.Engine { return p.honey }
func (p *Proxy) Events() *events.Sink       { return p.events }
func (p *Proxy) Close() error               { return p.events.Close() }

// reqState travels with the request through the reverse proxy so that
// ModifyResponse knows who asked and what was already found.
type reqState struct {
	client     string
	trustedHop bool
	method     string
	path       string // normalized
	uri        string
	host       string
	ua         string
	action     profile.Action
	trap       *honeypot.Trap
	req        honeypot.Request
}

type stateKey struct{}

func stateOf(ctx context.Context) *reqState {
	st, _ := ctx.Value(stateKey{}).(*reqState)
	return st
}

// Handler returns the http.Handler that proxies to target.
func (p *Proxy) Handler(target *url.URL) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if st := stateOf(pr.In.Context()); st != nil && st.trustedHop {
				pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			}
			pr.SetXForwarded()
			if p.opts.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
		},
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.backendError,
	}
	return &siteHandler{p: p, rp: rp}
}

type siteHandler struct {
	p  *Proxy
	rp *httputil.ReverseProxy
}

var loginPath = regexp.MustCompile(`login|signin|sign-in|logon|auth|session|xmlrpc|token|password`)

func (h *siteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := h.p

	// Never let a client forge the headers we send to the backend.
	for k := range r.Header {
		if strings.HasPrefix(k, "X-Rbproxy-") {
			r.Header.Del(k)
		}
	}

	client, trusted := p.clientID(r)
	st := &reqState{
		client: client, trustedHop: trusted, method: r.Method, path: honeypot.Normalize(r.URL.Path),
		uri: truncate(r.URL.RequestURI(), 400), host: r.Host, ua: truncate(r.UserAgent(), 300),
	}

	// 1. Blocked clients are answered before any parsing or scanning.
	if p.opts.Mode != ModeMonitor {
		if blocked, _ := p.tracker.CheckBlocked(client); blocked {
			p.deny(w, st, http.StatusForbidden, "", false)
			return
		}
	}

	if p.opts.MaxRequestBytes > 0 {
		if r.ContentLength > p.opts.MaxRequestBytes {
			p.deny(w, st, http.StatusRequestEntityTooLarge, "request body too large", true)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, p.opts.MaxRequestBytes)
	}
	body := peekBody(r, p.opts.MaxScanBytes)
	st.req = honeypot.Request{
		Method: r.Method, Path: r.URL.Path, Host: r.Host, UserAgent: r.UserAgent(),
		Raw: r.URL.RequestURI(), Query: r.URL.Query(), Form: formValues(r, body),
	}

	// 2. Behaviour: rate, scanners, enumeration, brute force.
	for _, sig := range p.tracker.Observe(client, profile.Request{
		Method: r.Method, Path: st.path, UserAgent: r.UserAgent(), IsLogin: loginPath.MatchString(st.path),
	}) {
		p.emitSignal(st, sig)
	}

	// 3. Canaries: someone is using credentials a honeypot handed out.
	if p.honey != nil {
		for _, c := range p.honey.FindCanaries(canaryText(r, body)) {
			p.tracker.Link(client, c.Client)
			p.tracker.Add(client, 50, "canary-reuse")
			msg := "stolen honeypot credential used"
			if c.Client != client {
				msg += " (stolen by " + c.Client + ")"
			}
			p.emit(st, "canary_used", events.Critical, msg, map[string]any{
				"canary_kind": c.Kind, "issued_to": c.Client, "issued_at": c.Issued, "same_client": c.Client == client,
			})
		}
	}

	// 4. Payloads.
	findings := p.detector.ScanRequest(r, body)
	total, peak, top := security.Score(findings)
	if total > 0 {
		cats := security.Categories(findings)
		p.tracker.Attack(client, cats, float64(total))
		shown := findings
		if len(shown) > 8 {
			shown = shown[:8]
		}
		p.emit(st, "attack", severityFor(peak), fmt.Sprintf("%s (score %d)", strings.Join(cats, ","), total), map[string]any{
			"findings": shown, "categories": cats, "score": total,
		})
	}

	// 5. Traps. Shadow traps count now; forward-first traps only count if the
	// backend turns out not to have the path (see modifyResponse).
	if p.honey != nil {
		if t, ok := p.honey.Match(st.path); ok {
			st.trap = &t
			if t.Shadow {
				p.tracker.HoneypotHit(client, t.Name, t.Score)
				p.emit(st, "honeypot_hit", events.Medium, "trap "+t.Name, map[string]any{"trap": t.Name, "kind": t.Kind})
			}
		}
	}

	// 6. Decide.
	dec := p.tracker.Decide(client)
	st.action = dec.Action
	if dec.NewlyBlacklisted {
		p.emit(st, "blacklisted", events.Critical, dec.Reason, map[string]any{"score": round1(dec.Score)})
	} else if dec.NewlyBlocked {
		p.emit(st, "blocked", events.High, dec.Reason, map[string]any{"score": round1(dec.Score), "until": dec.Until})
	}

	if p.opts.Mode != ModeMonitor {
		switch dec.Action {
		case profile.Block:
			p.deny(w, st, http.StatusForbidden, "", false)
			return
		case profile.Throttle:
			w.Header().Set("Retry-After", "60")
			p.deny(w, st, http.StatusTooManyRequests, "", false)
			return
		}
		if st.trap != nil && st.trap.Shadow {
			if p.opts.Mode == ModeDeceive {
				p.serveDecoy(w, r, st, p.honey.Respond(*st.trap, st.req, client))
			} else {
				http.NotFound(w, r)
			}
			return
		}
		if peak >= p.opts.BlockFindingScore || (total > 0 && dec.Action == profile.Watch) {
			if p.opts.Mode == ModeDeceive && p.honey != nil {
				p.serveDecoy(w, r, st, p.honey.Deceive(string(top), st.req, client))
			} else {
				p.deny(w, st, http.StatusForbidden, "attack payload: "+string(top), true)
			}
			return
		}
	}

	// 7. Forward.
	if p.opts.ForwardClientInfo {
		r.Header.Set("X-RBProxy-Client", client)
		r.Header.Set("X-RBProxy-Score", strconv.FormatFloat(dec.Score, 'f', 1, 64))
		r.Header.Set("X-RBProxy-Action", dec.Action.String())
	}
	if p.opts.Verbose {
		terminal.Info("%s %s %s %s", terminal.Highlight(client), r.Method, st.uri, terminal.Dim(dec.Action.String()))
	}
	h.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	st := stateOf(resp.Request.Context())
	if st == nil {
		return nil
	}
	for _, sig := range p.tracker.RecordStatus(st.client, resp.StatusCode) {
		p.emitSignal(st, sig)
	}
	if p.opts.DetectLeaks {
		p.inspectLeaks(resp, st)
	}
	if resp.StatusCode != http.StatusNotFound || p.honey == nil {
		return nil
	}

	// The backend does not have this path.
	if st.trap != nil && !st.trap.Shadow {
		p.tracker.HoneypotHit(st.client, st.trap.Name, st.trap.Score)
		p.emit(st, "honeypot_hit", events.Medium, "probe for "+st.trap.Name, map[string]any{"trap": st.trap.Name, "kind": st.trap.Kind})
	}
	if p.tracker.Score(st.client) >= p.opts.ProbeMinScore {
		if t, ok := p.honey.RecordProbe(st.path, st.client); ok {
			p.emit(st, "honeypot_created", events.Medium, "learned new trap "+t.Pattern, map[string]any{"trap": t.Name, "path": t.Pattern})
		}
	}
	if p.opts.Mode != ModeDeceive {
		return nil
	}

	var d *honeypot.Decoy
	if st.trap != nil {
		d = p.honey.Respond(*st.trap, st.req, st.client)
	} else if st.action == profile.Watch || p.tracker.Suspicious(st.client) {
		d = p.honey.Spontaneous(st.req, st.client)
	}
	if d == nil {
		return nil
	}
	p.noteDecoy(st, d)
	sleep(resp.Request.Context(), d.Delay)
	replaceResponse(resp, d)
	return nil
}

func (p *Proxy) inspectLeaks(resp *http.Response, st *reqState) {
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return
	}
	if !textualResponse(resp.Header.Get("Content-Type")) {
		return
	}
	limit := p.opts.MaxInspectResponse
	// Unknown length is only inspected on errors: a chunked 200 may be a
	// long-lived stream and must not be buffered.
	if resp.ContentLength > limit || (resp.ContentLength < 0 && resp.StatusCode < 400) {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		resp.Body = rejoin(data, resp.Body)
		return
	}
	resp.Body.Close()
	if leaks := security.ScanLeaks(data); len(leaks) > 0 {
		kinds := make([]string, len(leaks))
		for i, l := range leaks {
			kinds[i] = l.Kind
		}
		p.emit(st, "leak", events.High, "backend response leaks "+strings.Join(kinds, ","), map[string]any{
			"leaks": leaks, "status": resp.StatusCode, "redacted": p.opts.RedactLeaks,
		})
		if p.opts.RedactLeaks {
			data = security.RedactLeaks(data)
		}
	}
	setBody(resp, data)
}

func (p *Proxy) backendError(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	case errors.Is(err, context.Canceled):
		return // client went away
	}
	terminal.Error("backend: %v", err)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write(security.BlockPage(http.StatusBadGateway, "Bad Gateway", events.NewID()))
}

func (p *Proxy) deny(w http.ResponseWriter, st *reqState, status int, reason string, log bool) {
	ref := events.NewID()
	if log {
		p.emit(st, "denied", events.Low, reason, map[string]any{"status": status, "ref": ref})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(security.BlockPage(status, http.StatusText(status), ref))
}

func (p *Proxy) serveDecoy(w http.ResponseWriter, r *http.Request, st *reqState, d *honeypot.Decoy) {
	if d == nil {
		http.NotFound(w, r)
		return
	}
	p.noteDecoy(st, d)
	sleep(r.Context(), d.Delay)
	for k, v := range d.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", d.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(d.Body)))
	w.WriteHeader(d.Status)
	_, _ = w.Write(d.Body)
}

func (p *Proxy) noteDecoy(st *reqState, d *honeypot.Decoy) {
	if d.Captured != nil {
		p.emit(st, "credentials_captured", events.High, "login attempt on "+d.Kind+" decoy", map[string]any{
			"decoy": d.Kind, "username": d.Captured["username"], "password": d.Captured["password"],
		})
	}
	p.emit(st, "decoy_served", events.Info, d.Kind, map[string]any{"decoy": d.Kind, "status": d.Status, "bytes": len(d.Body)})
}

func (p *Proxy) emitSignal(st *reqState, sig profile.Signal) {
	sev := events.Low
	switch {
	case strings.HasPrefix(sig.Tag, "scanner:"), sig.Tag == "bruteforce", sig.Tag == "enumeration", sig.Tag == "flood":
		sev = events.Medium
	case sig.Tag == "automation":
		sev = events.Info // curl & co. are worth a note, not an alert
	}
	p.emit(st, "pattern", sev, sig.Tag, map[string]any{"tag": sig.Tag, "score": sig.Score, "detail": sig.Detail})
}

func (p *Proxy) emit(st *reqState, typ, sev, msg string, details map[string]any) {
	p.events.Emit(events.Event{
		Type: typ, Severity: sev, Client: st.client, Method: st.method, Host: st.host,
		URI: st.uri, UserAgent: st.ua, Message: msg, Details: details,
	})
}

// --- helpers ----------------------------------------------------------------

// clientID identifies the client: its IP, the /64 for IPv6 (one host usually
// owns the whole prefix, so rotating addresses inside it does not reset the
// score), and the first untrusted X-Forwarded-For hop behind a trusted proxy.
func (p *Proxy) clientID(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	trusted := ip != nil && p.isTrusted(ip)
	if trusted {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			cand := net.ParseIP(strings.TrimSpace(hops[i]))
			if cand == nil {
				break
			}
			ip = cand
			if !p.isTrusted(cand) {
				break
			}
		}
	}
	if ip == nil {
		return host, trusted
	}
	return clientKey(ip), trusted
}

func clientKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return ip.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (p *Proxy) isTrusted(ip net.IP) bool {
	for _, n := range p.opts.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// peekBody reads up to n bytes of the body for inspection and puts them back,
// so the backend still receives the whole stream.
func peekBody(r *http.Request, n int) []byte {
	if r.Body == nil || r.Body == http.NoBody || n <= 0 {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(r.Body, int64(n)))
	r.Body = rejoin(data, r.Body)
	return data
}

type readCloser struct {
	io.Reader
	io.Closer
}

func rejoin(head []byte, rest io.ReadCloser) io.ReadCloser {
	return readCloser{io.MultiReader(bytes.NewReader(head), rest), rest}
}

func formValues(r *http.Request, body []byte) url.Values {
	if len(body) == 0 {
		return nil
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case mt == "application/x-www-form-urlencoded":
		v, _ := url.ParseQuery(string(body))
		return v
	case strings.Contains(mt, "json"):
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		v := url.Values{}
		for k, x := range m {
			if s, ok := x.(string); ok {
				v.Set(k, s)
			}
		}
		return v
	}
	return nil
}

func canaryText(r *http.Request, body []byte) string {
	var b strings.Builder
	b.WriteString(r.URL.RequestURI())
	b.WriteByte('\n')
	for _, vs := range r.Header {
		for _, v := range vs {
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	if u, pw, ok := r.BasicAuth(); ok {
		b.WriteString(u + "\n" + pw + "\n")
	}
	b.Write(body)
	return b.String()
}

func textualResponse(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil || mt == "text/event-stream" {
		return false
	}
	return strings.HasPrefix(mt, "text/") || strings.Contains(mt, "json") || strings.Contains(mt, "xml") || strings.Contains(mt, "javascript")
}

func setBody(resp *http.Response, data []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.ContentLength = int64(len(data))
	resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
	resp.TransferEncoding = nil
}

func replaceResponse(resp *http.Response, d *honeypot.Decoy) {
	resp.Body.Close()
	h := http.Header{}
	for _, k := range []string{"Server", "Date"} {
		if v := resp.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	for k, v := range d.Headers {
		h.Set(k, v)
	}
	h.Set("Content-Type", d.ContentType)
	resp.Header = h
	resp.StatusCode = d.Status
	resp.Status = fmt.Sprintf("%d %s", d.Status, http.StatusText(d.Status))
	setBody(resp, d.Body)
}

func sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func severityFor(score int) string {
	switch {
	case score >= 9:
		return events.High
	case score >= 7:
		return events.Medium
	}
	return events.Low
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
