// Package profile keeps a behavioural profile of every client (IP, or /64 for
// IPv6) and turns it into a threat score that decays over time.
//
// The score is fed by two sources: what the client sends (attack payloads,
// honeypot hits, reused canary credentials — reported by the proxy) and how
// the client behaves (request rate, 404 ratio, scanner user agents, login
// bursts — detected here). The score maps to an Action.
package profile

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Action int

const (
	Allow    Action = iota
	Watch           // suspicious: attack payloads get decoys, 404s become honeypots
	Throttle        // over the rate limit
	Block           // temporarily blocked or blacklisted
)

func (a Action) String() string {
	switch a {
	case Watch:
		return "watch"
	case Throttle:
		return "throttle"
	case Block:
		return "block"
	}
	return "allow"
}

type Config struct {
	Window         time.Duration // sliding window for rates
	MaxRequests    int           // requests per Window before throttling
	WatchScore     float64
	BlockScore     float64
	BlockDuration  time.Duration // first block; doubles on each repeat, max 24h
	BlacklistAfter int           // blocks before a permanent blacklist (0 = never)
	HalfLife       time.Duration // score halves every HalfLife
	LoginAttempts  int           // login POSTs per Window before "bruteforce"
	IdleEvict      time.Duration // forget clean clients idle this long
	MaxClients     int
}

func DefaultConfig() Config {
	return Config{
		Window:         time.Minute,
		MaxRequests:    300,
		WatchScore:     15,
		BlockScore:     60,
		BlockDuration:  15 * time.Minute,
		BlacklistAfter: 3,
		HalfLife:       10 * time.Minute,
		LoginAttempts:  10,
		IdleEvict:      time.Hour,
		MaxClients:     100_000,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Window <= 0 {
		c.Window = d.Window
	}
	if c.MaxRequests <= 0 {
		c.MaxRequests = d.MaxRequests
	}
	if c.WatchScore <= 0 {
		c.WatchScore = d.WatchScore
	}
	if c.BlockScore <= 0 {
		c.BlockScore = d.BlockScore
	}
	if c.BlockDuration <= 0 {
		c.BlockDuration = d.BlockDuration
	}
	if c.HalfLife <= 0 {
		c.HalfLife = d.HalfLife
	}
	if c.LoginAttempts <= 0 {
		c.LoginAttempts = d.LoginAttempts
	}
	if c.IdleEvict <= 0 {
		c.IdleEvict = d.IdleEvict
	}
	if c.MaxClients <= 0 {
		c.MaxClients = d.MaxClients
	}
	return c
}

// Request is what the tracker needs to know about one request.
type Request struct {
	Method    string
	Path      string
	UserAgent string
	IsLogin   bool
}

// Signal is a behavioural pattern that just fired for a client.
type Signal struct {
	Tag    string  `json:"tag"`
	Score  float64 `json:"score"`
	Detail string  `json:"detail,omitempty"`
}

type Decision struct {
	Action           Action
	Score            float64
	Reason           string
	Until            time.Time
	NewlyBlocked     bool
	NewlyBlacklisted bool
}

var (
	scannerUA    = regexp.MustCompile(`(?i)\b(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|ffuf|wfuzz|feroxbuster|nuclei|wpscan|joomscan|acunetix|netsparker|nessus|openvas|qualys|burp(?:suite)?|hydra|commix|whatweb|jaeles|xsstrike|arachni|w3af|skipfish|zmeu|morfeus|l9explore|l9tcpid|interactsh)\b`)
	automationUA = regexp.MustCompile(`(?i)^(?:curl|wget|python-requests|python-urllib|python-httpx|go-http-client|java/|okhttp|libwww-perl|aiohttp|axios|node-fetch|apache-httpclient|scrapy|php/|ruby|mechanize)`)
	oddMethods   = map[string]bool{"TRACE": true, "TRACK": true, "CONNECT": true, "DEBUG": true, "PROPFIND": true, "SEARCH": true}
)

const (
	maxPaths  = 300
	maxAgents = 20
)

type client struct {
	id                  string
	firstSeen, lastSeen time.Time
	requests            int
	notFound            int
	honeypotHits        int
	blockedHits         int
	score               float64
	scoreAt             time.Time
	hits                []time.Time // requests inside Window
	misses              []time.Time // 404s inside Window
	logins              []time.Time // login POSTs inside Window
	paths               map[string]int
	agents              map[string]int
	methods             map[string]int
	tags                map[string]time.Time // tag -> last time it fired
	categories          map[string]int
	linked              map[string]bool
	blockedUntil        time.Time
	blocks              int
	blacklisted         bool
}

// Tracker is safe for concurrent use.
type Tracker struct {
	cfg     Config
	mu      sync.Mutex
	clients map[string]*client
	now     func() time.Time
}

func NewTracker(cfg Config) *Tracker {
	return &Tracker{cfg: cfg.withDefaults(), clients: map[string]*client{}, now: time.Now}
}

func (t *Tracker) Config() Config { return t.cfg }

func (t *Tracker) get(id string, now time.Time) *client {
	c := t.clients[id]
	if c == nil {
		c = &client{
			id: id, firstSeen: now, lastSeen: now, scoreAt: now,
			paths: map[string]int{}, agents: map[string]int{}, methods: map[string]int{},
			tags: map[string]time.Time{}, categories: map[string]int{}, linked: map[string]bool{},
		}
		t.clients[id] = c
	}
	c.decay(now, t.cfg.HalfLife)
	return c
}

func (c *client) decay(now time.Time, half time.Duration) {
	if el := now.Sub(c.scoreAt); el > 0 && c.score > 0 {
		c.score *= math.Pow(0.5, float64(el)/float64(half))
		if c.score < 0.01 {
			c.score = 0
		}
	}
	c.scoreAt = now
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}

func bump(m map[string]int, k string, limit int) {
	if _, ok := m[k]; ok || len(m) < limit {
		m[k]++
		return
	}
	m["(other)"]++
}

// raise fires a tag at most once per Window and adds its score.
func (t *Tracker) raise(c *client, now time.Time, tag string, score float64, detail string) (Signal, bool) {
	if last, ok := c.tags[tag]; ok && now.Sub(last) < t.cfg.Window {
		return Signal{}, false
	}
	c.tags[tag] = now
	c.score += score
	return Signal{Tag: tag, Score: score, Detail: detail}, true
}

// Observe records a request and returns the behavioural patterns that fired.
func (t *Tracker) Observe(id string, r Request) []Signal {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	c := t.get(id, now)
	c.lastSeen = now
	c.requests++
	cutoff := now.Add(-t.cfg.Window)
	c.hits = append(prune(c.hits, cutoff), now)
	if len(c.hits) > 2*t.cfg.MaxRequests+10 {
		c.hits = append([]time.Time(nil), c.hits[len(c.hits)-t.cfg.MaxRequests-1:]...)
	}
	bump(c.paths, r.Path, maxPaths)
	bump(c.agents, r.UserAgent, maxAgents)
	bump(c.methods, r.Method, 16)

	var out []Signal
	emit := func(s Signal, ok bool) {
		if ok {
			out = append(out, s)
		}
	}

	if len(c.hits) > t.cfg.MaxRequests {
		emit(t.raise(c, now, "flood", 5, fmt.Sprintf("%d requests in %s", len(c.hits), t.cfg.Window)))
	}

	ua := strings.TrimSpace(r.UserAgent)
	switch {
	case ua == "":
		emit(t.raise(c, now, "no-user-agent", 2, ""))
	case scannerUA.MatchString(ua):
		name := strings.ToLower(scannerUA.FindStringSubmatch(ua)[1])
		emit(t.raise(c, now, "scanner:"+name, 20, ua))
	case automationUA.MatchString(ua):
		emit(t.raise(c, now, "automation", 1, ua))
	}

	if len(c.agents) >= 5 {
		emit(t.raise(c, now, "ua-rotation", 8, fmt.Sprintf("%d distinct user agents", len(c.agents))))
	}

	if m := strings.ToUpper(r.Method); oddMethods[m] {
		emit(t.raise(c, now, "odd-method:"+m, 3, ""))
	}

	if r.IsLogin && r.Method == "POST" {
		c.logins = append(prune(c.logins, cutoff), now)
		if len(c.logins) > t.cfg.LoginAttempts {
			emit(t.raise(c, now, "bruteforce", 15, fmt.Sprintf("%d login attempts in %s", len(c.logins), t.cfg.Window)))
		}
	}
	return out
}

// RecordStatus feeds the backend's answer back; lots of 404s means enumeration.
func (t *Tracker) RecordStatus(id string, status int) []Signal {
	if status != 404 {
		return nil
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	c := t.get(id, now)
	c.notFound++
	cutoff := now.Add(-t.cfg.Window)
	c.misses = append(prune(c.misses, cutoff), now)
	c.hits = prune(c.hits, cutoff)
	if len(c.misses) >= 15 && float64(len(c.misses)) >= 0.5*float64(len(c.hits)) {
		if s, ok := t.raise(c, now, "enumeration", 12, fmt.Sprintf("%d of %d requests were 404 in %s", len(c.misses), len(c.hits), t.cfg.Window)); ok {
			return []Signal{s}
		}
	}
	return nil
}

// Attack adds the score of payloads found in a request.
func (t *Tracker) Attack(id string, categories []string, score float64) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.get(id, now)
	c.score += score
	for _, cat := range categories {
		c.categories[cat]++
		c.tags["attack:"+cat] = now
	}
}

// HoneypotHit records that the client touched a trap.
func (t *Tracker) HoneypotHit(id, trap string, score float64) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.get(id, now)
	c.honeypotHits++
	c.score += score
	c.tags["honeypot:"+trap] = now
}

// Add adds score under a tag, without the once-per-window limit.
func (t *Tracker) Add(id string, score float64, tag string) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.get(id, now)
	c.score += score
	if tag != "" {
		c.tags[tag] = now
	}
}

// Link marks two clients as the same actor (e.g. one used credentials the
// other stole from a honeypot).
func (t *Tracker) Link(a, b string) {
	if a == b || a == "" || b == "" {
		return
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.get(a, now).linked[b] = true
	t.get(b, now).linked[a] = true
}

// Score returns the current (decayed) score.
func (t *Tracker) Score(id string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.clients[id]
	if c == nil {
		return 0
	}
	c.decay(t.now(), t.cfg.HalfLife)
	return c.score
}

// Suspicious reports whether the client is at or above the watch threshold.
func (t *Tracker) Suspicious(id string) bool { return t.Score(id) >= t.cfg.WatchScore }

// CheckBlocked is the cheap first check on every request: blocked clients are
// answered without parsing or scanning anything.
func (t *Tracker) CheckBlocked(id string) (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.clients[id]
	if c == nil {
		return false, ""
	}
	now := t.now()
	switch {
	case c.blacklisted:
		c.blockedHits++
		c.lastSeen = now
		return true, "blacklisted"
	case now.Before(c.blockedUntil):
		c.blockedHits++
		c.lastSeen = now
		return true, "temporarily blocked"
	}
	return false, ""
}

// Decide turns the current profile into an action, escalating blocks.
func (t *Tracker) Decide(id string) Decision {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.get(id, now)
	d := Decision{Score: c.score}

	switch {
	case c.blacklisted:
		d.Action, d.Reason = Block, "blacklisted"
	case now.Before(c.blockedUntil):
		d.Action, d.Reason, d.Until = Block, "temporarily blocked", c.blockedUntil
	case c.score >= t.cfg.BlockScore:
		c.blocks++
		dur := t.cfg.BlockDuration << (c.blocks - 1)
		if dur > 24*time.Hour || dur <= 0 {
			dur = 24 * time.Hour
		}
		c.blockedUntil = now.Add(dur)
		d.Action, d.Reason, d.Until, d.NewlyBlocked = Block, fmt.Sprintf("threat score %.0f", c.score), c.blockedUntil, true
		if t.cfg.BlacklistAfter > 0 && c.blocks >= t.cfg.BlacklistAfter {
			c.blacklisted = true
			d.NewlyBlacklisted = true
			d.Reason = fmt.Sprintf("blocked %d times", c.blocks)
		}
	case len(prune(c.hits, now.Add(-t.cfg.Window))) > t.cfg.MaxRequests:
		d.Action, d.Reason = Throttle, "rate limit"
	case c.score >= t.cfg.WatchScore:
		d.Action, d.Reason = Watch, fmt.Sprintf("threat score %.0f", c.score)
	}
	return d
}

// Block blocks a client manually. d <= 0 blacklists it.
func (t *Tracker) Block(id string, d time.Duration) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.get(id, now)
	if d <= 0 {
		c.blacklisted = true
		return
	}
	c.blockedUntil = now.Add(d)
}

// Unblock clears blocks, blacklist and score.
func (t *Tracker) Unblock(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.clients[id]
	if c == nil {
		return false
	}
	c.blacklisted = false
	c.blockedUntil = time.Time{}
	c.blocks = 0
	c.score = 0
	return true
}

// Sweep forgets idle clients that are not blocked, so memory stays bounded.
func (t *Tracker) Sweep() int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	removed := 0
	for id, c := range t.clients {
		if c.blacklisted || now.Before(c.blockedUntil) {
			continue
		}
		if now.Sub(c.lastSeen) > t.cfg.IdleEvict {
			delete(t.clients, id)
			removed++
		}
	}
	if len(t.clients) > t.cfg.MaxClients {
		all := make([]*client, 0, len(t.clients))
		for _, c := range t.clients {
			if !c.blacklisted {
				all = append(all, c)
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].lastSeen.Before(all[j].lastSeen) })
		for _, c := range all {
			if len(t.clients) <= t.cfg.MaxClients {
				break
			}
			delete(t.clients, c.id)
			removed++
		}
	}
	return removed
}

// View is a JSON-friendly snapshot of a client.
type View struct {
	ID           string         `json:"id"`
	Score        float64        `json:"score"`
	Action       string         `json:"action"`
	Requests     int            `json:"requests"`
	RatePerMin   float64        `json:"rate_per_min"`
	NotFound     int            `json:"not_found"`
	HoneypotHits int            `json:"honeypot_hits"`
	BlockedHits  int            `json:"blocked_hits"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	BlockedUntil *time.Time     `json:"blocked_until,omitempty"`
	Blocks       int            `json:"blocks"`
	Blacklisted  bool           `json:"blacklisted"`
	Tags         []string       `json:"tags"`
	Categories   map[string]int `json:"attack_categories,omitempty"`
	TopPaths     []PathCount    `json:"top_paths"`
	UserAgents   []string       `json:"user_agents"`
	Methods      map[string]int `json:"methods"`
	Linked       []string       `json:"linked,omitempty"`
}

type PathCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

func (t *Tracker) view(c *client, now time.Time) View {
	v := View{
		ID: c.id, Score: math.Round(c.score*10) / 10, Requests: c.requests, NotFound: c.notFound,
		HoneypotHits: c.honeypotHits, BlockedHits: c.blockedHits, FirstSeen: c.firstSeen, LastSeen: c.lastSeen,
		Blocks: c.blocks, Blacklisted: c.blacklisted, Methods: map[string]int{}, Categories: map[string]int{},
	}
	hits := prune(c.hits, now.Add(-t.cfg.Window))
	v.RatePerMin = math.Round(float64(len(hits))/t.cfg.Window.Minutes()*10) / 10
	switch {
	case c.blacklisted || now.Before(c.blockedUntil):
		v.Action = Block.String()
	case len(hits) > t.cfg.MaxRequests:
		v.Action = Throttle.String()
	case c.score >= t.cfg.WatchScore:
		v.Action = Watch.String()
	default:
		v.Action = Allow.String()
	}
	if now.Before(c.blockedUntil) {
		u := c.blockedUntil
		v.BlockedUntil = &u
	}
	for tag := range c.tags {
		v.Tags = append(v.Tags, tag)
	}
	sort.Strings(v.Tags)
	for k, n := range c.categories {
		v.Categories[k] = n
	}
	for p, n := range c.paths {
		v.TopPaths = append(v.TopPaths, PathCount{p, n})
	}
	sort.Slice(v.TopPaths, func(i, j int) bool {
		if v.TopPaths[i].Count != v.TopPaths[j].Count {
			return v.TopPaths[i].Count > v.TopPaths[j].Count
		}
		return v.TopPaths[i].Path < v.TopPaths[j].Path
	})
	if len(v.TopPaths) > 10 {
		v.TopPaths = v.TopPaths[:10]
	}
	for ua := range c.agents {
		v.UserAgents = append(v.UserAgents, ua)
	}
	sort.Strings(v.UserAgents)
	for m, n := range c.methods {
		v.Methods[m] = n
	}
	for l := range c.linked {
		v.Linked = append(v.Linked, l)
	}
	sort.Strings(v.Linked)
	return v
}

// Get returns one client's profile.
func (t *Tracker) Get(id string) (View, bool) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.clients[id]
	if c == nil {
		return View{}, false
	}
	c.decay(now, t.cfg.HalfLife)
	return t.view(c, now), true
}

// List returns clients with score >= minScore, highest first.
func (t *Tracker) List(minScore float64, limit int) []View {
	now := t.now()
	t.mu.Lock()
	out := make([]View, 0)
	for _, c := range t.clients {
		c.decay(now, t.cfg.HalfLife)
		if c.score >= minScore || c.blacklisted {
			out = append(out, t.view(c, now))
		}
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Len returns how many clients are tracked.
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.clients)
}
