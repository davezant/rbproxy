// Package honeypot answers probes with convincing fake content.
//
// There are three ways a request ends up here:
//
//   - Built-in traps: paths no legitimate visitor asks for (/.env, /.git/config,
//     /wp-login.php on a site that is not WordPress...). "Shadow" traps are
//     never forwarded to the backend, so a real leaked .env is never served.
//     The other traps are forwarded first and only become a decoy when the
//     backend answers 404, so a real /admin keeps working.
//   - Spontaneous decoys: when a client is already suspicious, any 404 from the
//     backend is replaced with something plausible for that path (a directory
//     listing, a config file, a SQL dump), so scanners waste time and show
//     what they are after.
//   - Learned traps: paths that several suspicious clients probe and the
//     backend does not have are promoted to permanent traps on their own.
//
// Every decoy that contains credentials uses canary values generated per
// client. If those values ever come back in a request, from any IP, the proxy
// knows who stole them and links both identities.
package honeypot

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Kind string

const (
	KindEnv          Kind = "env"
	KindGit          Kind = "git"
	KindCloudCreds   Kind = "cloud-credentials"
	KindSSHKey       Kind = "ssh-key"
	KindConfigBackup Kind = "config-backup"
	KindDatabaseDump Kind = "database-dump"
	KindWordPress    Kind = "wordpress-login"
	KindXMLRPC       Kind = "xmlrpc"
	KindDBAdmin      Kind = "db-admin"
	KindAdminPanel   Kind = "admin-panel"
	KindPHPInfo      Kind = "phpinfo"
	KindServerStatus Kind = "server-status"
	KindActuator     Kind = "actuator"
	KindExploit      Kind = "exploit-target"
	KindLearned      Kind = "learned"
)

type Trap struct {
	Name      string    `json:"name"`
	Kind      Kind      `json:"kind"`
	Pattern   string    `json:"pattern"`
	Shadow    bool      `json:"shadow"` // answered here, never forwarded
	Score     float64   `json:"score"`
	Learned   bool      `json:"learned"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	Hits      int       `json:"hits"`
	match     func(p string) bool
}

type Config struct {
	Tarpit         bool          // delay decoys to slow scanners down
	TarpitMin      time.Duration //
	TarpitMax      time.Duration //
	LearnThreshold int           // distinct suspicious clients before a path becomes a trap
	LogPasswords   bool          // keep captured passwords in clear text
	CanaryTTL      time.Duration // how long issued canaries are remembered
}

func DefaultConfig() Config {
	return Config{
		Tarpit:         true,
		TarpitMin:      300 * time.Millisecond,
		TarpitMax:      1500 * time.Millisecond,
		LearnThreshold: 3,
		CanaryTTL:      30 * 24 * time.Hour,
	}
}

// Request is the part of an HTTP request a decoy needs.
type Request struct {
	Method    string
	Path      string
	Host      string
	UserAgent string
	Raw       string // path + query as received
	Query     url.Values
	Form      url.Values
}

// Decoy is a fake response.
type Decoy struct {
	Kind        string
	Status      int
	ContentType string
	Headers     map[string]string
	Body        []byte
	Delay       time.Duration
	Captured    map[string]string // credentials typed into a fake login
}

const (
	maxProbePaths = 20_000
	maxLearned    = 5_000
	maxSecrets    = 50_000
)

type Engine struct {
	cfg      Config
	mu       sync.Mutex
	builtin  []*Trap
	learned  map[string]*Trap
	probes   map[string]map[string]struct{} // path -> clients that probed it
	canaries map[string]Canary              // token -> who received it
	secrets  map[string]*issued             // client -> its fake credentials
	now      func() time.Time
}

func New(cfg Config) *Engine {
	d := DefaultConfig()
	if cfg.LearnThreshold <= 0 {
		cfg.LearnThreshold = d.LearnThreshold
	}
	if cfg.CanaryTTL <= 0 {
		cfg.CanaryTTL = d.CanaryTTL
	}
	if cfg.TarpitMax < cfg.TarpitMin {
		cfg.TarpitMax = cfg.TarpitMin
	}
	return &Engine{
		cfg:      cfg,
		builtin:  builtinTraps(),
		learned:  map[string]*Trap{},
		probes:   map[string]map[string]struct{}{},
		canaries: map[string]Canary{},
		secrets:  map[string]*issued{},
		now:      time.Now,
	}
}

// Normalize lowercases and cleans a URL path so "//.ENV" and "/a/../.env"
// match the same trap.
func Normalize(p string) string {
	return strings.ToLower(path.Clean("/" + p))
}

var (
	reConfigBackup = regexp.MustCompile(`^(?:wp-)?config(?:uration)?\.(?:php|inc|ini|json|yml|yaml)(?:\.bak|\.old|\.save|\.orig|\.swp|\.txt|\.dist|~)$|^(?:wp-)?config\.php\.\d+$|^settings\.py\.bak$`)
	reDump         = regexp.MustCompile(`^(?:backup|backups|dump|db|database|mysql|users|sql|site-backup|www)\.(?:sql|sql\.gz|zip|tar\.gz|tgz|bak|rar|7z)$`)
	reExploit      = regexp.MustCompile(`eval-stdin\.php|/(?:shell|cmd|c99|r57|wso|alfa|b374k|webshell|sh|bypass|indoxploit)\.php$|^/boaform/|^/hnap1|^/goform/|/_ignition/execute-solution|/vendor/phpunit/|^/solr/admin/cores|^/remote/fgt_lang|^/mgmt/tm/util/bash|^/api/jsonws/invoke|^/cgi-bin/luci|^/setup\.cgi|^/shell$|^/device\.rsp`)
)

func firstSegment(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

func oneOf(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

func builtinTraps() []*Trap {
	return []*Trap{
		{Name: "dotenv", Kind: KindEnv, Pattern: "**/.env, **/.env.*", Shadow: true, Score: 12,
			match: func(p string) bool { b := path.Base(p); return b == ".env" || strings.HasPrefix(b, ".env.") }},
		{Name: "git", Kind: KindGit, Pattern: "**/.git/**", Shadow: true, Score: 12,
			match: func(p string) bool { return strings.Contains(p+"/", "/.git/") }},
		{Name: "cloud-credentials", Kind: KindCloudCreds, Pattern: "**/.aws/*, **/.docker/config.json, **/.s3cfg", Shadow: true, Score: 15,
			match: func(p string) bool {
				return strings.Contains(p, "/.aws/") || path.Base(p) == ".s3cfg" || strings.HasSuffix(p, "/.docker/config.json")
			}},
		{Name: "ssh-key", Kind: KindSSHKey, Pattern: "**/.ssh/*", Shadow: true, Score: 15,
			match: func(p string) bool { return strings.Contains(p, "/.ssh/") }},
		{Name: "config-backup", Kind: KindConfigBackup, Pattern: "config.php.bak, wp-config.php~, ...", Shadow: true, Score: 12,
			match: func(p string) bool { return reConfigBackup.MatchString(path.Base(p)) }},
		{Name: "exploit-target", Kind: KindExploit, Pattern: "known webshells and RCE endpoints", Shadow: true, Score: 15,
			match: reExploit.MatchString},
		{Name: "database-dump", Kind: KindDatabaseDump, Pattern: "backup.sql, dump.zip, db.tar.gz, ...", Score: 8,
			match: func(p string) bool { return reDump.MatchString(path.Base(p)) }},
		{Name: "wordpress", Kind: KindWordPress, Pattern: "/wp-login.php, /wp-admin/*", Score: 6,
			match: func(p string) bool {
				return p == "/wp-login.php" || p == "/wp-admin" || strings.HasPrefix(p, "/wp-admin/")
			}},
		{Name: "xmlrpc", Kind: KindXMLRPC, Pattern: "**/xmlrpc.php", Score: 5,
			match: func(p string) bool { return path.Base(p) == "xmlrpc.php" }},
		{Name: "db-admin", Kind: KindDBAdmin, Pattern: "/phpmyadmin, /pma, /myadmin, adminer.php", Score: 8,
			match: func(p string) bool {
				return oneOf(firstSegment(p), "phpmyadmin", "pma", "myadmin", "mysqladmin", "dbadmin", "phpmyadmin2", "sqladmin") || path.Base(p) == "adminer.php"
			}},
		{Name: "admin-panel", Kind: KindAdminPanel, Pattern: "/admin, /administrator, /manager/html, /cpanel", Score: 3,
			match: func(p string) bool {
				return oneOf(firstSegment(p), "admin", "administrator", "admin.php", "cpanel", "webadmin", "siteadmin", "admin-console") || strings.HasPrefix(p, "/manager/html")
			}},
		{Name: "phpinfo", Kind: KindPHPInfo, Pattern: "phpinfo.php, info.php, test.php", Score: 6,
			match: func(p string) bool {
				return oneOf(path.Base(p), "phpinfo.php", "info.php", "php_info.php", "test.php", "i.php", "pi.php")
			}},
		{Name: "server-status", Kind: KindServerStatus, Pattern: "/server-status, /server-info", Score: 5,
			match: func(p string) bool { return p == "/server-status" || p == "/server-info" }},
		{Name: "actuator", Kind: KindActuator, Pattern: "/actuator/*", Score: 6,
			match: func(p string) bool { return p == "/actuator" || strings.HasPrefix(p, "/actuator/") }},
	}
}

// Match finds the trap for a path and counts the hit.
func (e *Engine) Match(p string) (Trap, bool) {
	p = Normalize(p)
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.learned[p]; ok {
		t.Hits++
		return *t, true
	}
	for _, t := range e.builtin {
		if t.match(p) {
			t.Hits++
			return *t, true
		}
	}
	return Trap{}, false
}

var staticExt = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".webp": true, ".avif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".otf": true, ".eot": true, ".mp4": true, ".webm": true, ".mp3": true,
}

func ignoreProbe(p string) bool {
	if p == "/" || staticExt[path.Ext(p)] || strings.HasPrefix(p, "/.well-known/") || strings.HasPrefix(p, "/apple-touch-icon") {
		return true
	}
	return oneOf(p, "/favicon.ico", "/robots.txt", "/sitemap.xml", "/ads.txt", "/humans.txt", "/security.txt")
}

// RecordProbe notes that a suspicious client asked for a path the backend does
// not have. Once LearnThreshold distinct clients did, the path becomes a trap.
func (e *Engine) RecordProbe(p, client string) (Trap, bool) {
	p = Normalize(p)
	if ignoreProbe(p) {
		return Trap{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.learned[p]; ok || len(e.learned) >= maxLearned {
		return Trap{}, false
	}
	for _, t := range e.builtin {
		if t.match(p) {
			return Trap{}, false
		}
	}
	set := e.probes[p]
	if set == nil {
		if len(e.probes) >= maxProbePaths {
			for k := range e.probes { // drop an arbitrary entry
				delete(e.probes, k)
				break
			}
		}
		set = map[string]struct{}{}
		e.probes[p] = set
	}
	if len(set) < 64 {
		set[client] = struct{}{}
	}
	if len(set) < e.cfg.LearnThreshold {
		return Trap{}, false
	}
	exact := p
	t := &Trap{
		Name: "learned:" + p, Kind: KindLearned, Pattern: p, Score: 6, Learned: true, CreatedAt: e.now(),
		match: func(q string) bool { return q == exact },
	}
	e.learned[p] = t
	delete(e.probes, p)
	return *t, true
}

// Traps lists built-in and learned traps.
func (e *Engine) Traps() []Trap {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Trap, 0, len(e.builtin)+len(e.learned))
	for _, t := range e.builtin {
		out = append(out, *t)
	}
	learned := make([]Trap, 0, len(e.learned))
	for _, t := range e.learned {
		learned = append(learned, *t)
	}
	sort.Slice(learned, func(i, j int) bool { return learned[i].CreatedAt.Before(learned[j].CreatedAt) })
	return append(out, learned...)
}

// Sweep forgets expired canaries.
func (e *Engine) Sweep() {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for tok, c := range e.canaries {
		if now.Sub(c.Issued) > e.cfg.CanaryTTL {
			delete(e.canaries, tok)
		}
	}
	for client, s := range e.secrets {
		if now.Sub(s.at) > e.cfg.CanaryTTL {
			delete(e.secrets, client)
		}
	}
}
