package honeypot

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	mrand "math/rand/v2"
	"regexp"
	"time"
)

// Canary is a fake secret handed to one client. Seeing it again in any request
// means someone is using credentials stolen from a honeypot.
type Canary struct {
	Token  string    `json:"-"`
	Kind   string    `json:"kind"`
	Client string    `json:"issued_to"`
	Issued time.Time `json:"issued_at"`
}

// Secrets are the fake credentials embedded in decoys for one client. They
// stay the same across requests so a scanner sees a consistent "server".
type Secrets struct {
	AWSAccessKey  string
	AWSSecretKey  string
	DBUser        string
	DBPassword    string
	AppKey        string
	APIKey        string
	GitToken      string
	AdminUser     string
	AdminPassword string
}

type issued struct {
	s  *Secrets
	at time.Time
}

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upper32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func randString(alphabet string, n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // crypto/rand never fails on supported platforms
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

func randBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

var dbUsers = []string{"app", "webapp", "deploy", "prod_rw", "backend", "svc_web"}

// secretsFor returns the client's fake credentials, issuing them on first use.
// The caller must hold e.mu.
func (e *Engine) secretsFor(client string) *Secrets {
	if s, ok := e.secrets[client]; ok {
		return s.s
	}
	if len(e.secrets) >= maxSecrets {
		for k := range e.secrets {
			delete(e.secrets, k)
			break
		}
	}
	s := &Secrets{
		AWSAccessKey:  "AKIA" + randString(upper32, 16),
		AWSSecretKey:  randString(alnum, 40),
		DBUser:        dbUsers[mrand.IntN(len(dbUsers))],
		DBPassword:    randString(alnum, 18),
		AppKey:        "base64:" + randBase64(32),
		APIKey:        "sk_live_" + randString(alnum, 24),
		GitToken:      "ghp_" + randString(alnum, 36),
		AdminUser:     "admin",
		AdminPassword: randString(alnum, 14),
	}
	now := e.now()
	e.secrets[client] = &issued{s: s, at: now}
	for kind, tok := range map[string]string{
		"aws-access-key": s.AWSAccessKey,
		"aws-secret-key": s.AWSSecretKey,
		"db-password":    s.DBPassword,
		"api-key":        s.APIKey,
		"git-token":      s.GitToken,
		"admin-password": s.AdminPassword,
	} {
		e.canaries[tok] = Canary{Token: tok, Kind: kind, Client: client, Issued: now}
	}
	return s
}

// Secrets returns (issuing if needed) the fake credentials of a client.
func (e *Engine) Secrets(client string) Secrets {
	e.mu.Lock()
	defer e.mu.Unlock()
	return *e.secretsFor(client)
}

// Canary tokens are alphanumeric (plus "_"), so splitting the request on
// anything else finds them whether they arrive in a query, a form, JSON or a
// decoded Basic auth header.
var tokenRe = regexp.MustCompile(`[A-Za-z0-9_]{12,64}`)

// FindCanaries returns the canaries present in text.
func (e *Engine) FindCanaries(text string) []Canary {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.canaries) == 0 {
		return nil
	}
	var out []Canary
	seen := map[string]bool{}
	for _, tok := range tokenRe.FindAllString(text, 1000) {
		if c, ok := e.canaries[tok]; ok && !seen[tok] {
			seen[tok] = true
			out = append(out, c)
		}
	}
	return out
}

func (e *Engine) delay() time.Duration {
	if !e.cfg.Tarpit || e.cfg.TarpitMax <= 0 {
		return 0
	}
	span := e.cfg.TarpitMax - e.cfg.TarpitMin
	if span <= 0 {
		return e.cfg.TarpitMin
	}
	return e.cfg.TarpitMin + time.Duration(mrand.Int64N(int64(span)))
}
