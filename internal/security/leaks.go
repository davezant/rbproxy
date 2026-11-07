package security

import "regexp"

// Leak is sensitive data found in a backend response.
type Leak struct {
	Kind   string `json:"kind"`
	Sample string `json:"sample"`
}

type leakRule struct {
	kind   string
	secret bool // secrets get redacted; error pages are only reported
	re     *regexp.Regexp
}

var leakRules = []leakRule{
	{"aws-access-key", true, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"private-key", true, regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`)},
	{"github-token", true, regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"slack-token", true, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"stripe-key", true, regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b`)},
	{"google-api-key", true, regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"env-secret", true, regexp.MustCompile(`(?im)^\s*(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|APP_KEY|AWS_SECRET_ACCESS_KEY|MAIL_PASSWORD|REDIS_PASSWORD|JWT_SECRET)\s*=\s*\S+`)},
	{"connection-string", true, regexp.MustCompile(`(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@`)},
	{"stack-trace", false, regexp.MustCompile(`Traceback \(most recent call last\)|\bat [\w$.]+\(\w+\.java:\d+\)|goroutine \d+ \[running\]|System\.[\w.]+Exception|(?i)(?:fatal error|parse error|warning):.{0,300}? on line (?:<b>)?\d+|\bat [\w.<>]+ \((?:/|[A-Z]:\\)[^)]+:\d+:\d+\)`)},
	{"sql-error", false, regexp.MustCompile(`(?i)you have an error in your sql syntax|\bORA-\d{5}\b|PG::SyntaxError|SQLSTATE\[|sqlite3?\.OperationalError|unclosed quotation mark after the character string`)},
	{"directory-listing", false, regexp.MustCompile(`<title>Index of /`)},
}

// ScanLeaks reports at most one leak per kind, with the secret masked.
func ScanLeaks(body []byte) []Leak {
	var out []Leak
	for _, r := range leakRules {
		if m := r.re.Find(body); m != nil {
			out = append(out, Leak{Kind: r.kind, Sample: mask(string(m), r.secret)})
		}
	}
	return out
}

// RedactLeaks replaces secrets in body. Error pages are left alone.
func RedactLeaks(body []byte) []byte {
	for _, r := range leakRules {
		if r.secret {
			body = r.re.ReplaceAll(body, []byte("[redacted by rbproxy]"))
		}
	}
	return body
}

func mask(s string, secret bool) string {
	if len(s) > 80 {
		s = s[:80]
	}
	if !secret || len(s) <= 8 {
		return s
	}
	return s[:6] + "…" + "(" + itoa(len(s)) + " chars)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
