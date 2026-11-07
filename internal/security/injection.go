package security

import (
	"html"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Category groups detection rules by attack family.
type Category string

const (
	SQLInjection      Category = "sqli"
	CrossSiteScript   Category = "xss"
	CommandInjection  Category = "cmdi"
	PathTraversal     Category = "traversal"
	TemplateInjection Category = "ssti"
	NoSQLInjection    Category = "nosqli"
	HeaderInjection   Category = "crlf"
	CodeInjection     Category = "code"
	JNDIInjection     Category = "jndi"
	XXE               Category = "xxe"
	SSRF              Category = "ssrf"
)

// Location says where in a request a value came from. Some rules only make
// sense in some places: "localhost" in a Referer is a dev setup, not SSRF, and
// a "../" inside an HTML body is a relative link, not traversal.
type Location uint8

const (
	LocPath   Location = 1
	LocQuery  Location = 2
	LocHeader Location = 4
	LocBody   Location = 8
	LocAll             = LocPath | LocQuery | LocHeader | LocBody

	notBody = LocPath | LocQuery | LocHeader
)

// Rule is one regular expression with a weight. Weights are roughly:
// 3 = odd, 5 = suspicious, 7-8 = attack, 9-10 = unambiguous exploit payload.
type Rule struct {
	Name     string
	Category Category
	Score    int
	where    Location
	re       *regexp.Regexp
}

// Finding is a rule that matched a value of the request.
type Finding struct {
	Rule     string   `json:"rule"`
	Category Category `json:"category"`
	Score    int      `json:"score"`
	Field    string   `json:"field"`
	Sample   string   `json:"sample"`
}

func rule(cat Category, name string, score int, where Location, pattern string) Rule {
	return Rule{Name: name, Category: cat, Score: score, where: where, re: regexp.MustCompile(pattern)}
}

var defaultRules = []Rule{
	// SQL injection
	rule(SQLInjection, "union-select", 9, LocAll, `(?i)\bunion\b(?:\s|/\*.*?\*/|\+)+(?:all\s+|distinct\s+)?select\b`),
	rule(SQLInjection, "select-from", 4, LocAll, `(?i)\bselect\s+(?:\*|[\w.()]+(?:\s*,\s*[\w.()'"]+)*)\s+from\s+[\w.\x60"\[\]]+`),
	rule(SQLInjection, "quoted-tautology", 9, LocAll, `(?i)['")]\s*(?:or|and|\|\||&&)\s*['"(]?\s*[\w'"]+\s*['"]?\s*(?:=|<>|!=|>|<|\blike\b)\s*['"(]?\s*[\w'"]+`),
	rule(SQLInjection, "numeric-tautology", 7, LocAll, `(?i)\b(?:or|and)\s+\d+\s*=\s*\d+`),
	rule(SQLInjection, "quote-terminator", 5, LocAll, `['"]\s*(?:--|#|/\*|;)`),
	rule(SQLInjection, "stacked-query", 8, LocAll, `(?i);\s*(?:drop|delete|insert|update|alter|truncate|create|exec(?:ute)?|shutdown|declare)\s`),
	rule(SQLInjection, "time-based", 9, LocAll, `(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\s+'`),
	rule(SQLInjection, "schema-probe", 7, LocAll, `(?i)\b(?:information_schema|sysobjects|syscolumns|pg_catalog|sqlite_master|mysql\.user)\b`),
	rule(SQLInjection, "ddl", 7, LocAll, `(?i)\b(?:drop|truncate)\s+(?:table|database|schema)\b`),
	rule(SQLInjection, "file-access", 9, LocAll, `(?i)\bload_file\s*\(|\binto\s+(?:out|dump)file\b|\bxp_cmdshell\b`),
	rule(SQLInjection, "char-obfuscation", 4, LocAll, `(?i)\b(?:char|chr)\s*\(\s*\d+\s*(?:,\s*\d+\s*){2,}\)`),

	// Cross-site scripting
	rule(CrossSiteScript, "script-tag", 9, LocAll, `(?i)<\s*/?\s*script\b`),
	rule(CrossSiteScript, "js-uri", 8, LocAll, `(?i)\b(?:java|vb)script\s*:`),
	rule(CrossSiteScript, "event-handler", 8, LocAll, `(?i)<[^>]*\son[a-z]{3,}\s*=`),
	rule(CrossSiteScript, "dangerous-tag", 5, LocAll, `(?i)<\s*(?:iframe|frame|object|embed|svg|math|base|meta|link)\b`),
	rule(CrossSiteScript, "js-sink", 5, LocAll, `(?i)\b(?:alert|prompt|confirm)\(|\bdocument\s*\.\s*(?:cookie|domain|write)\b|\beval\s*\(|\bString\.fromCharCode\s*\(`),
	rule(CrossSiteScript, "html-data-uri", 6, LocAll, `(?i)\bdata\s*:\s*text/html|\bsrcdoc\s*=`),

	// Command injection
	rule(CommandInjection, "chained-command", 8, LocAll, `(?i)(?:;|\|\|?|&&|\x60|\$\()\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|bash|sh|zsh|python[23]?|perl|ruby|php|rm|chmod|chown|echo|ping|nslookup|dig|powershell|cmd|busybox|tftp|sleep)\b`),
	rule(CommandInjection, "subshell", 3, notBody, `\$\([^)]{1,100}\)|\x60[^\x60]{1,100}\x60`),
	rule(CommandInjection, "shell-binary", 8, LocAll, `(?i)/bin/(?:ba|z|da)?sh\b|\bcmd(?:\.exe)?\s+/c\b|\bpowershell(?:\.exe)?\s+-(?:e|enc|c|nop)\b`),
	rule(CommandInjection, "reverse-shell", 9, LocAll, `(?i)/dev/tcp/|\bnc\s+-[ec]\b|\bmkfifo\b|\bsh\s+-i\b`),

	// Path traversal
	rule(PathTraversal, "dot-dot-chain", 7, LocAll, `(?:\.\.[/\\]){2,}`),
	rule(PathTraversal, "dot-dot", 3, notBody, `\.\.[/\\]`),
	rule(PathTraversal, "sensitive-file", 8, LocAll, `(?i)/etc/(?:passwd|shadow|hosts|group|issue)\b|/proc/(?:self|\d+)/|[a-z]:\\windows\\|\\windows\\system32|/windows/system32|\b(?:boot|win)\.ini\b|\.htpasswd\b|/\.ssh/`),
	rule(PathTraversal, "null-byte", 5, notBody, `\x00`),

	// Server-side template injection
	rule(TemplateInjection, "arithmetic-probe", 7, LocAll, `\{\{\s*\d+\s*[*+\-/]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+\-/]\s*\d+\s*\}|<%=\s*\d+\s*[*+\-/]\s*\d+\s*%>|#\{\s*\d+\s*[*+\-/]\s*\d+\s*\}`),
	rule(TemplateInjection, "object-walk", 9, LocAll, `(?i)\{\{[^}]{0,200}(?:__class__|__globals__|__mro__|__subclasses__|__builtins__|config|self\.|request\.|lipsum|cycler|joiner)`),
	rule(TemplateInjection, "expression-language", 7, LocAll, `(?i)\$\{[^}]{0,200}(?:class|runtime|getclass|t\(|new\s|exec|forname)`),
	rule(TemplateInjection, "expression", 3, notBody, `\$\{[\w.]+\}`),
	rule(TemplateInjection, "erb-tag", 4, LocAll, `<%[=-]?[\s\S]{1,200}?%>`),

	// NoSQL injection
	rule(NoSQLInjection, "json-operator", 7, LocAll, `(?i)["']\$(?:gt|gte|lt|lte|ne|eq|in|nin|where|regex|exists|expr|or|and|not|nor|elemmatch)["']\s*:`),
	rule(NoSQLInjection, "query-operator", 7, LocAll, `(?i)\[\s*\$(?:gt|gte|lt|lte|ne|eq|in|nin|where|regex|exists|expr|or|and|not|nor)\s*\]`),

	// CRLF / header injection
	rule(HeaderInjection, "header-injection", 8, LocAll, `(?i)[\r\n]\s*(?:set-cookie|location|content-(?:type|length)|refresh|x-[\w-]+)\s*:`),
	rule(HeaderInjection, "encoded-newline", 4, notBody, `(?i)%0[da]`),

	// Code injection (PHP, Java, Python, OGNL, deserialization)
	rule(CodeInjection, "php-tag", 8, LocAll, `(?i)<\?(?:php|=)`),
	rule(CodeInjection, "php-function", 6, LocAll, `(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open|assert|base64_decode|phpinfo|file_put_contents)\s*\(`),
	rule(CodeInjection, "php-superglobal", 4, LocAll, `\$_(?:GET|POST|REQUEST|SERVER|COOKIE|FILES|SESSION|ENV)\b`),
	rule(CodeInjection, "stream-wrapper", 7, LocAll, `(?i)\b(?:php|phar|expect|zip|glob|file)://`),
	rule(CodeInjection, "java-runtime", 9, LocAll, `(?i)\bjava\.lang\.(?:runtime|processbuilder|system)\b|runtime\.getruntime\s*\(|\bclass\.module\.classloader\b|\bjava\.io\.file\b`),
	rule(CodeInjection, "python-exec", 7, LocAll, `\b__import__\s*\(|\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\s*\(`),
	rule(CodeInjection, "ognl", 9, LocAll, `%\{\s*[#(@]|\(#_memberAccess|@java\.lang`),
	rule(CodeInjection, "serialized-object", 7, LocAll, `rO0AB|\bO:\d+:"[\w\\]+":\d+:\{|aced0005`),

	// Log4Shell & friends
	rule(JNDIInjection, "jndi-lookup", 10, LocAll, `(?i)\$\{\s*(?:jndi|\$\{|lower:|upper:|env:|sys:|::-)`),

	// XML external entities
	rule(XXE, "external-entity", 9, LocAll, `(?i)<!ENTITY\s+[^>]*\b(?:SYSTEM|PUBLIC)\b|<!DOCTYPE[^>\[]*\[\s*<!ENTITY`),

	// Server-side request forgery
	rule(SSRF, "internal-url", 7, LocPath|LocQuery|LocBody, `(?i)\b(?:https?|gopher|dict|ftp|ldap)://(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|0x7f|169\.254\.169\.254|metadata\.google\.internal|\[::1?\]|100\.100\.100\.200)`),
}

// Detector scans request values against a rule set.
type Detector struct {
	rules []Rule
}

func NewDetector() *Detector {
	return &Detector{rules: defaultRules}
}

// Rules returns how many rules are loaded.
func (d *Detector) Rules() int { return len(d.rules) }

// Scan checks one value. field is a label for reports ("query", "header:User-Agent").
// The value is also checked in URL-decoded, HTML-unescaped and comment-stripped
// form, so double encoding and UNION/**/SELECT do not slip through.
func (d *Detector) Scan(loc Location, field, value string) []Finding {
	if value == "" {
		return nil
	}
	vs := variants(value, loc&LocQuery != 0)
	var out []Finding
	for i := range d.rules {
		r := &d.rules[i]
		if r.where != 0 && r.where&loc == 0 {
			continue
		}
		for _, v := range vs {
			if m := r.re.FindStringIndex(v); m != nil {
				out = append(out, Finding{Rule: r.Name, Category: r.Category, Score: r.Score, Field: field, Sample: sample(v, m)})
				break
			}
		}
	}
	return out
}

// Headers that never carry user-controlled payloads worth scanning, or that
// carry secrets we do not want copied into logs.
var skipHeaders = map[string]bool{
	"Accept": true, "Accept-Encoding": true, "Accept-Language": true, "Authorization": true,
	"Cache-Control": true, "Connection": true, "Content-Length": true, "Dnt": true,
	"If-Modified-Since": true, "If-None-Match": true, "Pragma": true, "Priority": true,
	"Te": true, "Upgrade-Insecure-Requests": true, "Proxy-Authorization": true,
}

// ScanRequest checks the path, query, headers, cookies and the first bytes of
// the body. body is whatever part of the body the caller managed to buffer.
func (d *Detector) ScanRequest(r *http.Request, body []byte) []Finding {
	var out []Finding
	out = append(out, d.Scan(LocPath, "path", r.URL.EscapedPath())...)
	if r.URL.RawQuery != "" {
		out = append(out, d.Scan(LocQuery, "query", r.URL.RawQuery)...)
	}
	for name, values := range r.Header {
		if skipHeaders[name] || strings.HasPrefix(name, "Sec-") {
			continue
		}
		if name == "Cookie" {
			for _, c := range r.Cookies() {
				out = append(out, d.Scan(LocHeader, "cookie:"+c.Name, c.Value)...)
			}
			continue
		}
		for _, v := range values {
			out = append(out, d.Scan(LocHeader, "header:"+name, v)...)
		}
	}
	if len(body) > 0 {
		out = append(out, d.scanBody(r.Header.Get("Content-Type"), body)...)
	}
	return dedupe(out)
}

func (d *Detector) scanBody(contentType string, body []byte) []Finding {
	mt := ""
	if contentType != "" {
		if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
			mt = parsed
		}
	}
	if !textualRequest(mt, contentType) {
		return nil
	}
	if mt == "application/x-www-form-urlencoded" {
		values, _ := url.ParseQuery(string(body))
		if len(values) > 0 {
			var out []Finding
			for k, vs := range values {
				out = append(out, d.Scan(LocBody, "body", k)...)
				for _, v := range vs {
					out = append(out, d.Scan(LocBody, "body:"+k, v)...)
				}
			}
			return out
		}
	}
	return d.Scan(LocBody, "body", string(body))
}

func textualRequest(mt, raw string) bool {
	if raw == "" {
		return true
	}
	if mt == "" {
		return true // unparsable content type: scan it, attackers love those
	}
	return strings.HasPrefix(mt, "text/") ||
		strings.Contains(mt, "json") ||
		strings.Contains(mt, "xml") ||
		strings.Contains(mt, "javascript") ||
		strings.Contains(mt, "graphql") ||
		mt == "application/x-www-form-urlencoded" ||
		mt == "multipart/form-data" // catches webshell uploads
}

// Score sums the strongest finding of each category, so ten variants of the
// same SQL injection count once. It also returns the strongest single finding.
func Score(fs []Finding) (total, peak int, top Category) {
	best := map[Category]int{}
	for _, f := range fs {
		if f.Score > best[f.Category] {
			best[f.Category] = f.Score
		}
		if f.Score > peak {
			peak, top = f.Score, f.Category
		}
	}
	for _, s := range best {
		total += s
	}
	return total, peak, top
}

// Categories lists the distinct categories in fs, sorted.
func Categories(fs []Finding) []string {
	seen := map[Category]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.Category] {
			seen[f.Category] = true
			out = append(out, string(f.Category))
		}
	}
	sort.Strings(out)
	return out
}

func dedupe(fs []Finding) []Finding {
	if len(fs) < 2 {
		return fs
	}
	type key struct{ rule, field string }
	seen := make(map[key]bool, len(fs))
	out := fs[:0]
	for _, f := range fs {
		k := key{f.Rule, f.Field}
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

var sqlComment = regexp.MustCompile(`/\*.*?\*/`)

func variants(s string, plusIsSpace bool) []string {
	out := []string{s}
	cur := s
	for i := 0; i < 3; i++ {
		next := percentDecode(cur, plusIsSpace)
		if next == cur {
			break
		}
		out = append(out, next)
		cur = next
	}
	if strings.Contains(cur, "&") {
		if h := html.UnescapeString(cur); h != cur {
			out = append(out, h)
			cur = h
		}
	}
	if strings.Contains(cur, "/*") {
		if c := sqlComment.ReplaceAllString(cur, " "); c != cur {
			out = append(out, c)
		}
	}
	return out
}

// percentDecode is a lenient %XX decoder: invalid escapes ("100%") are kept
// as-is instead of failing the whole string like url.QueryUnescape does.
func percentDecode(s string, plusIsSpace bool) string {
	if !strings.ContainsRune(s, '%') && !(plusIsSpace && strings.ContainsRune(s, '+')) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case c == '+' && plusIsSpace:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func sample(s string, m []int) string {
	start, end := m[0]-20, m[1]+20
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	out := s[start:end]
	if len(out) > 120 {
		out = out[:120]
	}
	return strings.ToValidUTF8(out, "")
}
