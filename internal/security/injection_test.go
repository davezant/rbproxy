package security

import (
	"testing"
)

func TestCheckForInjection(t *testing.T) {
	matcher := NewMatcher()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// --- SQL Injection Tests ---
		{"SQL Classic", "SELECT * FROM users", true},
		{"SQL Union", "1 UNION SELECT 1,2,3", true},
		{"SQL Comment", "admin' --", true},
		{"SQL DROP", "'; DROP TABLE students; --", true},

		// --- XSS / Javascript Tests ---
		{"JS Script Tag", "<script>alert(1)</script>", true},
		{"JS Inline Event", "<img src=x onmouseover=alert(1)>", true},
		{"JS Protocol", "javascript:alert(1)", true},

		// --- Path Traversal Tests ---
		{"Traversal Linux", "../../etc/passwd", true},
		{"Traversal Windows", "..\\..\\windows\\system32", true},

		// --- NoSQL Tests ---
		{"NoSQL Greater Than", `{"username": {"$gt": ""}}`, true},
		{"NoSQL Not Equal", `{"id": {"$ne": null}}`, true},

		// --- Shell/Command Injection ---
		{"Shell Pipe", "cat file.txt | rm -rf /", true},
		{"Shell Backticks", "echo `whoami`", true},
		{"Shell Semicolon", "ls; pwd", true},

		// --- PHP/SSTI Tests ---
		{"PHP Open Tag", "<?php phpinfo(); ?>", true},
		{"SSTI Handlebars", "{{7*7}}", true},
		{"SSTI Template", "${res.class.loader}", true},

		// --- CRLF Injection ---
		{"CRLF Encoded", "example.com%0d%0aSet-Cookie:session=bad", true},

		// --- Clean Input (False Positive Checks) ---
		{"Clean String", "Hello world, this is a normal message.", false},
		{"Clean Number", "12345", false},
		{"Clean URL", "https://www.google.com/search?q=golang", false},
		{"Clean Path", "/home/user/documents/report.pdf", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.CheckForInjection(tt.input)
			if result != tt.expected {
				t.Errorf("CheckForInjection() for '%s' failed: expected %v, got %v", tt.name, tt.expected, result)
			}
		})
	}
}

func BenchmarkCheckForInjection(b *testing.B) {
	matcher := NewMatcher()
	longInput := "SELECT * FROM users WHERE id = 1 AND name = 'admin' OR '1'='1' UNION SELECT username, password FROM private_table --"
	
	for i := 0; i < b.N; i++ {
		matcher.CheckForInjection(longInput)
	}
}
