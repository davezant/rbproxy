package security

import (
	"fmt"
	"html"
)

// BlockPage renders the page shown to blocked or throttled clients. It is
// deliberately plain: no product name and no rule names, nothing that helps an
// attacker fingerprint the proxy or tune a payload around it.
func BlockPage(status int, title, ref string) []byte {
	t := html.EscapeString(title)
	return []byte(fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>%d %s</title></head>
<body style="font-family:sans-serif;margin:4em auto;max-width:36em;color:#222">
<h1>%d %s</h1>
<p>Your request could not be processed.</p>
<p style="color:#777;font-size:.9em">Reference: %s</p>
</body></html>
`, status, t, status, t, html.EscapeString(ref)))
}
