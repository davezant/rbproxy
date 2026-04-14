package security

import (
	"regexp"
	"strings"
)

const (
	regexJAVASCRIPT = `(?i)(<script|script:|javascript:|on\w+\s*=)`
	regexPHP = `(?i)(<\?php|<\?|\?>|\$_(GET|POST|SESSION|SERVER|FILES|REQUEST))`
	regexJAVA = `(?i)(java\.lang|java\.util|System\.out|Runtime\.getRuntime|<%@|jsp:useBean)`
	regexSQL = `(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|TRUNCATE|CREATE|TABLE|FROM|WHERE|--|0x[0-9a-f]+|GROUP BY|ORDER BY|HAVING)`
	regexSHELL = `(?i)(\||&|;|` + "`" + `|\$\(|\.\.\/|\\|/etc/passwd|/bin/sh)`
	regexHTML = `(?i)(<[a-z/!]|&lt;|&gt;|&#x|expression\(|url\s*\(|base64|data:)`
    regexCRLF = `(?i)(\r|\n|%0d|%0a)`
    regexNOSQL = `(?i)(\$gt|\$ne|\$eq|\$where|\$regex|\$nil|\$exists)`
    regexTRAVERSAL = `(?i)(\.\.\/|\.\.\\|/etc/|/windows/system32|/proc/|/var/log/)`
	regexSSTI = `(?i)({{|%{|\||\[\[|\${|}})`
)

var (
	regexKEYS = []string{
		regexJAVASCRIPT,
		regexPHP,
		regexJAVA,
		regexSQL,
		regexSHELL,
		regexHTML,
		regexCRLF,
		regexNOSQL,
		regexTRAVERSAL,
		regexSSTI,
	}
)
func combineRegex() string{
	return strings.Join(regexKEYS, "|")
}

type Matcher struct {
	CompiledRegex *regexp.Regexp
}

func NewMatcher() Matcher {
	regex := combineRegex()
	matcher := regexp.MustCompile(regex)

	return Matcher{
		CompiledRegex: matcher,
	}
}

func (m *Matcher) CheckForInjection(text string) bool{
	return m.CompiledRegex.MatchString(text)
}
