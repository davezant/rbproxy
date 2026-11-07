package terminal

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const Version = "0.2.0"

var color = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

const (
	reset   = "\033[0m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	boldRed = "\033[1;31m"
)

func paint(code, s string) string {
	if !color {
		return s
	}
	return code + s + reset
}

func line(level, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s %s %s\n", paint(dim, time.Now().Format("15:04:05")), level, fmt.Sprintf(format, args...))
}

func Info(format string, args ...any)  { line(paint(cyan, "[rbproxy]"), format, args...) }
func Warn(format string, args ...any)  { line(paint(yellow, "[rbproxy] WARN"), format, args...) }
func Error(format string, args ...any) { line(paint(red, "[rbproxy] ERR"), format, args...) }

// Severity renders a fixed-width, colored severity label.
func Severity(sev string) string {
	label := fmt.Sprintf("%-8s", strings.ToUpper(sev))
	switch sev {
	case "critical":
		return paint(boldRed, label)
	case "high":
		return paint(red, label)
	case "medium":
		return paint(yellow, label)
	case "low":
		return paint(green, label)
	}
	return paint(dim, label)
}

// Highlight colors identifiers such as client addresses.
func Highlight(s string) string { return paint(magenta, s) }

// Dim de-emphasizes secondary text.
func Dim(s string) string { return paint(dim, s) }
