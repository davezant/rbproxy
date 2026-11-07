// Package events records what the proxy saw: one JSON object per line in a
// log file (easy to grep, ship to a SIEM or feed to `rbproxy report`), plus an
// in-memory ring buffer for the admin API.
package events

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

const (
	Info     = "info"
	Low      = "low"
	Medium   = "medium"
	High     = "high"
	Critical = "critical"
)

// Rank orders severities, for filtering.
func Rank(sev string) int {
	switch sev {
	case Low:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	case Critical:
		return 4
	}
	return 0
}

type Event struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Type      string         `json:"type"`
	Severity  string         `json:"severity"`
	Client    string         `json:"client,omitempty"`
	Method    string         `json:"method,omitempty"`
	Host      string         `json:"host,omitempty"`
	URI       string         `json:"uri,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
	Message   string         `json:"message,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type Sink struct {
	mu      sync.Mutex
	file    io.WriteCloser
	enc     *json.Encoder
	ring    []Event
	next    int
	full    bool
	counts  map[string]int
	OnEvent func(Event) // called for every event, outside the lock
}

// Open creates a sink. An empty path keeps events in memory only.
func Open(path string, ringSize int) (*Sink, error) {
	if ringSize <= 0 {
		ringSize = 1000
	}
	s := &Sink{ring: make([]Event, ringSize), counts: map[string]int{}}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		s.file = f
		s.enc = json.NewEncoder(f)
		s.enc.SetEscapeHTML(false)
	}
	return s, nil
}

func (s *Sink) Emit(e Event) {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = Info
	}
	s.mu.Lock()
	if s.enc != nil {
		_ = s.enc.Encode(e)
	}
	s.ring[s.next] = e
	s.next = (s.next + 1) % len(s.ring)
	if s.next == 0 {
		s.full = true
	}
	s.counts[e.Type]++
	hook := s.OnEvent
	s.mu.Unlock()
	if hook != nil {
		hook(e)
	}
}

// Recent returns up to n events, newest first, at or above minSeverity.
func (s *Sink) Recent(n int, minSeverity string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	size := s.next
	if s.full {
		size = len(s.ring)
	}
	min := Rank(minSeverity)
	out := make([]Event, 0, min2(n, size))
	for i := 0; i < size && len(out) < n; i++ {
		e := s.ring[(s.next-1-i+len(s.ring))%len(s.ring)]
		if Rank(e.Severity) >= min {
			out = append(out, e)
		}
	}
	return out
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Counts returns how many events of each type were emitted since start.
func (s *Sink) Counts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counts))
	for k, v := range s.counts {
		out[k] = v
	}
	return out
}

func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		err := s.file.Close()
		s.file, s.enc = nil, nil
		return err
	}
	return nil
}

// ReadFile parses an event log written by a Sink. Malformed lines are skipped.
func ReadFile(path string, fn func(Event)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			fn(e)
		}
	}
	return sc.Err()
}
