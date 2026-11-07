package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"rbproxy/internal/events"
	"rbproxy/pkg/terminal"
)

// AdminHandler serves a small JSON API:
//
//	GET  /api/stats                     counters and uptime
//	GET  /api/clients?min_score=5&limit=100
//	GET  /api/clients/{id}
//	POST /api/clients/{id}/block?minutes=60   (minutes=0 blacklists)
//	POST /api/clients/{id}/unblock
//	GET  /api/events?n=100&min_severity=medium
//	GET  /api/traps
//
// IPv6 clients are identified by their /64, so {id} looks like
// "2001:db8::/64"; URL-encode the slash as %2F.
func (p *Proxy) AdminHandler(token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/stats", func(w http.ResponseWriter, r *http.Request) {
		traps := 0
		if p.honey != nil {
			traps = len(p.honey.Traps())
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version":         terminal.Version,
			"mode":            p.opts.Mode,
			"uptime_seconds":  int(time.Since(p.started).Seconds()),
			"tracked_clients": p.tracker.Len(),
			"traps":           traps,
			"events":          p.events.Counts(),
		})
	})

	mux.HandleFunc("GET /api/clients", func(w http.ResponseWriter, r *http.Request) {
		min, _ := strconv.ParseFloat(r.URL.Query().Get("min_score"), 64)
		limit := atoiDefault(r.URL.Query().Get("limit"), 100)
		writeJSON(w, http.StatusOK, p.tracker.List(min, limit))
	})

	mux.HandleFunc("GET /api/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, ok := p.tracker.Get(r.PathValue("id"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown client"})
			return
		}
		writeJSON(w, http.StatusOK, v)
	})

	mux.HandleFunc("POST /api/clients/{id}/block", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		minutes := atoiDefault(r.URL.Query().Get("minutes"), 60)
		p.tracker.Block(id, time.Duration(minutes)*time.Minute)
		p.events.Emit(events.Event{Type: "manual_block", Severity: events.Medium, Client: id, Message: "blocked from admin API",
			Details: map[string]any{"minutes": minutes}})
		writeJSON(w, http.StatusOK, map[string]any{"blocked": id, "minutes": minutes})
	})

	mux.HandleFunc("POST /api/clients/{id}/unblock", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ok := p.tracker.Unblock(id)
		if ok {
			p.events.Emit(events.Event{Type: "manual_unblock", Severity: events.Low, Client: id, Message: "unblocked from admin API"})
		}
		writeJSON(w, http.StatusOK, map[string]any{"unblocked": ok})
	})

	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		n := atoiDefault(r.URL.Query().Get("n"), 100)
		writeJSON(w, http.StatusOK, p.events.Recent(n, r.URL.Query().Get("min_severity")))
	})

	mux.HandleFunc("GET /api/traps", func(w http.ResponseWriter, r *http.Request) {
		if p.honey == nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		writeJSON(w, http.StatusOK, p.honey.Traps())
	})

	if token == "" {
		return mux
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or wrong bearer token"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}
