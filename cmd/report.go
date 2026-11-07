/*
Copyright © 2026 RBProxy
*/
package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"rbproxy/internal/events"
)

var reportOpts struct {
	log   string
	top   int
	since time.Duration
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Summarize the event log: who attacked, how, and what they fell for",
	Example: `  rbproxy report
  rbproxy report --log /var/log/rbproxy-events.jsonl --since 24h --top 20`,
	Args: cobra.NoArgs,
	RunE: runReport,
}

type actor struct {
	id         string
	events     int
	worst      string
	types      map[string]int
	categories map[string]int
	agents     map[string]bool
	last       time.Time
}

func runReport(_ *cobra.Command, _ []string) error {
	var (
		total      int
		first      time.Time
		last       time.Time
		byType     = map[string]int{}
		bySeverity = map[string]int{}
		cats       = map[string]int{}
		paths      = map[string]int{}
		actors     = map[string]*actor{}
		canaries   []events.Event
		creds      []events.Event
		learned    []events.Event
		leaks      []events.Event
		cutoff     time.Time
	)
	if reportOpts.since > 0 {
		cutoff = time.Now().Add(-reportOpts.since)
	}

	err := events.ReadFile(reportOpts.log, func(e events.Event) {
		if e.Time.Before(cutoff) || e.Type == "decoy_served" {
			return
		}
		total++
		if first.IsZero() || e.Time.Before(first) {
			first = e.Time
		}
		if e.Time.After(last) {
			last = e.Time
		}
		byType[e.Type]++
		bySeverity[e.Severity]++

		switch e.Type {
		case "attack":
			if list, ok := e.Details["categories"].([]any); ok {
				for _, c := range list {
					if s, ok := c.(string); ok {
						cats[s]++
					}
				}
			}
		case "canary_used":
			canaries = append(canaries, e)
		case "credentials_captured":
			creds = append(creds, e)
		case "honeypot_created":
			learned = append(learned, e)
		case "leak":
			leaks = append(leaks, e)
		}
		if e.Type == "attack" || e.Type == "honeypot_hit" {
			p := e.URI
			if i := strings.IndexByte(p, '?'); i >= 0 {
				p = p[:i]
			}
			paths[p]++
		}

		if e.Client == "" {
			return
		}
		a := actors[e.Client]
		if a == nil {
			a = &actor{id: e.Client, types: map[string]int{}, categories: map[string]int{}, agents: map[string]bool{}}
			actors[e.Client] = a
		}
		a.events++
		a.types[e.Type]++
		if events.Rank(e.Severity) > events.Rank(a.worst) {
			a.worst = e.Severity
		}
		if e.UserAgent != "" && len(a.agents) < 5 {
			a.agents[e.UserAgent] = true
		}
		if e.Time.After(a.last) {
			a.last = e.Time
		}
		if list, ok := e.Details["categories"].([]any); ok {
			for _, c := range list {
				if s, ok := c.(string); ok {
					a.categories[s]++
				}
			}
		}
	})
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no event log at %s (run `rbproxy host` first, or pass --log)", reportOpts.log)
		}
		return err
	}
	if total == 0 {
		fmt.Println("No events yet.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "RBProxy report — %d events from %s to %s\n\n", total, first.Local().Format("2006-01-02 15:04"), last.Local().Format("2006-01-02 15:04"))

	fmt.Fprintln(w, "SEVERITY\tEVENTS")
	for _, s := range []string{events.Critical, events.High, events.Medium, events.Low, events.Info} {
		if n := bySeverity[s]; n > 0 {
			fmt.Fprintf(w, "%s\t%d\n", s, n)
		}
	}

	fmt.Fprintln(w, "\nEVENT TYPE\tCOUNT")
	for _, kv := range sortedCounts(byType, 0) {
		fmt.Fprintf(w, "%s\t%d\n", kv.k, kv.n)
	}

	if len(cats) > 0 {
		fmt.Fprintln(w, "\nATTACK CATEGORY\tREQUESTS")
		for _, kv := range sortedCounts(cats, 0) {
			fmt.Fprintf(w, "%s\t%d\n", kv.k, kv.n)
		}
	}

	if len(paths) > 0 {
		fmt.Fprintln(w, "\nMOST TARGETED PATH\tHITS")
		for _, kv := range sortedCounts(paths, reportOpts.top) {
			fmt.Fprintf(w, "%s\t%d\n", kv.k, kv.n)
		}
	}

	list := make([]*actor, 0, len(actors))
	for _, a := range actors {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if ri, rj := events.Rank(list[i].worst), events.Rank(list[j].worst); ri != rj {
			return ri > rj
		}
		return list[i].events > list[j].events
	})
	if len(list) > reportOpts.top {
		list = list[:reportOpts.top]
	}
	fmt.Fprintln(w, "\nTOP CLIENTS\tWORST\tEVENTS\tATTACKS\tTRAPS\tCATEGORIES\tLAST SEEN\tUSER AGENT")
	for _, a := range list {
		ua := ""
		for k := range a.agents {
			ua = k
			break
		}
		if len(ua) > 50 {
			ua = ua[:50] + "…"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\n", a.id, a.worst, a.events, a.types["attack"], a.types["honeypot_hit"],
			strings.Join(keys(a.categories), ","), a.last.Local().Format("01-02 15:04"), ua)
	}

	if len(canaries) > 0 {
		fmt.Fprintln(w, "\nSTOLEN CANARIES USED\tSTOLEN BY\tCANARY\tWHEN")
		for _, e := range canaries {
			fmt.Fprintf(w, "%s\t%v\t%v\t%s\n", e.Client, e.Details["issued_to"], e.Details["canary_kind"], e.Time.Local().Format("01-02 15:04"))
		}
	}
	if len(creds) > 0 {
		fmt.Fprintln(w, "\nCAPTURED LOGINS\tDECOY\tUSERNAME\tPASSWORD")
		for _, e := range creds {
			fmt.Fprintf(w, "%s\t%v\t%v\t%v\n", e.Client, e.Details["decoy"], e.Details["username"], e.Details["password"])
		}
	}
	if len(learned) > 0 {
		fmt.Fprintln(w, "\nLEARNED TRAPS\tWHEN")
		for _, e := range learned {
			fmt.Fprintf(w, "%v\t%s\n", e.Details["path"], e.Time.Local().Format("01-02 15:04"))
		}
	}
	if len(leaks) > 0 {
		fmt.Fprintln(w, "\nBACKEND LEAKS\tURI\tMESSAGE")
		for _, e := range leaks {
			fmt.Fprintf(w, "%s\t%s\t%s\n", e.Time.Local().Format("01-02 15:04"), e.URI, e.Message)
		}
	}
	return nil
}

type kv struct {
	k string
	n int
}

func sortedCounts(m map[string]int, limit int) []kv {
	out := make([]kv, 0, len(m))
	for k, n := range m {
		out = append(out, kv{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVar(&reportOpts.log, "log", "rbproxy-events.jsonl", "event log to read")
	reportCmd.Flags().IntVar(&reportOpts.top, "top", 10, "rows in the top lists")
	reportCmd.Flags().DurationVar(&reportOpts.since, "since", 0, "only events newer than this (e.g. 24h)")
}
