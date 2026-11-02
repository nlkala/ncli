package form

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ohstr/ncli/cli/social"
	"github.com/ohstr/nmilat/nippf"
	"github.com/spf13/cobra"
)

// printJSON writes v as indented JSON to the command's output.
func printJSON(cmd *cobra.Command, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), `{"error":"failed to encode JSON output"}`)
		return
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(b))
}

func jsonMode(cmd *cobra.Command) bool {
	j, _ := cmd.Flags().GetBool("json")
	return j
}

func when(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04Z")
}

func short(hex string) string {
	n := social.Npub(hex)
	if len(n) > 16 {
		return n[:12] + "…" + n[len(n)-4:]
	}
	return n
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// stateLine: the state, with the end and where the form lives.
func stateLine(v *View) string {
	s := string(v.State)
	f := v.Form
	if f.EndsAt > 0 && v.State == nippf.StateOpen {
		s += ", ends " + when(f.EndsAt)
	}
	switch v.Where {
	case "group":
		s += ", in group " + f.Group
	default:
		s += ", " + v.Where
	}
	if f.Priority {
		s += ", priority high"
	}
	if f.ReadOnly {
		s += ", read-only (a question type this client doesn't answer)"
	}
	return s
}

// listLine is one form in form list.
func listLine(v *View) string {
	f := v.Form
	you := ""
	switch {
	case v.Role == "author":
		you = "yours"
	case v.Mine != nil:
		you = "you answered"
	case v.CanRespond:
		you = "to answer"
	case v.Role == "observer":
		you = "observer"
	}
	answered := fmt.Sprintf("%d answered", v.Tally.Responses)
	if n := len(f.Responders()); n > 0 {
		answered = fmt.Sprintf("%d/%d answered", v.Tally.Responses, n)
	}
	parts := []string{stateLine(v), "by " + short(f.Author), answered}
	if you != "" {
		parts = append(parts, you)
	}
	return fmt.Sprintf("%s  %s  (%s)", shortID(f.ID), f.Title, strings.Join(parts, "; "))
}

// writeView prints one form in full: what it asks, the tally and notes, the
// answers, who hasn't answered, your response and the result.
func writeView(w io.Writer, v *View) {
	f := v.Form
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("form %s by %s, %s (%s)\n", f.ID, social.Npub(f.Author), when(f.CreatedAt), stateLine(v))
	p("\n%s\n", f.Title)
	if f.Context != "" {
		p("\n%s\n", f.Context)
	}
	for _, e := range f.Events {
		p("about: event %s\n", e)
	}
	for _, a := range f.Addrs {
		p("about: %s\n", a)
	}
	if rs := f.Responders(); len(rs) > 0 {
		names := make([]string, 0, len(rs))
		for _, r := range rs {
			names = append(names, social.Npub(r))
		}
		p("responders: %s\n", strings.Join(names, ", "))
	}
	if os := f.Observers(); len(os) > 0 {
		names := make([]string, 0, len(os))
		for _, o := range os {
			names = append(names, social.Npub(o))
		}
		p("observers: %s\n", strings.Join(names, ", "))
	}
	if f.Quorum > 0 {
		met := "not met"
		if v.Tally.QuorumMet {
			met = "met"
		}
		p("quorum: %d (%s)\n", f.Quorum, met)
	}
	if f.Expiration > 0 {
		p("expires: %s\n", when(f.Expiration))
	}
	for _, q := range f.Questions {
		qt := tallyOf(v.Tally, q.Index)
		p("\n[%d] %s (%s", q.Index, q.Text, q.Type)
		if q.Optional {
			p(", optional")
		}
		if q.Min != "" {
			p(", min %s", q.Min)
		}
		if q.Max != "" {
			p(", max %s", q.Max)
		}
		p(")\n")
		if q.Why != "" {
			p("    why: %s\n", q.Why)
		}
		for _, o := range q.Options {
			p("    - %s: %s", o.ID, o.Label)
			if o.Rec {
				p("  [recommended]")
			}
			if o.NoteRequired {
				p("  [note required]")
			}
			if qt != nil && qt.Counts != nil {
				p("  — %d", qt.Counts[o.ID])
			}
			p("\n")
			if qt != nil {
				for _, n := range qt.Notes[o.ID] {
					p("        %s: %s\n", short(n.PubKey), n.Text)
				}
			}
		}
		if len(q.Defaults) > 0 {
			p("    default: %s\n", strings.Join(q.Defaults, ", "))
		}
		if qt != nil {
			for _, a := range qt.Answers {
				p("    %s: %s", short(a.PubKey), a.Value)
				if a.Note != "" {
					p(" (%s)", a.Note)
				}
				p("\n")
			}
		}
	}
	p("\n%d response(s)", v.Tally.Responses)
	if len(v.Waiting) > 0 {
		names := make([]string, 0, len(v.Waiting))
		for _, k := range v.Waiting {
			names = append(names, social.Npub(k))
		}
		p("; not answered: %s", strings.Join(names, ", "))
	}
	p("\n")
	if v.Mine != nil {
		p("your response (%s): %s\n", when(v.Mine.CreatedAt), describe(v.Mine.Choices, v.Mine.Answers))
	}
	if r := v.Result; r != nil {
		p("result: %s at %s", r.Status, when(r.CreatedAt))
		if d := describe(r.Choices, r.Answers); d != "" {
			p(" — %s", d)
		}
		p("\n")
		if r.Content != "" {
			p("    %s\n", r.Content)
		}
	}
	switch {
	case v.CanRespond && v.Role != "author":
		p("answer: ncli form respond %s …\n", shortID(f.ID))
	case v.Role == "author" && v.Result == nil:
		p("close: ncli form result %s --status decided|default|cancelled …\n", shortID(f.ID))
	}
}

func tallyOf(t *nippf.Tally, index int) *nippf.QuestionTally {
	if t == nil {
		return nil
	}
	for i := range t.Questions {
		if t.Questions[i].Index == index {
			return &t.Questions[i]
		}
	}
	return nil
}

// describe: choices and answers on one line.
func describe(cs []nippf.Choice, as []nippf.Answer) string {
	var parts []string
	for _, c := range cs {
		s := c.Option
		if c.Note != "" {
			s += fmt.Sprintf(" (%s)", c.Note)
		}
		parts = append(parts, s)
	}
	for _, a := range as {
		s := fmt.Sprintf("[%d]=%s", a.Question, a.Value)
		if a.Note != "" {
			s += fmt.Sprintf(" (%s)", a.Note)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}
