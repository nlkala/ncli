package social

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip10"
)

// Message is one DM or group message as dm read, groups read and groups
// feed print it, so a caller handles both with one parser. Pubkeys are hex.
type Message struct {
	ID        string   `json:"id"`
	Channel   string   `json:"channel"` // "dm" or "group"
	Group     string   `json:"group,omitempty"`
	Wrap      string   `json:"wrap,omitempty"` // the gift wrap a DM came in
	From      string   `json:"from"`
	CreatedAt uint64   `json:"created_at"`
	Kind      int      `json:"kind"`
	Subject   string   `json:"subject,omitempty"`
	ReplyTo   string   `json:"reply_to,omitempty"`
	Root      string   `json:"root,omitempty"`
	Mentions  []string `json:"mentions"`
	Content   string   `json:"content"`
	// Type is "reaction" (a NIP-25 kind 7) or "delete" (a NIP-09 kind 5);
	// empty for a message.
	Type    string   `json:"type,omitempty"`
	Emoji   string   `json:"emoji,omitempty"`   // a reaction's content
	Target  string   `json:"target,omitempty"`  // the event a reaction is to
	Targets []string `json:"targets,omitempty"` // the events a deletion names
	// Reactions are the reactions to this message still standing, when a
	// reader folds them in (dm read --fold).
	Reactions []Reaction `json:"reactions,omitempty"`
}

// Reaction is one reaction folded into the message it is to.
type Reaction struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	Emoji     string `json:"emoji"`
	CreatedAt uint64 `json:"created_at"`
}

// Kinds FromEvent gives a meaning beyond a message.
const (
	KindDeletion = 5 // NIP-09
	KindReaction = 7 // NIP-25
)

// FromEvent reads ev's threading (NIP-10 markers, else NIP-17's unmarked
// "e"), subject and "p" tags into a Message.
func FromEvent(ev *nip01.Event, channel string) Message {
	m := Message{
		ID: ev.ID, Channel: channel, From: strings.ToLower(ev.PubKey),
		CreatedAt: ev.CreatedAt, Kind: ev.Kind, Content: ev.Content, Mentions: []string{},
	}
	seen := map[string]bool{}
	hasE := false
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "p":
			pk := strings.ToLower(t[1])
			if !seen[pk] {
				seen[pk] = true
				m.Mentions = append(m.Mentions, pk)
			}
		case "subject":
			m.Subject = t[1]
		case "h":
			m.Group = t[1]
		case "q":
			// A group chat reply quotes its parent (NIP-C7).
			if channel == "group" && m.ReplyTo == "" {
				m.ReplyTo = t[1]
			}
		case "e":
			hasE = true
			marker := ""
			if len(t) >= 4 {
				marker = t[3]
			}
			switch marker {
			case "reply":
				m.ReplyTo = t[1]
			case "root":
				m.Root = t[1]
			case "mention":
			default:
				// No marker (NIP-17), or NIP-22's parent "e", whose 4th
				// field is the parent's author, not a marker.
				if m.ReplyTo == "" {
					m.ReplyTo = t[1]
				}
			}
		case "E":
			// NIP-22's root.
			m.Root = t[1]
		}
	}
	if hasE && m.ReplyTo == "" && m.Root != "" {
		// A direct reply to the root names only the root.
		m.ReplyTo = m.Root
	}
	if m.Root == "" && m.ReplyTo != "" && ev.Kind == 1 {
		if root, _, _ := nip10.Root(ev); root != ev.ID {
			m.Root = root
		}
	}
	switch ev.Kind {
	case KindReaction:
		// NIP-25: the last "e" is the event reacted to; it is no reply.
		m.Type, m.Emoji, m.ReplyTo, m.Root = "reaction", ev.Content, "", ""
		for _, t := range ev.Tags {
			if len(t) >= 2 && t[0] == "e" {
				m.Target = strings.ToLower(t[1])
			}
		}
	case KindDeletion:
		// NIP-09: every "e" is an event its author asks to drop.
		m.Type, m.ReplyTo, m.Root, m.Targets = "delete", "", "", []string{}
		for _, t := range ev.Tags {
			if len(t) >= 2 && t[0] == "e" {
				m.Targets = append(m.Targets, strings.ToLower(t[1]))
			}
		}
	}
	return m
}

// SortMessages orders messages oldest first, ties by id.
func SortMessages(ms []Message) {
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].CreatedAt != ms[j].CreatedAt {
			return ms[i].CreatedAt < ms[j].CreatedAt
		}
		return ms[i].ID < ms[j].ID
	})
}

// PrintMessage writes m as text: a header line, then the content indented.
func PrintMessage(w io.Writer, m Message) {
	at := time.Unix(int64(m.CreatedAt), 0).UTC().Format("2006-01-02 15:04")
	head := fmt.Sprintf("%s  %s", at, Npub(m.From))
	if m.Group != "" {
		head += "  in " + m.Group
	}
	if m.Subject != "" {
		head += "  [" + m.Subject + "]"
	}
	if m.ReplyTo != "" {
		head += "  ↩ " + short(m.ReplyTo)
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", head, short(m.ID))
	switch m.Type {
	case "reaction":
		_, _ = fmt.Fprintf(w, "  %s on %s\n", m.Emoji, short(m.Target))
		return
	case "delete":
		ids := make([]string, len(m.Targets))
		for i, id := range m.Targets {
			ids[i] = short(id)
		}
		_, _ = fmt.Fprintf(w, "  removed %s\n", strings.Join(ids, ", "))
		return
	}
	for _, line := range strings.Split(m.Content, "\n") {
		_, _ = fmt.Fprintf(w, "  %s\n", line)
	}
	if len(m.Reactions) > 0 {
		// "reactions: 👀 2, 💬 1", in the order each emoji first came.
		var emojis []string
		n := map[string]int{}
		for _, r := range m.Reactions {
			if n[r.Emoji] == 0 {
				emojis = append(emojis, r.Emoji)
			}
			n[r.Emoji]++
		}
		for i, e := range emojis {
			emojis[i] = fmt.Sprintf("%s %d", e, n[e])
		}
		_, _ = fmt.Fprintf(w, "  reactions: %s\n", strings.Join(emojis, ", "))
	}
}

// Fold applies deletions and folds reactions into the messages they are
// to. A deletion counts only for events by its own author (NIP-09): it
// removes them, and is itself dropped. A reaction to a message in ms joins
// that message's Reactions, oldest first, and goes with it if it was
// deleted; one to an event not in ms stays in place as a reaction. Order
// is kept.
func Fold(ms []Message) []Message {
	byID := map[string]Message{}
	for _, m := range ms {
		byID[m.ID] = m
	}
	deleted := map[string]bool{}
	for _, m := range ms {
		if m.Type != "delete" {
			continue
		}
		for _, id := range m.Targets {
			if t, ok := byID[id]; ok && t.From == m.From && t.ID != m.ID {
				deleted[id] = true
			}
		}
	}
	// The reactions each message left standing gets.
	reactions := map[string][]Reaction{}
	for _, m := range ms {
		if m.Type == "reaction" && !deleted[m.ID] {
			if t, ok := byID[m.Target]; ok && t.Type == "" && !deleted[t.ID] {
				reactions[t.ID] = append(reactions[t.ID], Reaction{ID: m.ID, From: m.From, Emoji: m.Emoji, CreatedAt: m.CreatedAt})
			}
		}
	}
	out := []Message{}
	for _, m := range ms {
		switch {
		case deleted[m.ID], m.Type == "delete":
			continue
		case m.Type == "reaction":
			if t, ok := byID[m.Target]; ok && t.Type == "" {
				continue // folded into its message, or gone with it
			}
		case m.Type == "":
			m.Reactions = reactions[m.ID]
			sort.SliceStable(m.Reactions, func(i, j int) bool { return m.Reactions[i].CreatedAt < m.Reactions[j].CreatedAt })
		}
		out = append(out, m)
	}
	return out
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
