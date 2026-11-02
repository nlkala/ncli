package social

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestFromEventReactionAndDeletion(t *testing.T) {
	r := FromEvent(&nip01.Event{ID: "r", PubKey: "A", Kind: 7, Content: "👀",
		Tags: [][]string{{"e", "MSG", "", "bb"}, {"p", "bb"}, {"k", "14"}}}, "dm")
	if r.Type != "reaction" || r.Emoji != "👀" || r.Target != "msg" || r.ReplyTo != "" || r.Root != "" || r.From != "a" {
		t.Fatalf("reaction %+v", r)
	}
	d := FromEvent(&nip01.Event{ID: "d", PubKey: "a", Kind: 5,
		Tags: [][]string{{"e", "R1"}, {"k", "7"}, {"e", "r2"}, {"p", "bb"}}}, "dm")
	if d.Type != "delete" || !reflect.DeepEqual(d.Targets, []string{"r1", "r2"}) || d.ReplyTo != "" {
		t.Fatalf("deletion %+v", d)
	}
	if m := FromEvent(&nip01.Event{Kind: 14, Content: "x"}, "dm"); m.Type != "" || m.Targets != nil {
		t.Fatalf("message %+v", m)
	}
	// A message's JSON is what it was: none of the new fields.
	raw, _ := json.Marshal(FromEvent(&nip01.Event{ID: "m", Kind: 14, Content: "x"}, "dm"))
	for _, k := range []string{"type", "emoji", "target", "targets", "reactions"} {
		if strings.Contains(string(raw), `"`+k+`"`) {
			t.Fatalf("message JSON has %s: %s", k, raw)
		}
	}
	raw, _ = json.Marshal(r)
	if !strings.Contains(string(raw), `"type":"reaction","emoji":"👀","target":"msg"`) {
		t.Fatalf("reaction JSON %s", raw)
	}
	raw, _ = json.Marshal(d)
	if !strings.Contains(string(raw), `"type":"delete","targets":["r1","r2"]`) {
		t.Fatalf("deletion JSON %s", raw)
	}
}

func TestFold(t *testing.T) {
	msg := func(id, from string, at uint64) Message {
		return Message{ID: id, From: from, CreatedAt: at, Kind: 14, Content: id, Mentions: []string{}}
	}
	react := func(id, from, target, emoji string, at uint64) Message {
		return Message{ID: id, From: from, CreatedAt: at, Kind: 7, Type: "reaction", Target: target, Emoji: emoji}
	}
	del := func(id, from string, at uint64, targets ...string) Message {
		return Message{ID: id, From: from, CreatedAt: at, Kind: 5, Type: "delete", Targets: targets}
	}
	ms := []Message{
		msg("m1", "them", 1),
		msg("m2", "me", 2),
		react("eyes", "me", "m1", "👀", 3),
		react("talk", "me", "m1", "💬", 4),
		react("their", "them", "m2", "+", 5),
		react("orphan", "me", "not-read", "👀", 6),
		msg("m3", "them", 7),
		react("on-m3", "me", "m3", "👀", 8),
		del("d-mine", "me", 9, "eyes"),
		// Another author's deletion of my reaction, or of my message, counts
		// for nothing.
		del("d-foreign", "them", 10, "talk", "m2"),
		// They delete their own message: it goes, with my reaction.
		del("d-m3", "them", 11, "m3"),
	}
	out := Fold(ms)
	var ids []string
	for _, m := range out {
		ids = append(ids, m.ID)
	}
	if !reflect.DeepEqual(ids, []string{"m1", "m2", "orphan"}) {
		t.Fatalf("folded %v", ids)
	}
	if got := out[0].Reactions; len(got) != 1 || got[0].ID != "talk" || got[0].Emoji != "💬" || got[0].From != "me" || got[0].CreatedAt != 4 {
		t.Fatalf("m1 reactions %+v", got)
	}
	if got := out[1].Reactions; len(got) != 1 || got[0].ID != "their" {
		t.Fatalf("m2 reactions %+v", got)
	}
	if out[2].Type != "reaction" || out[2].Target != "not-read" {
		t.Fatalf("orphan %+v", out[2])
	}
	if ms[0].Reactions != nil {
		t.Fatal("Fold changed its input")
	}
	if got := Fold(nil); got == nil || len(got) != 0 {
		t.Fatalf("empty fold %v", got)
	}
}

func TestFoldReactionsOldestFirst(t *testing.T) {
	out := Fold([]Message{
		{ID: "m", From: "o", CreatedAt: 1},
		{ID: "late", From: "me", Type: "reaction", Target: "m", Emoji: "💬", CreatedAt: 9},
		{ID: "early", From: "me", Type: "reaction", Target: "m", Emoji: "👀", CreatedAt: 2},
	})
	if len(out) != 1 || len(out[0].Reactions) != 2 || out[0].Reactions[0].ID != "early" {
		t.Fatalf("folded %+v", out)
	}
}

func TestPrintReactionAndDeletion(t *testing.T) {
	var b strings.Builder
	PrintMessage(&b, Message{ID: "r", From: "a", Type: "reaction", Emoji: "👀", Target: "0123456789abcdef"})
	PrintMessage(&b, Message{ID: "d", From: "a", Type: "delete", Targets: []string{"0123456789abcdef", "ff"}})
	PrintMessage(&b, Message{ID: "m", From: "a", Content: "hi", Reactions: []Reaction{{Emoji: "👀"}, {Emoji: "💬"}, {Emoji: "👀"}}})
	out := b.String()
	for _, want := range []string{"  👀 on 0123456789ab\n", "  removed 0123456789ab, ff\n", "  hi\n  reactions: 👀 2, 💬 1\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}
