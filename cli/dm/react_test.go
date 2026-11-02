package dm

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ohstr/ncli/cli/social"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
)

const (
	alicePriv = "0000000000000000000000000000000000000000000000000000000000000001"
	bobPriv   = "0000000000000000000000000000000000000000000000000000000000000002"
	malPriv   = "0000000000000000000000000000000000000000000000000000000000000003"
	msgID     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func key(t *testing.T, priv string) *nip46.LocalKey {
	t.Helper()
	k, err := nip46.NewLocalKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewReactionRumor(t *testing.T) {
	ev := newReactionRumor(msgID, "bob", 14, "👀", "bob")
	if ev.Kind != 7 || ev.Content != "👀" {
		t.Fatalf("kind %d content %q", ev.Kind, ev.Content)
	}
	want := [][]string{{"e", msgID, "", "bob"}, {"p", "bob"}, {"k", "14"}}
	if !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("tags %v", ev.Tags)
	}
	// Reacting to your own message: "p" names the author and the recipient;
	// no kind given, no "k".
	ev = newReactionRumor(msgID, "alice", 0, "💬", "bob")
	want = [][]string{{"e", msgID, "", "alice"}, {"p", "alice"}, {"p", "bob"}}
	if !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("own message tags %v", ev.Tags)
	}
}

func TestNewUnreactRumor(t *testing.T) {
	ev, err := newUnreactRumor("alice", []string{"r1", "r2"}, "bob")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"e", "r1"}, {"k", "7"}, {"e", "r2"}, {"p", "bob"}}
	if ev.Kind != 5 || ev.Content != "" || !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("kind %d content %q tags %v", ev.Kind, ev.Content, ev.Tags)
	}
}

// open unwraps w as key, from senders only, into a message.
func open(t *testing.T, k *nip46.LocalKey, w *nip01.Event, from ...string) social.Message {
	t.Helper()
	o, out, err := openWrap(context.Background(), k, w, from)
	if err != nil || out != opened {
		t.Fatalf("open: %v %v", out, err)
	}
	return message(o)
}

func TestReactionWrapRoundTrip(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	cmd := newReactCommand()
	cmd.SetContext(context.Background())

	// alice reacts 👀 to bob's message.
	rumor := newReactionRumor(msgID, bob.PubKey(), 14, "👀", bob.PubKey())
	rumor.CreatedAt = 100
	wraps, err := wrapForBoth(cmd, alice, rumor, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(wraps) != 2 || wraps[0].Kind != 1059 || rumor.ID == "" || rumor.PubKey != alice.PubKey() {
		t.Fatalf("wraps %d, rumor %+v", len(wraps), rumor)
	}
	for _, w := range wraps {
		if strings.Contains(w.Content, "👀") || strings.Contains(w.Content, msgID) {
			t.Fatal("wrap carries the plaintext")
		}
	}
	// bob reads it from his wrap.
	got := open(t, bob, wraps[0], alice.PubKey())
	if got.Type != "reaction" || got.Emoji != "👀" || got.Target != msgID || got.From != alice.PubKey() ||
		got.ID != rumor.ID || got.Kind != 7 || got.ReplyTo != "" {
		t.Fatalf("bob read %+v", got)
	}
	// alice's copy is the same rumor.
	self := open(t, alice, wraps[1], alice.PubKey())
	if self.ID != rumor.ID || self.Target != msgID {
		t.Fatalf("self copy %+v", self)
	}
	// bob can't open alice's copy.
	if _, out, _ := openWrap(context.Background(), bob, wraps[1], nil); out != invalid {
		t.Fatalf("bob opened alice's copy: %v", out)
	}

	// alice finds her reaction in her copies and removes it.
	ids := ownReactions([]social.Message{self}, alice.PubKey(), bob.PubKey(), msgID, "👀")
	if !reflect.DeepEqual(ids, []string{rumor.ID}) {
		t.Fatalf("own reactions %v", ids)
	}
	del, err := newUnreactRumor(alice.PubKey(), ids, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	del.CreatedAt = 200
	dwraps, err := wrapForBoth(newUnreactCommand(), alice, del, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	gotDel := open(t, bob, dwraps[0], alice.PubKey())
	if gotDel.Type != "delete" || !reflect.DeepEqual(gotDel.Targets, []string{rumor.ID}) || gotDel.From != alice.PubKey() {
		t.Fatalf("bob read the deletion %+v", gotDel)
	}
	// Folded, bob's message has no reaction left; with the deletion's copy,
	// alice has nothing left to remove.
	msg := social.Message{ID: msgID, From: bob.PubKey(), Kind: 14, Content: "hi", Mentions: []string{alice.PubKey()}}
	if out := social.Fold([]social.Message{msg, got, gotDel}); len(out) != 1 || len(out[0].Reactions) != 0 {
		t.Fatalf("folded %+v", out)
	}
	if out := social.Fold([]social.Message{msg, got}); len(out) != 1 || len(out[0].Reactions) != 1 || out[0].Reactions[0].ID != rumor.ID {
		t.Fatalf("folded without the deletion %+v", out)
	}
	selfDel := open(t, alice, dwraps[1], alice.PubKey())
	if ids := ownReactions([]social.Message{self, selfDel}, alice.PubKey(), bob.PubKey(), msgID, "👀"); len(ids) != 0 {
		t.Fatalf("already removed, still found %v", ids)
	}
}

func TestReactionNoSelfCopy(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	cmd := newReactCommand()
	cmd.SetContext(context.Background())
	if err := cmd.Flags().Set("no-self-copy", "true"); err != nil {
		t.Fatal(err)
	}
	wraps, err := wrapForBoth(cmd, alice, newReactionRumor(msgID, bob.PubKey(), 0, "+", bob.PubKey()), bob.PubKey())
	if err != nil || len(wraps) != 1 {
		t.Fatalf("%d wraps, %v", len(wraps), err)
	}
}

func TestOwnReactions(t *testing.T) {
	alice, bob, mal := key(t, alicePriv).PubKey(), key(t, bobPriv).PubKey(), key(t, malPriv).PubKey()
	r := func(id, from, target, emoji string, at uint64, p ...string) social.Message {
		return social.Message{ID: id, From: from, Type: "reaction", Target: target, Emoji: emoji, CreatedAt: at, Mentions: p}
	}
	ms := []social.Message{
		r("r3", alice, msgID, "👀", 3, bob),
		r("r1", alice, msgID, "👀", 1, bob),
		r("gone", alice, msgID, "👀", 2, bob),
		r("other-emoji", alice, msgID, "💬", 1, bob),
		r("other-target", alice, "bbbb", "👀", 1, bob),
		r("other-chat", alice, msgID, "👀", 1, mal),
		r("bobs", bob, msgID, "👀", 1, bob),
		{ID: "d", From: alice, Type: "delete", Targets: []string{"gone"}, CreatedAt: 4},
		// mal can't remove alice's reaction: not even in alice's own view.
		{ID: "d2", From: mal, Type: "delete", Targets: []string{"r1"}, CreatedAt: 5},
	}
	if got := ownReactions(ms, alice, bob, msgID, "👀"); !reflect.DeepEqual(got, []string{"r1", "r3"}) {
		t.Fatalf("got %v", got)
	}
}

func TestUnreactArgs(t *testing.T) {
	for name, args := range map[string][]string{
		"nothing":             {"--to", "npub1x"},
		"both ways":           {"--to", "npub1x", msgID, "--target", msgID, "--emoji", "👀"},
		"target with no emoj": {"--to", "npub1x", "--target", msgID},
		"emoji with no targe": {"--to", "npub1x", "--emoji", "👀"},
		"no --to":             {msgID},
	} {
		cmd := newUnreactCommand()
		cmd.Flags().Bool("json", true, "")
		cmd.SetArgs(args)
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
