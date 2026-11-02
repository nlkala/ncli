package client

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// One junk gift wrap dated a year ahead, recorded as
// delivered, moved the relay's since a year ahead, and every later
// subscription (a reconnect, a restart with --state) asked only for events
// from then on. A wrap that didn't open is now remembered by id alone
// (ErrSeenOnly), a since never passes now, and a peer's real answer —
// a wrap backdated up to two days, as NIP-59 allows — is delivered after a
// reconnect.
func TestFollowJunkAheadNeverBlinds(t *testing.T) {
	fastBackoff(t)
	r := newLiveRelay(t)
	now := time.Now().Unix()
	const backdate = 2 * 24 * 3600
	r.add(note(t, "first", now))                   // opened: since = now
	r.add(note(t, "junk", now+365*24*3600))        // doesn't open
	r.add(note(t, "ahead but opened", now+7*3600)) // opened, dated ahead: since held to now
	path := filepath.Join(t.TempDir(), "s.json")
	state, _ := LoadFollowState(path)
	targets, _ := TargetsFromRelayList([]string{r.url})

	var mu sync.Mutex
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, targets, kindFilter(), FollowOptions{
			State:   state,
			Overlap: backdate*time.Second + 10*time.Minute,
			Emit: func(ev *nip01.Event, _ string) error {
				mu.Lock()
				got = append(got, ev.Content)
				mu.Unlock()
				if ev.Content == "junk" {
					return ErrSeenOnly
				}
				return nil
			},
		})
	}()
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }
	waitFor(t, func() bool { return count() == 3 && r.subscribers() == 1 })
	if s := state.Since(r.url); s > time.Now().Unix() || s < now {
		t.Fatalf("since %d, want within [%d, now]", s, now)
	}
	if state.Seen("") || len(state.order) != 2 || len(state.onlyOrder) != 1 {
		t.Fatalf("the junk's id must be remembered apart: %v %v", state.order, state.onlyOrder)
	}

	r.drop()
	// The peer's answer, sent while the follow was away, its wrap dated
	// as far back as NIP-59 allows.
	r.add(note(t, "the real answer", time.Now().Unix()-backdate+1))
	waitFor(t, func() bool { return count() == 4 })
	mu.Lock()
	if got[3] != "the real answer" {
		t.Fatalf("got %v", got)
	}
	mu.Unlock()
	if since := r.lastSince(); int64(since) > time.Now().Unix()-backdate {
		t.Fatalf("resumed since %d is past the answer's wrap", since)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	back, _ := LoadFollowState(path)
	if back.Since(r.url) > time.Now().Unix() {
		t.Fatalf("saved since %d is ahead", back.Since(r.url))
	}
}

// A state an older ncli saved with a since ahead of now (a junk wrap it
// recorded) is healed on load: that since is forgotten, so the next read
// asks again from its own filter, and the seen ids still dedupe.
func TestFollowStateHealsSinceAhead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	now := time.Now().Unix()
	raw, _ := json.Marshal(followStateFile{Seen: []string{"junk", "old"},
		Since: map[string]int64{"wss://ahead.example": now + 365*24*3600, "wss://other.example": now - 60}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadFollowState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Since("wss://ahead.example"); got != 0 {
		t.Fatalf("since ahead kept: %d", got)
	}
	if got := s.Since("wss://other.example"); got != now-60 {
		t.Fatalf("a past since lost: %d", got)
	}
	if !s.Seen("junk") || !s.Seen("old") {
		t.Fatal("seen ids lost")
	}
	if got := s.Resume(10 * time.Minute); got != uint64(now-60-600) {
		t.Fatalf("resume %d", got)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	back, _ := LoadFollowState(path)
	if back.Since("wss://ahead.example") != 0 {
		t.Fatal("the healed state was not saved")
	}

	// Mark holds a since to now; MarkSeen moves none.
	m, _ := LoadFollowState("")
	m.Mark("a", "r", now+365*24*3600)
	if got := m.Since("r"); got > time.Now().Unix() {
		t.Fatalf("Mark moved since ahead: %d", got)
	}
	if !m.MarkSeen("b") || m.MarkSeen("b") || m.Since("x") != 0 {
		t.Fatal("MarkSeen")
	}
}
