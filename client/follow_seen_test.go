package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// The seen ids were one FIFO list of 5000, so a flood of
// junk wraps (seen only) pushed the delivered answers out, and a restarted
// follow printed them again. Junk now has its own bounded list.
func TestFollowJunkFloodKeepsDelivered(t *testing.T) {
	fastBackoff(t)
	r := newLiveRelay(t)
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		r.add(note(t, fmt.Sprintf("answer %d", i), now-120))
	}
	path := filepath.Join(t.TempDir(), "s.json")
	targets, _ := TargetsFromRelayList([]string{r.url})

	// run follows until stop, counting what it printed and what it only saw.
	run := func(state *FollowState) (printed func() []string, junk func() int,
		stop func()) {
		var mu sync.Mutex
		var got []string
		var nJunk int
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Follow(ctx, targets, kindFilter(), FollowOptions{
				State: state,
				Emit: func(ev *nip01.Event, _ string) error {
					mu.Lock()
					defer mu.Unlock()
					if strings.HasPrefix(ev.Content, "junk") {
						nJunk++
						return ErrSeenOnly
					}
					got = append(got, ev.Content)
					return nil
				},
			})
		}()
		printed = func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
		junk = func() int { mu.Lock(); defer mu.Unlock(); return nJunk }
		stop = func() {
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		return
	}

	state, _ := LoadFollowState(path)
	printed, junk, stop := run(state)
	waitFor(t, func() bool { return len(printed()) == 3 && r.subscribers() == 1 })
	// The first junk wraps come through Follow (ErrSeenOnly).
	const live = 20
	for i := 0; i < live; i++ {
		r.add(note(t, fmt.Sprintf("junk %d", i), now-60))
	}
	waitFor(t, func() bool { return junk() == live })
	// Then the flood: 10000 more wraps that didn't open, marked as Follow
	// marks them (signing and verifying each here would take a minute).
	const flood = 10000
	for i := 0; i < flood; i++ {
		state.MarkSeen(fmt.Sprintf("%064x", i))
	}
	stop()

	// Restart: the relay sends everything again.
	back, err := LoadFollowState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.order) != 3 || len(back.onlyOrder) != maxSeenOnly {
		t.Fatalf("saved %d delivered, %d seen only", len(back.order), len(back.onlyOrder))
	}
	printed, junk, stop = run(back)
	// The live junk fell out of its own list and is seen again; the answers are not.
	waitFor(t, func() bool { return junk() == live && r.subscribers() == 1 })
	time.Sleep(200 * time.Millisecond)
	stop()
	if got := printed(); len(got) != 0 {
		t.Fatalf("a restart printed delivered answers again: %v", got)
	}
}

// A state file from an older ncli (one seen list) loads as delivered; a new
// one keeps its seen-only ids apart across a save.
func TestFollowStateSeenOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	raw, _ := json.Marshal(map[string]any{"seen": []string{"a", "b"}, "since": map[string]int64{}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadFollowState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Seen("a") || !s.Seen("b") || len(s.order) != 2 || len(s.onlyOrder) != 0 {
		t.Fatalf("old file: %v %v", s.order, s.onlyOrder)
	}
	if !s.MarkSeen("j") || s.MarkSeen("a") || s.Mark("j", "r", 1) {
		t.Fatal("a known id was marked again")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	back, _ := LoadFollowState(path)
	if strings.Join(back.order, ",") != "a,b" || strings.Join(back.onlyOrder, ",") != "j" {
		t.Fatalf("round trip: %v %v", back.order, back.onlyOrder)
	}
}
