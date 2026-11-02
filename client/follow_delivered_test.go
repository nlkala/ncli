package client

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// dm read -f marks a wrap delivered as soon as it is printed, and a reconnect or a restart of the
// follow with the same --state never prints it again: printing is delivery. A consumer keeps what
// it couldn't handle itself; this pins that the follow never repeats one.
func TestFollowPrintedIsDeliveredEvenIfConsumerFailed(t *testing.T) {
	fastBackoff(t)
	r := newLiveRelay(t)
	now := time.Now().Unix()
	r.add(note(t, "the peer's answer", now-60))
	path := filepath.Join(t.TempDir(), "s.json")
	var mu sync.Mutex
	got := 0
	run := func() {
		state, _ := LoadFollowState(path)
		targets, _ := TargetsFromRelayList([]string{r.url})
		followUntilPaged(t, targets, kindFilter(), FollowOptions{State: state, Overlap: 48*time.Hour + 10*time.Minute,
			Emit: func(ev *nip01.Event, _ string) error {
				mu.Lock()
				got++
				mu.Unlock()
				return nil // printed: dm read returns nil whatever its reader does with the line
			}})
	}
	run() // the consumer fails on this one (only logged)
	run() // the follow restarted
	run()
	mu.Lock()
	defer mu.Unlock()
	t.Logf("the answer was printed %d time(s) over three follows sharing --state", got)
	if got != 1 {
		t.Fatalf("got %d", got)
	}
}
