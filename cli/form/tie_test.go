package form

import (
	"testing"
	"time"
)

// In one second: respond, change, withdraw — each counts over the one
// before (nippf breaks a tie by the lowest id, so each is timed after).
func TestSameSecondReplies(t *testing.T) {
	setup(t)
	frozen := time.Unix(1793000000, 0)
	clock = func() time.Time { return frozen }
	alice, bob := newActor(t, 1), newActor(t, 2)
	g := func(a actor, args ...string) []string {
		return append(args, "--group", "ops", "--relay", "wss://groups.example", "--json", "--signer", a.priv)
	}
	sent := decode[deliveryJSON](t, mustOK(t, "", g(alice, "create", "--spec", specFile(t, []string{bob.pub}, ""))...))
	mustOK(t, "", g(bob, "respond", sent.ID, "--choose", "forward")...)
	mustOK(t, "", g(bob, "respond", sent.ID, "--choose", "revert")...)
	v := decode[viewJSON](t, mustOK(t, "", g(alice, "show", sent.ID)...))
	if v.Tally.Responses != 1 || v.Responses[0].Choices[0].Option != "revert" {
		t.Fatalf("after the change %+v", v)
	}
	mustOK(t, "", g(bob, "withdraw", sent.ID)...)
	if v := decode[viewJSON](t, mustOK(t, "", g(alice, "show", sent.ID)...)); v.Tally.Responses != 0 {
		t.Fatalf("after the withdrawal %+v", v)
	}
}
