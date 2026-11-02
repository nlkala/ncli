package dm

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip59"

	"github.com/ohstr/ncli/client"
)

// policyLike answers as the policy signer does for a ciphertext that doesn't
// decrypt: "nip44_decrypt failed: …", no denied code.
type policyLike struct{ *nip46.LocalKey }

func (k policyLike) Decrypt(ctx context.Context, scheme, peer, ct string) (string, error) {
	out, err := k.LocalKey.Decrypt(ctx, scheme, peer, ct)
	if err != nil {
		return "", &nip46.Error{Reason: fmt.Sprintf("nip44_decrypt failed: %v", err)}
	}
	return out, nil
}

// One junk wrap dated a year ahead was "invalid", so
// recorded with its created_at, and the state's since moved a year ahead —
// every later read with --state (or a follow's reconnect) asked only for wraps
// from then on. A wrap that didn't open is remembered by its id alone; the
// peer's real answer is read after it.
func TestJunkWrapAheadMovesNoSince(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv) // alice writes, bob reads
	now := time.Now()
	junkKey := key(t, "00000000000000000000000000000000000000000000000000000000000000ff")
	junk := nip01.NewEvent(nip59.KindGiftWrap, "AAAAnotnip44", []string{"p", bob.PubKey()})
	junk.CreatedAt = uint64(now.Add(365 * 24 * time.Hour).Unix())
	if err := junkKey.Sign(context.Background(), junk); err != nil {
		t.Fatal(err)
	}
	r := &reader{signer: policyLike{bob}, from: []string{alice.PubKey()}}
	_, show, record, err := r.open(context.Background(), junk)
	if err != nil || show || !record || r.invalid != 1 {
		t.Fatalf("junk: show=%v record=%v err=%v invalid=%d", show, record, err, r.invalid)
	}

	// As runRead records it: a shown wrap moves the since, one that didn't
	// open is only remembered.
	path := filepath.Join(t.TempDir(), "dm.state")
	st, _ := client.LoadFollowState(path)
	mark := func(w *nip01.Event, show, record bool) {
		switch {
		case show:
			st.Mark(w.ID, "", int64(w.CreatedAt))
		case record:
			st.MarkSeen(w.ID)
		}
	}
	mark(junk, show, record)
	if !st.Seen(junk.ID) || st.Resume(wrapBackdate+10*time.Minute) != 0 {
		t.Fatalf("junk: seen=%v resume=%d", st.Seen(junk.ID), st.Resume(wrapBackdate+10*time.Minute))
	}

	// A real answer, opened, then alice's next one: the resume from the
	// first still reaches the second, whose wrap is backdated up to two days.
	first := dmWrap(t, alice, bob, "salam")
	m, show, record, err := r.open(context.Background(), first)
	if err != nil || !show || !record || m.Content != "salam" {
		t.Fatalf("first: %+v show=%v record=%v err=%v", m, show, record, err)
	}
	mark(first, show, record)
	_ = st.Save()
	back, _ := client.LoadFollowState(path)
	resume := back.Resume(wrapBackdate + 10*time.Minute)
	if resume == 0 || resume > uint64(time.Now().Add(-wrapBackdate).Unix()) {
		t.Fatalf("resume %d: a wrap backdated two days from now would be missed", resume)
	}
	real := dmWrap(t, alice, bob, "approve")
	if real.CreatedAt < resume {
		t.Fatalf("the real answer's wrap (%d) is before the resume (%d)", real.CreatedAt, resume)
	}
}
