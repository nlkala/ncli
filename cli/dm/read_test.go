package dm

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip59"
	"github.com/ohstr/nmilat/nipLS"
)

// limitedKey refuses its first n decryptions the way the policy signer
// refuses for a rule's rate, or for a sender unwrap_from does not list.
type limitedKey struct {
	*nip46.LocalKey
	n      int
	reason string
}

func (k *limitedKey) Decrypt(ctx context.Context, scheme, peer, ciphertext string) (string, error) {
	if k.n > 0 {
		k.n--
		return "", nipLS.Denyf("rule %q: %s", "inbox", k.reason)
	}
	return k.LocalKey.Decrypt(ctx, scheme, peer, ciphertext)
}

func dmWrap(t *testing.T, from, to *nip46.LocalKey, text string) *nip01.Event {
	t.Helper()
	ctx := context.Background()
	seal, err := nip59.Seal(ctx, from, nip01.NewEvent(14, text, []string{"p", to.PubKey()}), to.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	w, err := nip59.WrapSeal(seal, to.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// A wrap the signer refuses for its rate is tried again, never skipped
// (until its context ends); one it refuses for its policy is skipped and left unrecorded.
func TestReadRetriesRateLimited(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	w := dmWrap(t, alice, bob, "OBJECT: stop this change")

	var waits []int
	r := &reader{
		signer: &limitedKey{LocalKey: bob, n: 3, reason: "rate limit exceeded"},
		from:   []string{alice.PubKey()},
		wait:   func(_ context.Context, n int) error { waits = append(waits, n); return nil },
	}
	m, show, record, err := r.open(context.Background(), w)
	if err != nil || !show || !record || m.Content != "OBJECT: stop this change" {
		t.Fatalf("open: %+v show=%v record=%v err=%v", m, show, record, err)
	}
	if r.limited != 3 || len(waits) != 3 || r.skipped != 0 {
		t.Fatalf("limited %d, waits %v, skipped %d", r.limited, waits, r.skipped)
	}

	// Stopped while waiting: an error, and the wrap stays unrecorded.
	ctx, cancel := context.WithCancel(context.Background())
	r = &reader{
		signer: &limitedKey{LocalKey: bob, n: 1, reason: "rate limit exceeded"},
		from:   []string{alice.PubKey()},
		wait:   func(ctx context.Context, _ int) error { cancel(); return ctx.Err() },
	}
	if _, show, record, err := r.open(ctx, w); !errors.Is(err, context.Canceled) || show || record {
		t.Fatalf("cancelled: show=%v record=%v err=%v", show, record, err)
	}

	// Refused by the policy: skipped, not retried, not recorded.
	r = &reader{
		signer: &limitedKey{LocalKey: bob, n: 1, reason: "seal is from a sender unwrap_from does not list"},
		from:   []string{alice.PubKey()},
		wait:   func(context.Context, int) error { t.Fatal("retried a policy refusal"); return nil },
	}
	if _, show, record, err := r.open(context.Background(), w); err != nil || show || record || r.skipped != 1 {
		t.Fatalf("refused: show=%v record=%v err=%v skipped=%d", show, record, err, r.skipped)
	}
}
