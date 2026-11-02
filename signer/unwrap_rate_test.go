package signer

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip59"
	"github.com/ohstr/nmilat/nipLS"
)

const floodPolicy = `kind: signer-policy
rules:
  - name: friend
    allow: {methods: [nip44_encrypt, nip44_decrypt], counterparts: [%[1]s]}
  - name: inbox
    allow: {unwrap_from: [%[2]s]}
    rate: %[3]s
`

type wrapper struct {
	t   *testing.T
	pub string
}

func (w wrapper) of(from *nip46.LocalKey, text string) *nip01.Event {
	w.t.Helper()
	ctx := ctx5(w.t)
	seal, err := nip59.Seal(ctx, from, nip01.NewEvent(14, text, []string{"p", w.pub}), w.pub)
	if err != nil {
		w.t.Fatal(err)
	}
	wrap, err := nip59.WrapSeal(seal, w.pub)
	if err != nil {
		w.t.Fatal(err)
	}
	return wrap
}

// Junk gift wraps — anyone's, no key needed — never spend an
// unwrap_from rule's tokens; the listed sender's DM still opens after them.
func TestUnwrapJunkDoesNotStarveRate(t *testing.T) {
	priv, pub := testKey(t, "signer")
	friendPriv, friend := testKey(t, "friend")
	malPriv, _ := testKey(t, "mallory")
	r := startServer(t, Config{PrivKeyHex: priv, PolicyPath: writePolicy(t, floodPolicy, friend, friend, "600/h")})
	c := dial(t, r.uri)
	// 621 round trips: the test's own context, never one 5 s bound for them all
	// (under -race on a loaded machine they take longer)
	ctx := t.Context()
	friendKey, _ := nip46.NewLocalKey(friendPriv)
	malKey, _ := nip46.NewLocalKey(malPriv)
	w := wrapper{t, pub}

	junk := w.of(malKey, "junk")
	for i := 0; i < 600; i++ {
		_, err := nip59.Unwrap(ctx, c, junk, nip59.OpenOptions{})
		if !errors.Is(err, nipLS.ErrDenied) || RateLimited(err) {
			t.Fatalf("junk open %d: %v", i, err)
		}
	}
	for i := 0; i < 20; i++ { // fresh junk too
		if _, err := nip59.Unwrap(ctx, c, w.of(malKey, fmt.Sprint("junk ", i)), nip59.OpenOptions{}); !errors.Is(err, nipLS.ErrDenied) || RateLimited(err) {
			t.Fatalf("fresh junk %d: %v", i, err)
		}
	}
	got, err := nip59.Unwrap(ctx, c, w.of(friendKey, "OBJECT: stop this change"), nip59.OpenOptions{From: []string{friend}})
	if err != nil || got.Rumor.Content != "OBJECT: stop this change" {
		t.Fatalf("the friend's DM after the junk: %v", err)
	}

	// The repeated junk wrap was decrypted once; every later ask was
	// refused before any decryption.
	var first, again int
	for _, rec := range r.decisions.records(t) {
		switch {
		case rec.Rule == "inbox" && strings.HasSuffix(rec.Reason, "does not list"):
			first++
		case rec.Rule == "inbox" && strings.Contains(rec.Reason, "refused before"):
			again++
		}
	}
	if first != 21 || again != 599 {
		t.Fatalf("decrypted and refused %d, refused at once %d", first, again)
	}
}

// The rule's rate still holds for the senders it lists, a rate refusal says
// so (RateLimited), and a wrap not addressed to the signer is remembered too.
func TestUnwrapRateChargesReleasedOnly(t *testing.T) {
	priv, pub := testKey(t, "signer")
	friendPriv, friend := testKey(t, "friend")
	malPriv, mal := testKey(t, "mallory")
	_, other := testKey(t, "someone else")
	path := writePolicy(t, floodPolicy, friend, friend, "2/h")
	clock := &fakeClock{}
	clock.set(time.Unix(1700000000, 0))
	r := startServer(t, Config{PrivKeyHex: priv, PolicyPath: path, Now: clock.now})
	c := dial(t, r.uri)
	ctx := ctx5(t)
	friendKey, _ := nip46.NewLocalKey(friendPriv)
	malKey, _ := nip46.NewLocalKey(malPriv)
	w := wrapper{t, pub}
	open := func(ev *nip01.Event) error {
		_, err := nip59.Unwrap(ctx, c, ev, nip59.OpenOptions{})
		return err
	}

	malWrap := w.of(malKey, "junk")
	notOurs := wrapper{t, other}.of(malKey, "to someone else")
	for i := 0; i < 2; i++ {
		if err := open(malWrap); RateLimited(err) || !errors.Is(err, nipLS.ErrDenied) {
			t.Fatalf("junk: %v", err)
		}
		// The first ask fails to decrypt; the next is refused at once.
		if err := open(notOurs); err == nil || RateLimited(err) || (i > 0 && !errors.Is(err, nipLS.ErrDenied)) {
			t.Fatalf("a wrap to someone else: %v", err)
		}
		if err := open(w.of(friendKey, "hi")); err != nil {
			t.Fatalf("friend %d: %v", i, err)
		}
	}
	held := w.of(friendKey, "third")
	if err := open(held); !RateLimited(err) {
		t.Fatalf("third DM within the hour: %v, want rate limited", err)
	}
	if err := open(malWrap); RateLimited(err) || !errors.Is(err, nipLS.ErrDenied) {
		t.Fatalf("junk with an empty bucket: %v", err)
	}
	clock.set(clock.now().Add(31 * time.Minute))
	if err := open(held); err != nil {
		t.Fatalf("the held DM, half an hour later: %v", err)
	}

	refusedAgain := 0
	for _, rec := range r.decisions.records(t) {
		if strings.Contains(rec.Reason, "refused before") {
			refusedAgain++
		}
	}
	if refusedAgain != 3 { // malWrap twice more, notOurs once more
		t.Fatalf("refused at once %d\n%s", refusedAgain, r.decisions.String())
	}

	// A refusal is the policy's: once it lists mallory, her wrap opens.
	if err := os.WriteFile(path, []byte(fmt.Sprintf(floodPolicy, friend, mal, "2/h")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	clock.set(clock.now().Add(time.Hour))
	if _, err := c.Decrypt(ctx, nip59.EncryptionNIP44V2, malWrap.PubKey, malWrap.Content); err != nil {
		t.Fatalf("mallory's wrap after the reload: %v", err)
	}
}
