package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/ncli/signer"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipLS"
	"github.com/ohstr/nmilat/nipOA"
	"github.com/ohstr/nmilat/utils"
)

func attestKey(t *testing.T, name string) (priv, pub string) {
	t.Helper()
	sum := sha256.Sum256([]byte(name))
	priv = hex.EncodeToString(sum[:])
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// socketSigner runs an in-process policy signer with policy and dials it.
func socketSigner(t *testing.T, priv, policy string) *nipLS.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := signer.New(signer.Config{PrivKeyHex: priv, PolicyPath: path})
	if err != nil {
		t.Fatal(err)
	}
	l, err := nipLS.Listen(filepath.Join(dir, "s.sock"), nipLS.ListenOptions{Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done; _ = srv.Close() })
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	c, err := nipLS.Dial(dctx, nipLS.FormatURI(filepath.Join(dir, "s.sock")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSignAttestationWith(t *testing.T) {
	priv, pub := attestKey(t, "attester")
	_, sub := attestKey(t, "subordinate")
	_, stranger := attestKey(t, "stranger")
	conds := "kind=1&created_at<" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	ctx := context.Background()

	local, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := SignAttestationWith(ctx, local, sub, conds)
	if err != nil {
		t.Fatal(err)
	}
	if len(tag) != 4 || tag[0] != "auth" || tag[1] != pub || tag[2] != conds {
		t.Fatalf("tag = %q", tag)
	}
	ev := &nip01.Event{PubKey: sub, Tags: [][]string{tag}}
	if got, err := nipOA.ParseAuthTag(ev.Tags, sub); err != nil || got.OwnerPubkey != pub {
		t.Fatalf("ParseAuthTag: %+v, %v", got, err)
	}

	sock := socketSigner(t, priv, "kind: signer-policy\nrules:\n  - name: attest-sub\n    allow: {attest: {subordinates: ["+sub+"], max_until: 1d}}\n")
	tag2, err := SignAttestationWith(ctx, sock, sub, conds)
	if err != nil {
		t.Fatal(err)
	}
	if tag2[1] != pub || nipOA.VerifySignature(pub, sub, conds, tag2[3]) != nil {
		t.Fatalf("socket tag = %q", tag2)
	}
	if _, err := SignAttestationWith(ctx, sock, stranger, conds); !errors.Is(err, nipLS.ErrDenied) {
		t.Errorf("stranger through the socket: %v, want denied", err)
	}

	if _, err := SignAttestationWith(ctx, signOnly{local}, sub, conds); !errors.Is(err, ErrCannotAttest) {
		t.Errorf("a signer without the method: %v", err)
	}
}

// signOnly hides LocalSigner's Attest, as a NIP-46 bunker has none.
type signOnly struct{ s *LocalSigner }

func (s signOnly) PubKey() string                                  { return s.s.PubKey() }
func (s signOnly) Sign(ctx context.Context, ev *nip01.Event) error { return s.s.Sign(ctx, ev) }
