package dm

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ohstr/ncli/cli/social"
	"github.com/ohstr/ncli/client"
	"github.com/ohstr/nmilat/nip17"
	"github.com/ohstr/nmilat/nip59"
	"github.com/ohstr/nmilat/nipOA"
)

// dm send --auth: the rumor inside both seals carries the auth tag, and the
// seal and the gift wrap carry none (NIP-59).
func TestSendRumorCarriesAuth(t *testing.T) {
	alice, err := client.NewLocalSigner(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	bob := key(t, bobPriv)
	ks, err := nipOA.NewKeySigner(malPriv) // the owner
	if err != nil {
		t.Fatal(err)
	}
	tag, err := nipOA.Sign(context.Background(), ks, alice.PubKey(), "kind=14")
	if err != nil {
		t.Fatal(err)
	}
	signer := social.WithAuth(alice, tag)

	cmd := &cobra.Command{Use: "send"}
	cmd.Flags().Bool("no-self-copy", false, "")
	cmd.SetContext(context.Background())
	rumor := nip17.NewChatMessage("hi", nip17.WithRecipients(bob.PubKey()))
	rumor.CreatedAt = uint64(time.Now().Unix())
	wraps, err := wrapForBoth(cmd, signer, rumor, bob.PubKey())
	if err != nil || len(wraps) != 2 {
		t.Fatalf("%d wraps, %v", len(wraps), err)
	}
	for i, priv := range []string{bobPriv, alicePriv} {
		if len(wraps[i].Tags) > 0 {
			for _, tg := range wraps[i].Tags {
				if tg[0] == "auth" {
					t.Fatalf("wrap %d carries an auth tag", i)
				}
			}
		}
		got, _, err := nip59.UnwrapWithKey(wraps[i], priv)
		if err != nil {
			t.Fatal(err)
		}
		a, err := nipOA.ParseAuthTag(got.Tags, got.PubKey)
		if err != nil || a == nil || a.OwnerPubkey != ks.PubKey() {
			t.Fatalf("wrap %d's rumor: %v %v", i, a, err)
		}
	}
}
