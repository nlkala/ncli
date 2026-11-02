package social

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ohstr/ncli/client"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipOA"
)

const (
	ownerPriv = "0000000000000000000000000000000000000000000000000000000000000011"
	agentPriv = "0000000000000000000000000000000000000000000000000000000000000012"
)

// attest is ownerPriv's auth tag for sub under conditions.
func attest(t *testing.T, ownerPriv, sub, conditions string) []string {
	t.Helper()
	ks, err := nipOA.NewKeySigner(ownerPriv)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := nipOA.Sign(context.Background(), ks, sub, conditions)
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

func localSigner(t *testing.T, priv string) *client.LocalSigner {
	t.Helper()
	s, err := client.NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authCmd(t *testing.T, value string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "x"}
	AddSignerFlag(cmd)
	if value != "" {
		if err := cmd.Flags().Set("auth", value); err != nil {
			t.Fatal(err)
		}
	}
	return cmd
}

func TestAuthTag(t *testing.T) {
	agent := localSigner(t, agentPriv)
	owner := localSigner(t, ownerPriv)
	good := attest(t, ownerPriv, agent.PubKey(), "kind=1")
	js := func(tag []string) string { b, _ := json.Marshal(tag); return string(b) }

	if tag, err := AuthTag(authCmd(t, js(good)), agent.PubKey()); err != nil || strings.Join(tag, ",") != strings.Join(good, ",") {
		t.Fatalf("--auth: %v %v", tag, err)
	}
	if tag, err := AuthTag(authCmd(t, ""), agent.PubKey()); err != nil || tag != nil {
		t.Fatalf("none: %v %v", tag, err)
	}
	viper.Set("auth_tag", js(good))
	t.Cleanup(func() { viper.Set("auth_tag", "") })
	if tag, err := AuthTag(authCmd(t, ""), strings.ToUpper(agent.PubKey())); err != nil || tag == nil {
		t.Fatalf("NCLI_AUTH_TAG: %v %v", tag, err)
	}
	viper.Set("auth_tag", "")

	third := localSigner(t, "0000000000000000000000000000000000000000000000000000000000000013")
	other := attest(t, ownerPriv, third.PubKey(), "")
	bad := append([]string(nil), good...)
	bad[3] = strings.Repeat("0", 128)
	for name, v := range map[string]string{
		"not json":         "auth",
		"not auth":         `["t","x"]`,
		"three elements":   js(good[:3]),
		"another key's":    js(other),
		"bad signature":    js(bad),
		"the signer's own": js(attest(t, agentPriv, owner.PubKey(), "")),
	} {
		if _, err := AuthTag(authCmd(t, v), agent.PubKey()); err == nil || !strings.Contains(err.Error(), "--auth") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// WithAuth tags what the attestation covers, signs it validly, and never a
// seal or a gift wrap; AddAuth tags a rumor the same way.
func TestWithAuthSigns(t *testing.T) {
	agent := localSigner(t, agentPriv)
	tag := attest(t, ownerPriv, agent.PubKey(), "kind=1&created_at<4000000000")
	s := WithAuth(agent, tag)
	ctx := context.Background()

	note := nip01.NewEvent(1, "hi")
	note.CreatedAt = 1800000000
	if err := s.Sign(ctx, note); err != nil {
		t.Fatal(err)
	}
	if a, err := nipOA.ParseAuthTag(note.Tags, note.PubKey); err != nil || a == nil || ok(note) != nil {
		t.Fatalf("kind 1: %v %v %v", a, err, note.Tags)
	}
	for _, kind := range []int{7, kindSeal, kindGiftWrap} {
		ev := nip01.NewEvent(kind, "x")
		ev.CreatedAt = 1800000000
		if err := s.Sign(ctx, ev); err != nil {
			t.Fatal(err)
		}
		if hasAuth(ev) {
			t.Errorf("kind %d tagged", kind)
		}
	}
	// an event that already carries one keeps its own
	own := nip01.NewEvent(1, "x")
	own.CreatedAt = 1800000000
	own.Tags = [][]string{{"auth", "mine"}}
	_ = s.Sign(ctx, own)
	if len(own.Tags) != 1 || own.Tags[0][1] != "mine" {
		t.Fatalf("own tag replaced: %v", own.Tags)
	}

	rumor := nip01.NewEvent(1, "dm")
	rumor.CreatedAt = 1800000000
	AddAuth(s, rumor)
	if !hasAuth(rumor) {
		t.Fatal("rumor untagged")
	}
	plain := nip01.NewEvent(1, "dm")
	AddAuth(agent, plain)
	if hasAuth(plain) {
		t.Fatal("a signer without --auth tagged a rumor")
	}
	if WithAuth(agent, nil) != client.Crypto(agent) {
		t.Fatal("no tag: not the signer itself")
	}
}

func hasAuth(ev *nip01.Event) bool {
	for _, t := range ev.Tags {
		if len(t) > 0 && t[0] == "auth" {
			return true
		}
	}
	return false
}

func ok(ev *nip01.Event) error {
	return ev.Verify()
}
