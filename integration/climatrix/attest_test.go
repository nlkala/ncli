package climatrix

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipOA"
)

func TestAttest(t *testing.T) {
	e := NewEnv(t)
	alice, bob := A(t, "alice"), A(t, "bob")
	until := strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10)

	var res struct {
		Tag        []string `json:"tag"`
		Attester   string   `json:"attester"`
		Conditions string   `json:"conditions"`
	}
	e.MustOK(t, "id", "attest", bob.Npub, "--until", until, "--kind", "1", "--identity", alice.Nsec, "--json").JSON(t, &res)
	if res.Attester != alice.PubHex || res.Conditions != "kind=1&created_at<"+until || len(res.Tag) != 4 {
		t.Fatalf("attest: %+v", res)
	}
	if err := nipOA.VerifySignature(alice.PubHex, bob.PubHex, res.Conditions, res.Tag[3]); err != nil {
		t.Fatal(err)
	}
	text := e.MustOK(t, "id", "attest", bob.PubHex, "--until", until, "--identity", alice.Nsec)
	if !strings.HasPrefix(text.Stdout, `["auth","`+alice.PubHex+`","created_at<`+until+`",`) {
		t.Errorf("text output %q", text.Stdout)
	}

	t.Run("errors", func(t *testing.T) {
		e.Run(t, "id", "attest", bob.Npub, "--json").ExpectErr(t, "usage")
		e.Run(t, "id", "attest", bob.Npub, "--until", "1000", "--identity", alice.Nsec, "--json").ExpectErr(t, "invalid_input")
		e.Run(t, "id", "attest", alice.Npub, "--until", until, "--identity", alice.Nsec, "--json").ExpectErr(t, "invalid_input")
		e.Run(t, "id", "attest", "npub1nope", "--identity", alice.Nsec, "--json").ExpectErr(t, "invalid_input")
		e.Run(t, "id", "attest", bob.Npub, "--identity", alice.Npub, "--json").ExpectErr(t, "auth")
	})
}
