package signer

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip46"
)

func TestEvaluateExamplePolicy(t *testing.T) {
	p, err := LoadPolicy("../examples/signer/agent-policy.yaml", LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, signerPub := testKey(t, "signer")

	cases := []struct {
		name     string
		kind     int
		content  string
		tags     [][]string
		allow    bool
		rule     string
		reasonIs string
	}{
		{"chat message", 9, "hello", nil, true, "chat", ""},
		{"reaction", 7, "+", nil, true, "chat", ""},
		{"patch", 1617, "diff", nil, true, "git-proposals", ""},
		{"unknown kind", 4, "dm", nil, false, "everything-else", "denied by rule"},
		{"profile rewrite", 0, "{}", nil, false, "everything-else", "denied by rule"},
		{"nsec in chat", 9, "my key nsec1" + strings.Repeat("q", 58), nil, false, "chat", "content matches deny_matching pattern #1"},
		{"ncryptsec in tag", 1111, "ok", [][]string{{"x", "ncryptsec1abc"}}, false, "chat", "tag value matches deny_matching pattern #2"},
		{"relay auth, our relay", 22242, "", [][]string{{"relay", "wss://relay.example"}, {"challenge", "c"}}, true, "relay-auth", ""},
		{"relay auth, our relay path", 22242, "", [][]string{{"relay", "wss://relay.example/ws"}}, true, "relay-auth", ""},
		{"relay auth, lookalike host", 22242, "", [][]string{{"relay", "wss://relay.example.evil.example"}}, false, "everything-else", "denied by rule"},
		{"relay auth, other relay", 22242, "", [][]string{{"relay", "wss://other.example"}}, false, "everything-else", "denied by rule"},
		{"relay auth, no relay tag", 22242, "", nil, false, "everything-else", "denied by rule"},
		// tags_one: exactly one relay tag, ours (a relay takes any of a login's relay tags)
		{"relay auth, ours then another", 22242, "", [][]string{{"relay", "wss://relay.example"}, {"relay", "wss://other.example"}}, false, "everything-else", "denied by rule"},
		{"relay auth, another then ours", 22242, "", [][]string{{"relay", "wss://other.example"}, {"relay", "wss://relay.example"}}, false, "everything-else", "denied by rule"},
		{"relay auth, ours twice", 22242, "", [][]string{{"relay", "wss://relay.example"}, {"relay", "wss://relay.example"}}, false, "everything-else", "denied by rule"},
		{"relay auth, a bare relay tag beside ours", 22242, "", [][]string{{"relay", "wss://relay.example"}, {"relay"}}, false, "everything-else", "denied by rule"},
		{"http auth, git host GET", 27235, "", [][]string{{"u", "https://git.example/repo.git/info/refs"}, {"method", "GET"}}, true, "http-auth", ""},
		{"http auth, git host DELETE", 27235, "", [][]string{{"u", "https://git.example/repo"}, {"method", "DELETE"}}, false, "everything-else", "denied by rule"},
		{"http auth, other host", 27235, "", [][]string{{"u", "https://bank.example/"}, {"method", "POST"}}, false, "everything-else", "denied by rule"},
		{"repo state without approval", 30618, "", [][]string{{"d", "repo"}}, false, "repo-state", `attestation "maintainer-approval" required`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Evaluate(Request{
				Method:    nip46.MethodSignEvent,
				Event:     target(t, signerPub, c.kind, t0, c.content, c.tags...),
				Now:       t0,
				SignerPub: signerPub,
			}, p, noneUsed)
			if d.Allow != c.allow || d.Rule != c.rule || (c.reasonIs != "" && d.Reason != c.reasonIs) {
				t.Fatalf("got allow=%v rule=%q reason=%q, want allow=%v rule=%q reason=%q", d.Allow, d.Rule, d.Reason, c.allow, c.rule, c.reasonIs)
			}
		})
	}
}

func TestEvaluateSelectors(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	_, friend := testKey(t, "friend")
	_, stranger := testKey(t, "stranger")
	p := mustParse(t, `kind: signer-policy
rules:
  - name: first
    allow: {kinds: [1], tags: {t: ["exact"]}}
  - name: prefixed
    allow: {kinds: [1], tags: {t: ["pre*"], p: ["%s"]}}
  - name: kind-one-deny
    deny: {kinds: [1]}
  - name: kind-one-shadowed
    allow: {kinds: [1]}
  - name: dm
    allow: {methods: [nip44_decrypt, nip44_encrypt], counterparts: [%s]}
`, friend, npub(t, friend))

	sign := func(tags ...[]string) Decision {
		return Evaluate(Request{Method: nip46.MethodSignEvent, Event: target(t, signerPub, 1, t0, "x", tags...), Now: t0, SignerPub: signerPub}, p, noneUsed)
	}
	if d := sign([]string{"t", "exact"}); !d.Allow || d.Rule != "first" {
		t.Errorf("exact tag: %+v", d)
	}
	if d := sign([]string{"t", "exactly"}); d.Allow || d.Rule != "kind-one-deny" {
		t.Errorf("exact must not prefix-match: %+v", d)
	}
	if d := sign([]string{"t", "prefix"}, []string{"p", friend}); !d.Allow || d.Rule != "prefixed" {
		t.Errorf("prefix + second tag: %+v", d)
	}
	if d := sign([]string{"t", "prefix"}); d.Allow || d.Rule != "kind-one-deny" {
		t.Errorf("all tag keys must match: %+v", d)
	}
	if d := sign(); d.Allow || d.Rule != "kind-one-deny" {
		t.Errorf("first match wins over a later allow: %+v", d)
	}

	crypto := func(method, peer string) Decision {
		return Evaluate(Request{Method: method, Counterpart: peer, Now: t0, SignerPub: signerPub}, p, noneUsed)
	}
	if d := crypto(nip46.MethodNIP44Decrypt, friend); !d.Allow || d.Rule != "dm" {
		t.Errorf("listed counterpart: %+v", d)
	}
	if d := crypto(nip46.MethodNIP44Decrypt, stranger); d.Allow || d.Reason != "no rule matches" {
		t.Errorf("unlisted counterpart: %+v", d)
	}
	if d := crypto(nip46.MethodNIP04Decrypt, friend); d.Allow {
		t.Errorf("method not in rule: %+v", d)
	}
	if d := crypto("get_secret_key", friend); d.Allow || !strings.Contains(d.Reason, "unsupported method") {
		t.Errorf("unknown method: %+v", d)
	}
}

// tags matches when any same-named tag does; tags_one only when there is one, and it does.
func TestEvaluateTagsOne(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	p := mustParse(t, `kind: signer-policy
rules:
  - name: one
    allow: {kinds: [22242], tags_one: {relay: ["wss://ours.example", "wss://ours.example/*"]}, tags: {challenge: ["c"]}}
  - name: any
    allow: {kinds: [1], tags: {relay: ["wss://ours.example"]}}
  - name: rest
    deny: {}
`)
	sign := func(kind int, tags ...[]string) Decision {
		return Evaluate(Request{Method: nip46.MethodSignEvent, Event: target(t, signerPub, kind, t0, "", tags...), Now: t0, SignerPub: signerPub}, p, noneUsed)
	}
	ours, other, ch := []string{"relay", "wss://ours.example"}, []string{"relay", "wss://other.example"}, []string{"challenge", "c"}
	for _, c := range []struct {
		name  string
		kind  int
		tags  [][]string
		allow bool
	}{
		{"one, ours", 22242, [][]string{ours, ch}, true},
		{"one, ours with a path", 22242, [][]string{{"relay", "wss://ours.example/ws"}, ch}, true},
		{"one, another", 22242, [][]string{other, ch}, false},
		{"one, ours then another", 22242, [][]string{ours, other, ch}, false},
		{"one, another then ours", 22242, [][]string{other, ours, ch}, false},
		{"one, ours twice", 22242, [][]string{ours, ours, ch}, false},
		{"one, none", 22242, [][]string{ch}, false},
		{"one, ours, its other tag key unmatched", 22242, [][]string{ours, {"challenge", "d"}}, false},
		{"any, ours then another (tags: any one)", 1, [][]string{ours, other}, true},
	} {
		if d := sign(c.kind, c.tags...); d.Allow != c.allow {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	for why, bad := range map[string]string{
		"no value":        "{kinds: [1], tags_one: {relay: []}}",
		"in tags too":     "{kinds: [1], tags: {relay: [a]}, tags_one: {relay: [a]}}",
		"with an unwrap":  "{unwrap_from: [%s], tags_one: {relay: [a]}}",
		"with a method":   "{methods: [nip44_encrypt], tags_one: {relay: [a]}}",
		"with an attest ": "{attest: {subordinates: ['*'], max_until: 1d}, tags_one: {relay: [a]}}",
	} {
		if _, err := ParsePolicy([]byte("kind: signer-policy\nrules: [{name: r, allow: "+strings.ReplaceAll(bad, "%s", signerPub)+"}]"), "", LoadOptions{}); err == nil {
			t.Errorf("%s: loaded", why)
		}
	}
}

func TestEvaluateDefaultDeny(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	p := mustParse(t, "kind: signer-policy\nrules: [{name: chat, allow: {kinds: [9]}}]")
	d := Evaluate(Request{Method: nip46.MethodSignEvent, Event: target(t, signerPub, 5, t0, ""), Now: t0, SignerPub: signerPub}, p, noneUsed)
	if d.Allow || d.Rule != "" || d.Reason != "no rule matches" {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluateEncryptPlaintextPatterns(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	_, friend := testKey(t, "friend")
	p := mustParse(t, "kind: signer-policy\nrules: [{name: dm, allow: {counterparts: [%s]}, deny_matching: ['secret']}]", friend)
	d := Evaluate(Request{Method: nip46.MethodNIP44Encrypt, Counterpart: friend, Plaintext: "the secret is", Now: t0, SignerPub: signerPub}, p, noneUsed)
	if d.Allow || d.Reason != "plaintext matches deny_matching pattern #1" {
		t.Fatalf("%+v", d)
	}
}

func TestEvaluatePrechecks(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	_, other := testKey(t, "other")
	p := mustParse(t, "kind: signer-policy\nrules: [{name: chat, allow: {kinds: [9]}}]")

	d := Evaluate(Request{Method: nip46.MethodSignEvent, Event: target(t, other, 9, t0, ""), Now: t0, SignerPub: signerPub}, p, noneUsed)
	if d.Allow || !strings.Contains(d.Reason, "pubkey") {
		t.Errorf("pubkey mismatch: %+v", d)
	}
	d = Evaluate(Request{Method: nip46.MethodSignEvent, Event: target(t, signerPub, 9, t0.Add(11*60e9), ""), Now: t0, SignerPub: signerPub}, p, noneUsed)
	if d.Allow || !strings.Contains(d.Reason, "future") {
		t.Errorf("future event: %+v", d)
	}
	d = Evaluate(Request{Method: nip46.MethodSignEvent, Event: target(t, signerPub, 9, t0.Add(-11*60e9), ""), Now: t0, SignerPub: signerPub}, p, noneUsed)
	if d.Allow || !strings.Contains(d.Reason, "too old") {
		t.Errorf("old event: %+v", d)
	}
}
