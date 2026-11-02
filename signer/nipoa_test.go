package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nipLS"
	"github.com/ohstr/nmilat/nipOA"
)

func until(d time.Duration) string {
	return "created_at<" + strconv.FormatInt(t0.Add(d).Unix(), 10)
}

func attestReq(signerPub, sub, conds string) Request {
	return Request{Method: MethodAttest, Subordinate: sub, Conditions: conds, Now: t0, SignerPub: signerPub}
}

// attestPolicy allows the signer to attest `sub` (and with kinds [1] any
// key) for up to 30 days, and nothing else.
func attestPolicy(t *testing.T, sub string) *Policy {
	return mustParse(t, `kind: signer-policy
rules:
  - name: notes
    allow: {kinds: [1]}
  - name: attest-one
    allow: {attest: {subordinates: [%s], max_until: 30d}}
    rate: 2/h
  - name: attest-any-notes
    allow: {attest: {subordinates: ["*"], max_until: 7d, kinds: [1]}}
  - name: everything-else
    deny: {}
`, npub(t, sub))
}

func TestAttestPolicyValidation(t *testing.T) {
	_, sub := testKey(t, "sub")
	cases := map[string]string{
		"no max_until":          `allow: {attest: {subordinates: ["*"]}}`,
		"no subordinates":       `allow: {attest: {max_until: 1d}}`,
		"bad subordinate":       `allow: {attest: {subordinates: [npub1nope], max_until: 1d}}`,
		"kinds beside attest":   `allow: {kinds: [1], attest: {subordinates: ["*"], max_until: 1d}}`,
		"other method":          `allow: {methods: [sign_event], attest: {subordinates: ["*"], max_until: 1d}}`,
		"method without attest": `allow: {methods: [nipoa_attest]}`,
		"deny with bounds":      `deny: {attest: {subordinates: ["*"], max_until: 1d}}`,
		"deny_matching":         "allow: {attest: {subordinates: [\"*\"], max_until: 1d}}\n    deny_matching: [x]",
		"zero days":             `allow: {attest: {subordinates: ["*"], max_until: 0d}}`,
		"negative":              `allow: {attest: {subordinates: ["*"], max_until: "-1h"}}`,
		"bad kind":              `allow: {attest: {subordinates: ["*"], max_until: 1d, kinds: [70000]}}`,
		"require":               "allow: {attest: {subordinates: [\"*\"], max_until: 1d}}\n    require: {attestations: [{name: a, kinds: [9], authors: [" + sub + "], max_age: 1m, binds: [{tag: e, from: id}]}]}",
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			path := writePolicy(t, "kind: signer-policy\nrules:\n  - name: r\n    %s\n", rule)
			if _, err := LoadPolicy(path, LoadOptions{}); err == nil {
				t.Fatalf("policy loaded, want an error:\n%s", rule)
			}
		})
	}
	// The valid forms load.
	for _, rule := range []string{
		`allow: {attest: {subordinates: ["*"], max_until: 12h}}`,
		`allow: {methods: [nipoa_attest], attest: {subordinates: [` + sub + `], max_until: 30d, kinds: [1, 7]}}`,
		`deny: {attest: {subordinates: [` + sub + `]}}`,
		`deny: {methods: [nipoa_attest]}`,
	} {
		if _, err := LoadPolicy(writePolicy(t, "kind: signer-policy\nrules:\n  - name: r\n    %s\n", rule), LoadOptions{}); err != nil {
			t.Errorf("%s: %v", rule, err)
		}
	}
}

func TestAttestEvaluate(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	_, sub := testKey(t, "sub")
	_, other := testKey(t, "other")
	p := attestPolicy(t, sub)

	cases := []struct {
		name, sub, conds string
		allow            bool
		rule, reason     string
	}{
		{"listed key, 10 days", sub, until(10 * 24 * time.Hour), true, "attest-one", ""},
		{"listed key, kind and bound", sub, "kind=7&" + until(time.Hour), true, "attest-one", ""},
		{"listed key, beyond 30 days", sub, until(31 * 24 * time.Hour), false, "attest-one", "beyond max_until"},
		{"listed key, no bound", sub, "kind=1", false, "attest-one", "no created_at< bound"},
		{"listed key, empty conditions", sub, "", false, "attest-one", "no created_at< bound"},
		{"listed key, bound passed", sub, until(-time.Minute), false, "attest-one", "already passed"},
		{"listed key, tightest bound counts", sub, until(40*24*time.Hour) + "&" + until(time.Hour), true, "attest-one", ""},
		{"any key, notes only", other, "kind=1&" + until(time.Hour), true, "attest-any-notes", ""},
		{"any key, other kind", other, "kind=7&" + until(time.Hour), false, "attest-any-notes", "kind 7"},
		{"any key, no kind", other, until(time.Hour), false, "attest-any-notes", "no kind= clause"},
		{"any key, 8 days", other, "kind=1&" + until(8*24*time.Hour), false, "attest-any-notes", "beyond max_until"},
		{"itself", signerPub, "kind=1&" + until(time.Hour), false, "", "can't attest itself"},
		{"uppercase hex", strings.ToUpper(sub), until(time.Hour), false, "", "lowercase hex"},
		{"npub", npub(t, sub), until(time.Hour), false, "", "lowercase hex"},
		{"short", sub[:62], until(time.Hour), false, "", "lowercase hex"},
		{"conditions: an event", sub, `{"kind":1}`, false, "", "conditions"},
		{"conditions: leading zero", sub, "kind=01&" + until(time.Hour), false, "", "conditions"},
		{"conditions: unknown clause", sub, "pubkey=" + other, false, "", "conditions"},
		{"conditions: trailing &", sub, until(time.Hour) + "&", false, "", "conditions"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Evaluate(attestReq(signerPub, c.sub, c.conds), p, noneUsed)
			if d.Allow != c.allow || d.Rule != c.rule || !strings.Contains(d.Reason, c.reason) {
				t.Fatalf("got allow=%v rule=%q reason=%q, want allow=%v rule=%q reason~%q", d.Allow, d.Rule, d.Reason, c.allow, c.rule, c.reason)
			}
		})
	}
}

// Attesting is denied unless a rule written for it allows it: not by a
// catch-all allow, not by rules for events or encryption, and not by the
// example policies, which have no attest rule.
func TestAttestDefaultDeny(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	_, sub := testKey(t, "sub")
	req := attestReq(signerPub, sub, "kind=1&"+until(time.Hour))

	catchAll, err := LoadPolicy(writePolicy(t, "kind: signer-policy\nrules:\n  - name: all\n    allow: {}\n"), LoadOptions{AllowCatchAll: true})
	if err != nil {
		t.Fatal(err)
	}
	if d := Evaluate(req, catchAll, noneUsed); d.Allow || d.Reason != "no rule matches" {
		t.Errorf("catch-all allow: %+v", d)
	}

	events := mustParse(t, `kind: signer-policy
rules:
  - name: notes
    allow: {kinds: [0, 1, 3, 7, 9, 27235]}
  - name: dm
    allow: {counterparts: [%s]}
`, sub)
	if d := Evaluate(req, events, noneUsed); d.Allow {
		t.Errorf("event and encryption rules allowed an attestation: %+v", d)
	}

	for _, name := range []string{"agent-policy.yaml", "messaging-policy.yaml"} {
		p, err := LoadPolicy(filepath.Join("..", "examples", "signer", name), LoadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if d := Evaluate(req, p, noneUsed); d.Allow || d.Rule != "everything-else" {
			t.Errorf("examples/signer/%s: %+v, want denied by everything-else", name, d)
		}
	}

	// Denied by an earlier deny rule for that key, before the allow.
	denyFirst := mustParse(t, `kind: signer-policy
rules:
  - name: never-sub
    deny: {attest: {subordinates: [%s]}}
  - name: attest
    allow: {attest: {subordinates: ["*"], max_until: 1d}}
`, sub)
	if d := Evaluate(req, denyFirst, noneUsed); d.Allow || d.Rule != "never-sub" {
		t.Errorf("deny before allow: %+v", d)
	}
}

// An attest rule allows nothing but attestations.
func TestAttestRuleAllowsNoEvent(t *testing.T) {
	_, signerPub := testKey(t, "signer")
	p := mustParse(t, `kind: signer-policy
rules:
  - name: attest
    allow: {attest: {subordinates: ["*"], max_until: 30d}}
`)
	for _, kind := range []int{0, 1, 27235, 30617} {
		ev := target(t, signerPub, kind, t0, "")
		d := Evaluate(Request{Method: nip46.MethodSignEvent, Event: ev, Now: t0, SignerPub: signerPub}, p, noneUsed)
		if d.Allow {
			t.Errorf("kind %d signed under an attest rule", kind)
		}
	}
	_, peer := testKey(t, "peer")
	for _, m := range []string{nip46.MethodNIP44Encrypt, nip46.MethodNIP44Decrypt, nip46.MethodNIP04Encrypt} {
		if d := Evaluate(Request{Method: m, Counterpart: peer, Now: t0, SignerPub: signerPub}, p, noneUsed); d.Allow {
			t.Errorf("%s allowed under an attest rule", m)
		}
	}
}

func TestSignAttestation(t *testing.T) {
	priv, pub := testKey(t, "signer")
	_, sub := testKey(t, "sub")
	conds := "kind=1&" + until(time.Hour)
	sig, err := SignAttestation(priv, sub, conds)
	if err != nil {
		t.Fatal(err)
	}
	if err := nipOA.VerifySignature(pub, sub, conds, sig); err != nil {
		t.Fatal(err)
	}
	tag := AuthTag(pub, conds, sig)
	ev := &nip01.Event{Kind: 1, CreatedAt: uint64(t0.Unix()), Tags: [][]string{tag}}
	got, err := nipOA.ParseAuthTag(ev.Tags, sub)
	if err != nil || got.OwnerPubkey != pub {
		t.Fatalf("ParseAuthTag = %+v, %v", got, err)
	}
	for name, c := range map[string][2]string{
		"itself":     {pub, conds},
		"bad conds":  {sub, "kind=x"},
		"upper hex":  {strings.ToUpper(sub), conds},
		"not a key":  {"zz" + sub[2:], conds},
		"short hex":  {sub[:10], conds},
		"event json": {sub, `["EVENT"]`},
	} {
		if _, err := SignAttestation(priv, c[0], c[1]); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestAttestationConditions(t *testing.T) {
	u := time.Unix(1_900_000_000, 0)
	for _, c := range []struct {
		kinds []int
		until time.Time
		want  string
	}{
		{nil, time.Time{}, ""},
		{nil, u, "created_at<1900000000"},
		{[]int{1}, u, "kind=1&created_at<1900000000"},
		{[]int{7}, time.Time{}, "kind=7"},
	} {
		got := AttestationConditions(c.kinds, c.until)
		if got != c.want {
			t.Errorf("AttestationConditions(%v, %v) = %q, want %q", c.kinds, c.until, got, c.want)
		}
		if _, err := nipOA.ParseConditions(got); err != nil {
			t.Errorf("%q doesn't parse: %v", got, err)
		}
	}
}

func TestParseLongDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "1d": 24 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := ParseLongDuration(in); err != nil || got != want {
			t.Errorf("%s = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0d", "-1d", "1.5d", "d", "0s", "-1h", "9999d", "x"} {
		if _, err := ParseLongDuration(in); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
}

func TestServerAttest(t *testing.T) {
	priv, pub := testKey(t, "signer")
	_, sub := testKey(t, "sub")
	_, other := testKey(t, "other")
	clock := &fakeClock{}
	clock.set(time.Now())
	path := writePolicy(t, `kind: signer-policy
rules:
  - name: notes
    allow: {kinds: [1]}
  - name: attest-sub
    allow: {attest: {subordinates: [%s], max_until: 30d}}
    rate: 2/h
  - name: everything-else
    deny: {}
`, sub)
	r := startServer(t, Config{PrivKeyHex: priv, PolicyPath: path, Now: clock.now})
	c := dial(t, r.uri)
	ctx := ctx5(t)
	conds := "created_at<" + strconv.FormatInt(clock.now().Add(24*time.Hour).Unix(), 10)

	sig, err := c.Call(ctx, MethodAttest, sub, conds)
	if err != nil {
		t.Fatal(err)
	}
	if err := nipOA.VerifySignature(pub, sub, conds, sig); err != nil {
		t.Fatalf("signer's attestation: %v", err)
	}

	// Another key: denied by the policy, as a denial.
	if _, err := c.Call(ctx, MethodAttest, other, conds); !errors.Is(err, nipLS.ErrDenied) {
		t.Errorf("other key: %v, want denied", err)
	}
	// Malformed params: invalid, never signed.
	for _, params := range [][]string{{sub}, {sub, conds, "x"}, {}} {
		if _, err := c.Call(ctx, MethodAttest, params...); err == nil {
			t.Errorf("params %q: signed", params)
		}
	}
	// The rule's rate: one more allowed, then refused.
	if _, err := c.Call(ctx, MethodAttest, sub, conds); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(ctx, MethodAttest, sub, conds); err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("third attestation in an hour: %v, want rate limited", err)
	}

	recs := r.decisions.records(t)
	var allows, denies int
	for _, rec := range recs {
		if rec.Method != MethodAttest {
			t.Errorf("record method %q", rec.Method)
		}
		switch rec.Decision {
		case "allow":
			allows++
			if rec.Rule != "attest-sub" || rec.Subordinate != sub || rec.Conditions != conds {
				t.Errorf("allow record %+v", rec)
			}
		case "deny":
			denies++
		}
	}
	if allows != 2 || denies != 5 {
		t.Errorf("records: %d allows, %d denies, want 2 and 5:\n%s", allows, denies, r.decisions.String())
	}
	if strings.Contains(r.decisions.String(), sig) {
		t.Error("the decision log holds a signature")
	}
}

// The attestation method signs NIP-OA's preimage only, never a digest the
// caller picks: handed an event's id as the "subordinate", its signature
// covers sha256("nostr:agent-auth:" + id + ":" + conditions), and can't be
// passed off as the event's signature.
func TestServerAttestNeverSignsAnEventID(t *testing.T) {
	priv, pub := testKey(t, "signer")
	path := writePolicy(t, `kind: signer-policy
rules:
  - name: attest-any
    allow: {attest: {subordinates: ["*"], max_until: 30d}}
`)
	r := startServer(t, Config{PrivKeyHex: priv, PolicyPath: path})
	c := dial(t, r.uri)
	ctx := ctx5(t)

	ev := &nip01.Event{PubKey: pub, Kind: 1, CreatedAt: uint64(time.Now().Unix()), Tags: [][]string{}, Content: "not signed by policy"}
	id, err := ev.HashID()
	if err != nil {
		t.Fatal(err)
	}
	ev.ID = hex.EncodeToString(id)

	// The event's id is 64 hex: it may pass as a subordinate key...
	conds := "created_at<" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	sig, err := c.Call(ctx, MethodAttest, ev.ID, conds)
	if err != nil {
		// ...or be refused as not a point on the curve: either way nothing
		// usable comes back.
		t.Logf("refused: %v", err)
		return
	}
	ev.Sig = sig
	if ev.Verify() == nil {
		t.Fatal("an attestation's signature verified as an event's")
	}
	digest := sha256.Sum256(nipOA.Preimage(ev.ID, conds))
	if hex.EncodeToString(digest[:]) == ev.ID {
		t.Fatal("preimage digest equals the event id")
	}
	// sign_event itself is refused: no rule allows any event.
	if err := c.Sign(ctx, &nip01.Event{Kind: 1, CreatedAt: uint64(time.Now().Unix()), Tags: [][]string{}}); !errors.Is(err, nipLS.ErrDenied) {
		t.Errorf("sign_event under an attest-only policy: %v", err)
	}
	// No method signs a raw digest.
	for _, m := range []string{"sign", "sign_digest", "sign_hash", "schnorr_sign"} {
		if _, err := c.Call(ctx, m, ev.ID); err == nil {
			t.Errorf("method %s answered", m)
		}
	}
}
