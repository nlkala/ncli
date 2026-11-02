package signer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nipOA"
	"github.com/ohstr/nmilat/utils"
)

// MethodAttest is nmilat's nipOA.MethodSignAttestation, a signer method
// outside NIP-46's set (nmilat's nipOA.RemoteSigner calls it, nipLS's
// AttestationMethod serves it): sign a NIP-OA attestation ("auth" tag) for
// a subordinate key. Its params are the
// subordinate's pubkey (64 lowercase hex) and the conditions string; the
// result is the attestation's signature (hex).
//
// The method never signs a digest it is handed: the signer builds the
// preimage itself from the subordinate key and the parsed conditions, with
// NIP-OA's domain separator, so it can't be talked into signing an event id
// or any other protocol's message.
const MethodAttest = nipOA.MethodSignAttestation // "nipoa_attest"

// LongDuration is a duration that may also be written in days ("30d").
type LongDuration time.Duration

func (d *LongDuration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30d\" or \"12h\"")
	}
	v, err := ParseLongDuration(s)
	if err != nil {
		return err
	}
	*d = LongDuration(v)
	return nil
}

func (d LongDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// ParseLongDuration parses a Go duration ("12h", "90m") or a whole number
// of days ("30d"). It must be positive.
func ParseLongDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	var v time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > 3660 {
			return 0, fmt.Errorf("duration %q: want a whole number of days from 1 to 3660", s)
		}
		v = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if v, err = time.ParseDuration(s); err != nil {
			return 0, err
		}
	}
	if v <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return v, nil
}

// AttestSelector picks NIP-OA attestation requests, and in an allow rule
// bounds what may be attested.
//
//	allow: {attest: {subordinates: [npub1..., "*"], max_until: 30d, kinds: [1]}}
//
// An attestation is signed only through a rule with an attest selector: a
// catch-all allow never covers one.
type AttestSelector struct {
	// Subordinates are the keys this signer may attest: npubs or hex, or
	// "*" for any key but its own.
	Subordinates []string `json:"subordinates"`
	// MaxUntil (allow rules, required) is how far ahead the attestation's
	// created_at< bound may reach; one without such a bound is refused.
	MaxUntil *LongDuration `json:"max_until,omitempty"`
	// Kinds (allow rules), when set, requires the conditions to restrict
	// the subordinate to these kinds: at least one kind= clause, every one
	// of them listed here.
	Kinds []int `json:"kinds,omitempty"`

	any  bool
	subs map[string]bool
}

func (a *AttestSelector) validate(allow bool) error {
	if len(a.Subordinates) == 0 {
		return errors.New("attest: subordinates must name at least one key, or \"*\"")
	}
	a.subs = map[string]bool{}
	for _, s := range a.Subordinates {
		if strings.TrimSpace(s) == "*" {
			a.any = true
			continue
		}
		k, err := ParsePubkey(s)
		if err != nil {
			return fmt.Errorf("attest: subordinates: %w", err)
		}
		a.subs[k] = true
	}
	if !allow {
		if a.MaxUntil != nil || len(a.Kinds) > 0 {
			return errors.New("attest: a deny rule takes subordinates only")
		}
		return nil
	}
	if a.MaxUntil == nil {
		return errors.New("attest: max_until is required: an attestation must end")
	}
	for _, k := range a.Kinds {
		if k < 0 || k > 65535 {
			return fmt.Errorf("attest: kind %d out of range", k)
		}
	}
	return nil
}

func (a *AttestSelector) matches(subordinate string) bool {
	return a.any || a.subs[subordinate]
}

// check reports why conds may not be attested under a, or "".
func (a *AttestSelector) check(conds nipOA.Conditions, now time.Time) string {
	if len(conds.CreatedAtLT) == 0 {
		return "conditions have no created_at< bound"
	}
	until := conds.CreatedAtLT[0]
	for _, t := range conds.CreatedAtLT[1:] {
		until = min(until, t)
	}
	if int64(until) <= now.Unix() {
		return "conditions' created_at< bound has already passed"
	}
	limit := now.Add(time.Duration(*a.MaxUntil))
	if int64(until) > limit.Unix() {
		return fmt.Sprintf("conditions' created_at< bound is beyond max_until (%s)", time.Duration(*a.MaxUntil))
	}
	if len(a.Kinds) > 0 {
		if len(conds.Kinds) == 0 {
			return "conditions have no kind= clause"
		}
		for _, k := range conds.Kinds {
			if !containsInt(a.Kinds, k) {
				return fmt.Sprintf("kind %d is not one the rule allows", k)
			}
		}
	}
	return ""
}

// parseAttestRequest checks the shape of an attestation request: the
// subordinate is exactly 64 lowercase hex (the preimage uses it byte for
// byte) and not the signer, and the conditions follow NIP-OA's grammar.
func parseAttestRequest(req *Request) (nipOA.Conditions, string) {
	sub := req.Subordinate
	if len(sub) != 64 || strings.ToLower(sub) != sub || utils.Validate32Key(sub) != nil {
		return nipOA.Conditions{}, "subordinate must be a 64-char lowercase hex pubkey"
	}
	if strings.EqualFold(sub, req.SignerPub) {
		return nipOA.Conditions{}, "a key can't attest itself"
	}
	conds, err := nipOA.ParseConditions(req.Conditions)
	if err != nil {
		return nipOA.Conditions{}, fmt.Sprintf("conditions: %v", err)
	}
	return conds, ""
}

// AttestationConditions builds a conditions string in a fixed order: one
// kind= clause per kind, then created_at< for until (unless zero).
func AttestationConditions(kinds []int, until time.Time) string {
	var parts []string
	for _, k := range kinds {
		parts = append(parts, "kind="+strconv.Itoa(k))
	}
	if !until.IsZero() {
		parts = append(parts, "created_at<"+strconv.FormatInt(until.Unix(), 10))
	}
	return strings.Join(parts, "&")
}

// SignAttestation signs a NIP-OA attestation by privKeyHex for subordinate
// (hex) under conditions, through nmilat's nipOA.Sign (a BIP-340 signature
// over SHA256(nipOA.Preimage(subordinate, conditions)), verified before it is
// returned). It checks its inputs as the signer's policy does first.
func SignAttestation(privKeyHex, subordinate, conditions string) (string, error) {
	k, err := nipOA.NewKeySigner(privKeyHex)
	if err != nil {
		return "", err
	}
	if _, reason := parseAttestRequest(&Request{Subordinate: subordinate, Conditions: conditions, SignerPub: k.PubKey()}); reason != "" {
		return "", errors.New(reason)
	}
	tag, err := nipOA.Sign(context.Background(), k, subordinate, conditions)
	if err != nil {
		return "", err
	}
	return tag[3], nil
}

// AuthTag is the NIP-OA tag ["auth", attester, conditions, sig].
func AuthTag(attester, conditions, sig string) []string {
	return []string{nipOA.TagName, attester, conditions, sig}
}
