package social

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ohstr/ncli/cli/common"
	"github.com/ohstr/ncli/client"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipOA"
)

// AuthFlagHelp describes --auth the same way everywhere.
const AuthFlagHelp = `A NIP-OA "auth" tag to attach to every event this command signs, as JSON: ["auth","<owner hex>","<conditions>","<sig>"]; also NCLI_AUTH_TAG`

// Kinds an auth tag never goes on: a seal and a gift wrap carry no tags of
// their own (NIP-59), the rumor inside them does; and a NIP-42 client-auth
// login event's tags are fixed and relay-checked (client.signLogin), so an
// appended tag is rejected as tampering.
const (
	kindSeal       = 13
	kindGiftWrap   = 1059
	kindClientAuth = nip42.KindClientAuth // 22242
)

// AuthTag reads --auth, else NCLI_AUTH_TAG: a NIP-OA auth tag for signerPub
// (the key that signs), checked before it is used: four elements, a valid
// owner key that isn't signerPub, conditions in NIP-OA's grammar and the
// owner's signature over them. nil when neither is set.
func AuthTag(cmd *cobra.Command, signerPub string) ([]string, error) {
	value, from := "", "--auth"
	if f := cmd.Flags().Lookup("auth"); f != nil {
		value = f.Value.String()
	}
	if value == "" {
		value, from = viper.GetString("auth_tag"), "NCLI_AUTH_TAG"
	}
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var tag []string
	if err := json.Unmarshal([]byte(value), &tag); err != nil {
		return nil, common.InvalidInputError(cmd, from, fmt.Errorf("%s: not a JSON array of strings: %w", from, err))
	}
	if len(tag) == 0 || tag[0] != nipOA.TagName {
		return nil, common.InvalidInputError(cmd, from, fmt.Errorf(`%s: not an "auth" tag`, from))
	}
	if _, err := nipOA.ParseAuthTag([][]string{tag}, strings.ToLower(signerPub)); err != nil {
		return nil, common.InvalidInputError(cmd, from, fmt.Errorf("%s: no valid attestation of this signer's key: %w", from, err))
	}
	return tag, nil
}

// authSigner signs as its inner signer, after adding its auth tag to every
// event the attestation's conditions allow (kind=, created_at bounds) that
// has none, seals, gift wraps and login events aside.
type authSigner struct {
	client.Crypto
	tag  []string
	cond nipOA.Conditions
}

// authKeySigner is an authSigner whose inner signer can itself derive NIP-44
// message keys. WithAuth returns it only then, so a signer that cannot (e.g.
// a bunker) stays a non-MessageKeyer and the capability guard in a proof
// (cli/dm/prove.go) still catches it, rather than failing late at use.
type authKeySigner struct {
	*authSigner
	keyer client.MessageKeyer
}

// WithAuth wraps signer so the events it signs carry tag (AuthTag's).
// A nil tag returns signer as it is.
func WithAuth(signer client.Crypto, tag []string) client.Crypto {
	if tag == nil {
		return signer
	}
	cond, _ := nipOA.ParseConditions(tag[2]) // AuthTag checked it
	s := &authSigner{Crypto: signer, tag: tag, cond: cond}
	if k, ok := signer.(client.MessageKeyer); ok {
		return &authKeySigner{authSigner: s, keyer: k}
	}
	return s
}

func (s *authSigner) Sign(ctx context.Context, ev *nip01.Event) error {
	if ev.Kind != kindSeal && ev.Kind != kindGiftWrap && ev.Kind != kindClientAuth {
		addAuth(ev, s.tag, s.cond)
	}
	return s.Crypto.Sign(ctx, ev)
}

// MessageKeys passes through to the inner signer, which WithAuth confirmed
// can derive them.
func (s *authKeySigner) MessageKeys(ctx context.Context, peerPubKey, payload string) (nip44.Keys, error) {
	return s.keyer.MessageKeys(ctx, peerPubKey, payload)
}

// AddAuth adds signer's auth tag (WithAuth's) to rumor, an unsigned event
// a seal will carry (a NIP-17 message, a private form), when its kind and
// time meet the attestation's conditions and it has none. Call it once
// the rumor's kind, tags and created_at are final, before sealing.
func AddAuth(signer client.Signer, rumor *nip01.Event) {
	switch s := signer.(type) {
	case *authKeySigner:
		addAuth(rumor, s.tag, s.cond)
	case *authSigner:
		addAuth(rumor, s.tag, s.cond)
	}
}

func addAuth(ev *nip01.Event, tag []string, cond nipOA.Conditions) {
	for _, t := range ev.Tags {
		if len(t) > 0 && t[0] == nipOA.TagName {
			return
		}
	}
	if !cond.EvaluateKind(ev.Kind) || !cond.EvaluateTimeClauses(ev.CreatedAt) {
		return
	}
	ev.Tags = append(ev.Tags, append([]string(nil), tag...))
}
