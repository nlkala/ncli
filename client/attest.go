package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/ncli/signer"
	"github.com/ohstr/nmilat/nipLS"
	"github.com/ohstr/nmilat/nipOA"
)

// Attester signs NIP-OA attestations: a LocalSigner does it itself.
type Attester interface {
	Attest(ctx context.Context, subordinate, conditions string) (string, error)
}

var _ Attester = (*LocalSigner)(nil)

// Attest signs a NIP-OA attestation for subordinate (hex) under conditions.
func (s *LocalSigner) Attest(_ context.Context, subordinate, conditions string) (string, error) {
	return signer.SignAttestation(s.priv, subordinate, conditions)
}

// ErrCannotAttest is returned for a signer with no attestation method (a
// NIP-46 bunker).
var ErrCannotAttest = errors.New("this signer can't sign NIP-OA attestations: use a vault identity or a bunker+unix:// socket signer")

// SignAttestationWith signs a NIP-OA attestation through sgn -- a key held
// here, or a socket signer by its nipoa_attest method, whose policy decides
// -- and returns the auth tag ["auth", attester, conditions, sig]. The
// signature is verified before it is returned.
func SignAttestationWith(ctx context.Context, sgn Signer, subordinate, conditions string) ([]string, error) {
	var (
		sig string
		err error
	)
	switch v := sgn.(type) {
	case Attester:
		sig, err = v.Attest(ctx, subordinate, conditions)
	case *nipLS.Client:
		sig, err = v.Call(ctx, signer.MethodAttest, subordinate, conditions)
	default:
		return nil, ErrCannotAttest
	}
	if err != nil {
		return nil, err
	}
	if err := nipOA.VerifySignature(sgn.PubKey(), subordinate, conditions, sig); err != nil {
		return nil, fmt.Errorf("the signer's attestation does not verify: %w", err)
	}
	return signer.AuthTag(sgn.PubKey(), conditions, sig), nil
}
