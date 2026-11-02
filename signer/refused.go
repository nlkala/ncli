package signer

import (
	"crypto/sha256"
	"errors"
	"strings"
	"sync"

	"github.com/ohstr/nmilat/nipLS"
)

// RateLimitReason is the reason a request refused by its rule's rate
// carries. A caller retries such a request later; any other denial is final.
const RateLimitReason = "rate limit exceeded"

// RateLimited reports whether err is the signer refusing a request for its
// rule's rate, rather than for what the request is.
func RateLimited(err error) bool {
	var e *nipLS.Error
	if !errors.As(err, &e) {
		return false
	}
	return errors.Is(e, nipLS.ErrDenied) && strings.HasSuffix(e.Reason, RateLimitReason)
}

// refusedWraps remembers the gift wraps an unwrap_from rule refused (not
// addressed to the signer, not a seal, or sealed by a sender the rule does
// not list), so the same wrap asked again is refused before any decryption.
// A refusal depends only on the wrap and the policy, so the memory is
// dropped when the policy changes. It holds at most refusedWrapsMax wraps,
// the oldest forgotten first.
type refusedWraps struct {
	mu     sync.Mutex
	policy *Policy
	seen   map[[32]byte]bool
	order  [][32]byte
}

const refusedWrapsMax = 4096

func wrapKey(counterpart, ciphertext string) [32]byte {
	return sha256.Sum256([]byte(strings.ToLower(counterpart) + "\n" + ciphertext))
}

func (r *refusedWraps) has(p *Policy, k [32]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.policy == p && r.seen[k]
}

func (r *refusedWraps) add(p *Policy, k [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.policy != p || r.seen == nil {
		r.policy, r.seen, r.order = p, map[[32]byte]bool{}, nil
	}
	if r.seen[k] {
		return
	}
	if len(r.order) >= refusedWrapsMax {
		delete(r.seen, r.order[0])
		r.order = r.order[1:]
	}
	r.seen[k] = true
	r.order = append(r.order, k)
}
