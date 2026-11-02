package ncli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/ncli/cli/common"
	"github.com/ohstr/ncli/cli/keyresolve"
	"github.com/ohstr/ncli/client"
	"github.com/ohstr/ncli/signer"
	"github.com/spf13/cobra"
)

var attestCmd = &cobra.Command{
	Use:   "attest <subordinate npub|hex>",
	Short: "Sign a NIP-OA attestation for a subordinate key",
	Long: `Sign a NIP-OA owner attestation: the tag ["auth", <attester>, <conditions>,
<sig>] by which this identity vouches for a subordinate key. It is printed as
JSON; the subordinate carries it, and a verifier checks it with the attester's
key.

The conditions are built from the flags, in this order: kind=N for --kind,
then created_at<T for --until (RFC 3339 or unix seconds). Without
--until the attestation never ends; a socket signer's policy refuses that.

--signer takes a bunker+unix:///path/to.sock URI (an "ncli signer serve"
socket: its policy decides, by an attest rule, which keys it may attest and
for how long; a denial exits 7) or an identity like --identity. The signature
covers NIP-OA's preimage (a domain separator, the subordinate key and the
conditions), never an event.`,
	Example: `  ncli id attest npub1... --until 2026-12-01T00:00:00Z --identity alice
  ncli id attest 3bf0c63f... --until 1795000000 --kind 1 --signer bunker+unix:///run/signer/agent.sock`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return common.InvocationOrHelp(cmd, args, fmt.Errorf("accepts 1 arg (the subordinate's npub or hex pubkey), received %d", len(args)))
		}
		identity, _ := cmd.Flags().GetString("identity")
		signerFlag, _ := cmd.Flags().GetString("signer")
		switch {
		case identity == "" && signerFlag == "":
			return common.InvocationOrHelp(cmd, args, errors.New(`required flag(s) "identity" or "signer" not set`))
		case identity != "" && signerFlag != "":
			return common.InvocationError(cmd, errors.New("use --identity or --signer, not both"))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonMode, _ := cmd.Flags().GetBool("json")
		sub, err := signer.ParsePubkey(args[0])
		if err != nil {
			return common.InvalidInputError(cmd, args[0], err)
		}
		untilFlag, _ := cmd.Flags().GetString("until")
		var until time.Time
		if untilFlag != "" {
			if until, err = ParseUntil(untilFlag); err != nil {
				return common.InvalidInputError(cmd, untilFlag, err)
			}
			if !until.After(time.Now()) {
				return common.InvalidInputError(cmd, untilFlag, errors.New("--until is in the past"))
			}
		}
		var kinds []int
		if cmd.Flags().Changed("kind") {
			k, _ := cmd.Flags().GetInt("kind")
			if k < 0 || k > 65535 {
				return common.InvalidInputError(cmd, strconv.Itoa(k), errors.New("--kind must be 0-65535"))
			}
			kinds = []int{k}
		}
		conditions := signer.AttestationConditions(kinds, until)

		identity, _ := cmd.Flags().GetString("identity")
		if s, _ := cmd.Flags().GetString("signer"); s != "" {
			identity = s
		}
		sgn, closeSigner, err := keyresolve.ResolveSigner(cmd, jsonMode, identity)
		if err != nil {
			return err
		}
		defer closeSigner()
		if strings.EqualFold(sgn.PubKey(), sub) {
			return common.InvalidInputError(cmd, args[0], errors.New("a key can't attest itself"))
		}

		tag, err := client.SignAttestationWith(cmd.Context(), sgn, sub, conditions)
		if errors.Is(err, client.ErrCannotAttest) {
			return common.InvocationError(cmd, err)
		}
		if err != nil {
			return keyresolve.SignerError(cmd, args[0], fmt.Errorf("attest: %w", err))
		}

		if jsonMode {
			common.PrintJSON(map[string]any{
				"tag":         tag,
				"attester":    sgn.PubKey(),
				"subordinate": sub,
				"conditions":  conditions,
			})
			return nil
		}
		// Unescaped: the conditions' "<" stays "<", as NIP-OA writes it.
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetEscapeHTML(false)
		if err := enc.Encode(tag); err != nil {
			return common.RuntimeError(cmd, err)
		}
		return nil
	},
}

// ParseUntil reads a time as unix seconds or RFC 3339.
func ParseUntil(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n <= 0 || n > 4294967295 {
			return time.Time{}, fmt.Errorf("unix time %d out of range", n)
		}
		return time.Unix(n, 0), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("want RFC 3339 (2026-12-01T00:00:00Z) or unix seconds, got %q", s)
	}
	if t.Unix() <= 0 || t.Unix() > 4294967295 {
		return time.Time{}, fmt.Errorf("time %s out of range", s)
	}
	return t, nil
}

func init() {
	idCmd.AddCommand(attestCmd)
	attestCmd.Flags().String("identity", "", "Vault label/nsec identity to attest with")
	attestCmd.Flags().String("signer", "", "Attest through a socket signer (bunker+unix:///path/to.sock) instead of --identity")
	attestCmd.Flags().String("until", "", "End of the attestation: created_at< bound, RFC 3339 or unix seconds")
	attestCmd.Flags().Int("kind", 0, "Restrict the subordinate to this one event kind (a kind= clause)")
}
