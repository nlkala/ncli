package ncli

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/ohstr/ncli/cli/common"
	"github.com/ohstr/ncli/cli/keyresolve"
	"github.com/ohstr/nmilat/nip98"
	"github.com/spf13/cobra"
)

var nip98Cmd = &cobra.Command{
	Use:   "nip98 <url> <method>",
	Short: "Print a NIP-98 Authorization header for an HTTP request",
	Long: `Sign a NIP-98 HTTP Auth event (kind 27235) for one request and print the
header that carries it: "Authorization: Nostr <base64 event>". It is good for
that exact URL and method, for about a minute (the server's window).

--payload-file binds the header to the request's body: its SHA-256 goes in
the payload tag, and a server that checks it refuses any other body ("-" reads
stdin; /dev/null binds an empty body). Without it the header has no payload
tag.

--signer takes a bunker+unix:///path/to.sock URI (an "ncli signer serve"
socket, whose policy decides which URLs it signs for) or an identity like
--identity. --value prints the header's value alone.`,
	Example: `  curl -H "$(ncli nip98 https://example.com/api GET --identity me)" https://example.com/api
  ncli nip98 https://example.com/upload POST --payload-file body.json --signer bunker+unix:///run/signer/agent.sock`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return common.InvocationOrHelp(cmd, args, fmt.Errorf("accepts 2 args (url, method), received %d", len(args)))
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
		rawURL, method := args[0], strings.ToUpper(args[1])
		u, err := url.Parse(rawURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return common.InvalidInputError(cmd, rawURL, errors.New("want an absolute http(s) URL"))
		}
		if !validHTTPMethod(method) {
			return common.InvalidInputError(cmd, args[1], errors.New("want an HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)"))
		}

		var body []byte
		if path, _ := cmd.Flags().GetString("payload-file"); path != "" {
			if path == "-" {
				body, err = io.ReadAll(cmd.InOrStdin())
			} else {
				body, err = os.ReadFile(path)
			}
			if err != nil {
				return common.InvalidInputError(cmd, path, err)
			}
			if body == nil {
				body = []byte{}
			}
		}

		identity, _ := cmd.Flags().GetString("identity")
		if s, _ := cmd.Flags().GetString("signer"); s != "" {
			identity = s
		}
		sgn, closeSigner, err := keyresolve.ResolveSigner(cmd, jsonMode, identity)
		if err != nil {
			return err
		}
		defer closeSigner()

		header, err := nip98.Sign(cmd.Context(), sgn, rawURL, method, body)
		if err != nil {
			return keyresolve.SignerError(cmd, rawURL, err)
		}
		if jsonMode {
			common.PrintJSON(map[string]any{"header": "Authorization", "value": header, "pubkey": sgn.PubKey()})
			return nil
		}
		if v, _ := cmd.Flags().GetBool("value"); v {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), header)
			return nil
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Authorization: "+header)
		return nil
	},
}

func validHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func init() {
	RootCmd.AddCommand(nip98Cmd)
	nip98Cmd.Flags().String("identity", "", "Vault label/nsec identity to sign with")
	nip98Cmd.Flags().String("signer", "", "Sign through a socket signer (bunker+unix:///path/to.sock) instead of --identity")
	nip98Cmd.Flags().String("payload-file", "", `Bind the header to this request body (its SHA-256 in the payload tag); "-" for stdin`)
	nip98Cmd.Flags().Bool("value", false, "Print only the header's value (Nostr <base64>)")
}
