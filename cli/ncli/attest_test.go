package ncli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/ncli/signer"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nipLS"
	"github.com/ohstr/nmilat/nipOA"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// runRoot runs ncli in-process with args, every flag of sub reset first
// (cobra keeps flag values between runs), and returns its output.
func runRoot(t *testing.T, sub *cobra.Command, args ...string) (string, error) {
	t.Helper()
	sub.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	var out bytes.Buffer
	RootCmd.SetOut(&out)
	RootCmd.SetErr(&out)
	RootCmd.SetArgs(args)
	RootCmd.SilenceUsage, RootCmd.SilenceErrors = true, true
	t.Cleanup(func() { RootCmd.SetOut(nil); RootCmd.SetErr(nil); RootCmd.SetArgs(nil) })
	err := RootCmd.ExecuteContext(context.Background())
	return out.String(), err
}

// startAttestSigner runs a policy signer that may attest sub only, for
// up to a day, and sign NIP-98 for https://api.example.org/* only.
func startAttestSigner(t *testing.T, priv, sub string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	policy := filepath.Join(dir, "policy.yaml")
	body := "kind: signer-policy\nrules:\n  - name: attest-sub\n    allow: {attest: {subordinates: [" + sub + "], max_until: 1d}}\n" +
		"  - name: http-logins\n    allow: {kinds: [27235], tags: {u: [\"https://api.example.org/*\"]}}\n  - name: everything-else\n    deny: {}\n"
	if err := os.WriteFile(policy, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := signer.New(signer.Config{PrivKeyHex: priv, PolicyPath: policy})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	l, err := nipLS.Listen(sock, nipLS.ListenOptions{Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done; _ = srv.Close() })
	return nipLS.FormatURI(sock)
}

func TestAttestCommand(t *testing.T) {
	priv, pub := hexKey(t, "attester")
	_, sub := hexKey(t, "subordinate")
	_, stranger := hexKey(t, "stranger")
	nsec, _ := nip19.EncodePrivateKey(priv)
	subNpub, _ := nip19.EncodePublicKey(sub)
	until := time.Now().Add(12 * time.Hour).Unix()
	untilS := strconv.FormatInt(until, 10)

	out, err := runRoot(t, attestCmd, "id", "attest", subNpub, "--until", untilS, "--kind", "1", "--identity", nsec)
	if err != nil {
		t.Fatalf("attest: %v\n%s", err, out)
	}
	var tag []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &tag); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	wantConds := "kind=1&created_at<" + untilS
	if len(tag) != 4 || tag[0] != "auth" || tag[1] != pub || tag[2] != wantConds {
		t.Fatalf("tag %q", tag)
	}
	if err := nipOA.VerifySignature(pub, sub, tag[2], tag[3]); err != nil {
		t.Fatal(err)
	}

	// RFC 3339 --until.
	rfc := time.Unix(until, 0).UTC().Format(time.RFC3339)
	if out, err = runRoot(t, attestCmd, "id", "attest", sub, "--until", rfc, "--identity", nsec); err != nil || !strings.Contains(out, "created_at<"+untilS) {
		t.Errorf("RFC 3339 --until: %q, %v", out, err)
	}

	// Through the socket signer: allowed for sub within a day...
	uri := startAttestSigner(t, priv, sub)
	if out, err = runRoot(t, attestCmd, "id", "attest", sub, "--until", untilS, "--signer", uri); err != nil || !strings.Contains(out, pub) {
		t.Errorf("socket attest: %q, %v", out, err)
	}
	// ...not for another key, not for longer, not without an end.
	for name, args := range map[string][]string{
		"stranger":  {"id", "attest", stranger, "--until", untilS, "--signer", uri},
		"two days":  {"id", "attest", sub, "--until", strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10), "--signer", uri},
		"no –until": {"id", "attest", sub, "--signer", uri},
	} {
		if out, err := runRoot(t, attestCmd, args...); err == nil {
			t.Errorf("%s: attested: %s", name, out)
		}
	}
	// Invocation errors.
	for name, args := range map[string][]string{
		"itself":     {"id", "attest", pub, "--until", untilS, "--identity", nsec},
		"past":       {"id", "attest", sub, "--until", "1000", "--identity", nsec},
		"bad until":  {"id", "attest", sub, "--until", "tomorrow", "--identity", nsec},
		"bad key":    {"id", "attest", "npub1nope", "--identity", nsec},
		"no signer":  {"id", "attest", sub},
		"both":       {"id", "attest", sub, "--identity", nsec, "--signer", uri},
		"kind range": {"id", "attest", sub, "--kind", "70000", "--identity", nsec},
	} {
		if out, err := runRoot(t, attestCmd, args...); err == nil {
			t.Errorf("%s: ran: %s", name, out)
		}
	}
}
