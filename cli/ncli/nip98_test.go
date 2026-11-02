package ncli

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
)

func TestNIP98Command(t *testing.T) {
	priv, pub := hexKey(t, "client")
	nsec, _ := nip19.EncodePrivateKey(priv)
	dir := t.TempDir()
	payload := filepath.Join(dir, "body.json")
	_ = os.WriteFile(payload, []byte(`{"a":1}`), 0o600)

	decode := func(t *testing.T, out string) *nip01.Event {
		t.Helper()
		v, ok := strings.CutPrefix(strings.TrimSpace(out), "Authorization: Nostr ")
		if !ok {
			t.Fatalf("output %q", out)
		}
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		var ev nip01.Event
		if err := json.Unmarshal(raw, &ev); err != nil || ev.Verify(nip01.WithoutPowCheck()) != nil || ev.PubKey != pub || ev.Kind != 27235 {
			t.Fatalf("event %s: %v", raw, err)
		}
		return &ev
	}
	tagOf := func(ev *nip01.Event, name string) string {
		for _, tg := range ev.Tags {
			if tg[0] == name {
				return tg[1]
			}
		}
		return ""
	}

	out, err := runRoot(t, nip98Cmd, "nip98", "https://api.example.org/login", "post", "--payload-file", payload, "--identity", nsec)
	if err != nil {
		t.Fatalf("nip98: %v\n%s", err, out)
	}
	ev := decode(t, out)
	if tagOf(ev, "u") != "https://api.example.org/login" || tagOf(ev, "method") != "POST" || tagOf(ev, "payload") != sha256Hex([]byte(`{"a":1}`)) {
		t.Errorf("tags %q", ev.Tags)
	}
	out, err = runRoot(t, nip98Cmd, "nip98", "https://api.example.org/x", "GET", "--identity", nsec, "--value")
	if err != nil || !strings.HasPrefix(out, "Nostr ") {
		t.Errorf("--value: %q, %v", out, err)
	}

	uri := startAttestSigner(t, priv, mustOtherKey(t))
	if out, err = runRoot(t, nip98Cmd, "nip98", "https://api.example.org/login", "POST", "--signer", uri); err != nil {
		t.Errorf("socket, allowed URL: %v\n%s", err, out)
	} else if tagOf(decode(t, out), "payload") != "" {
		t.Error("payload tag without --payload-file")
	}
	if out, err = runRoot(t, nip98Cmd, "nip98", "https://elsewhere.example/login", "POST", "--signer", uri); err == nil {
		t.Errorf("socket, other URL: signed %s", out)
	}
	for name, args := range map[string][]string{
		"no scheme":  {"nip98", "api.example.org/x", "GET", "--identity", nsec},
		"bad method": {"nip98", "https://api.example.org/x", "FETCH", "--identity", nsec},
		"one arg":    {"nip98", "https://api.example.org/x", "--identity", nsec},
		"no file":    {"nip98", "https://api.example.org/x", "POST", "--payload-file", filepath.Join(dir, "missing"), "--identity", nsec},
	} {
		if out, err := runRoot(t, nip98Cmd, args...); err == nil {
			t.Errorf("%s: ran: %s", name, out)
		}
	}
}

func mustOtherKey(t *testing.T) string {
	_, pub := hexKey(t, "someone")
	return pub
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
