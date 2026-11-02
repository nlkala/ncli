package climatrix

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nip98auth "github.com/ohstr/nmilat/nip98"
)

func TestNIP98(t *testing.T) {
	e := NewEnv(t)
	alice := A(t, "alice")
	body := e.WriteFile("body.json", `{"x":1}`)

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := []byte(`{"x":1}`)
		pub, err := nip98auth.Verify(r, nip98auth.Options{AllowedPubkeys: []string{alice.PubHex}, Body: b, RequirePayload: true})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		got = pub
	}))
	defer srv.Close()

	var res struct {
		Value string `json:"value"`
	}
	e.MustOK(t, "nip98", srv.URL+"/x", "POST", "--payload-file", body, "--identity", alice.Nsec, "--json").JSON(t, &res)
	req, _ := http.NewRequest("POST", srv.URL+"/x", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", res.Value)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || got != alice.PubHex {
		t.Fatalf("server answered %d", resp.StatusCode)
	}
	text := e.MustOK(t, "nip98", srv.URL+"/x", "GET", "--identity", alice.Nsec)
	if !strings.HasPrefix(text.Stdout, "Authorization: Nostr ") {
		t.Errorf("text output %q", text.Stdout)
	}
	e.Run(t, "nip98", "not-a-url", "GET", "--identity", alice.Nsec, "--json").ExpectErr(t, "invalid_input")
	e.Run(t, "nip98", srv.URL, "--identity", alice.Nsec, "--json").ExpectErr(t, "usage")
}
