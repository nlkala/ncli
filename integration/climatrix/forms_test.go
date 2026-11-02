package climatrix

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// formSpec is the three-question example of skills/ncli-forms
// with these responders.
func formSpec(t *testing.T, e *Env, name string, responders ...string) string {
	t.Helper()
	rs, _ := json.Marshal(responders)
	return e.WriteFile(name, `{"title": "hello crash-loops since 14:02",
 "context": "deploy/hello crash-loops since main's commit 9c1e0f2 (14:02).",
 "responders": `+string(rs)+`,
 "quorum": 1,
 "endsAt": 4102444800,
 "questions": [
  {"text": "How do we fix hello?", "type": "singlechoice",
   "why": "The revert brings back what ran for 3 days, today.",
   "options": [
    {"id": "revert", "label": "Merge my revert PR", "rec": true},
    {"id": "forward", "label": "Fix forward in a new PR"},
    {"id": "other", "label": "Other (say what)", "noteRequired": true}]},
  {"text": "Raise hello's memory limit to (MiB)", "type": "number", "optional": true, "min": "256", "max": "2048"},
  {"text": "Deploy no later than", "type": "time", "optional": true}]}`)
}

type formSent struct {
	ID     string `json:"id"`
	Kind   int    `json:"kind"`
	Form   string `json:"form"`
	Where  string `json:"where"`
	Wraps  []struct{ To, ID string }
	Report struct {
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"report"`
}

type formView struct {
	Form struct {
		ID       string `json:"id"`
		Private  bool   `json:"private"`
		Group    string `json:"group"`
		ReadOnly bool   `json:"read_only"`
	} `json:"form"`
	Where      string `json:"where"`
	State      string `json:"state"`
	Role       string `json:"role"`
	CanRespond bool   `json:"can_respond"`
	Result     *struct {
		Status string `json:"status"`
	} `json:"result"`
	Responses []struct {
		Author  string `json:"author"`
		Choices []struct{ Option, Note string }
	} `json:"responses"`
	Tally struct {
		Responses int `json:"responses"`
		Questions []struct {
			Counts map[string]int `json:"counts"`
		} `json:"questions"`
	} `json:"tally"`
	Waiting []string `json:"waiting"`
}

// formsPolicy: the agent seals and opens with alice and itself, signs
// responses, and logs in to the relay.
func formsPolicy(t *testing.T, e *Env, relay string) string {
	t.Helper()
	agent, alice := A(t, "agent"), A(t, "alice")
	return e.WriteFile("forms-policy.yaml", fmt.Sprintf(`kind: signer-policy
rules:
  - name: seals
    allow: {kinds: [13]}
  - name: alice
    allow: {methods: [nip44_encrypt, nip44_decrypt], counterparts: [%[1]s, %[2]s]}
  - name: inbox
    allow: {unwrap_from: [%[1]s, %[2]s]}
  - name: forms
    allow: {kinds: [1019]}
  - name: relay-login
    allow: {kinds: [22242], tags: {relay: [%[3]s]}}
  - name: rest
    deny: {}
`, alice.Npub, agent.Npub, relay))
}

func TestForms_Private(t *testing.T) {
	needsRelay(t)
	r := StartRelay(t, "", nil)
	e := NewEnv(t)
	alice, bob, agent, mallory := A(t, "alice"), A(t, "bob"), A(t, "agent"), A(t, "mallory")
	s := startSigner(t, e, formsPolicy(t, e, r.URL))
	at := []string{"-s", r.URL, "--json"}
	form := func(args ...string) []string { return append(append([]string{"form"}, args...), at...) }

	// private to two p: one rumor, wrapped to each and to alice
	var sent formSent
	e.MustOK(t, form("create", "--spec", formSpec(t, e, "spec.json"), "--to", agent.Npub, "--to", bob.Npub, "--signer", alice.Nsec)...).JSON(t, &sent)
	if sent.Where != "private" || sent.Kind != 1069 || len(sent.Wraps) != 3 || sent.Report.Succeeded != 3 {
		t.Fatalf("sent %+v", sent)
	}

	t.Run("listed for the agent, through its signer", func(t *testing.T) {
		var vs []formView
		e.MustOK(t, form("list", "--open", "--signer", s.URI)...).JSON(t, &vs)
		if len(vs) != 1 || vs[0].Form.ID != sent.ID || !vs[0].Form.Private || vs[0].Role != "responder" || !vs[0].CanRespond {
			t.Fatalf("list %+v", vs)
		}
		var none []formView
		e.MustOK(t, form("list", "--signer", mallory.Nsec)...).JSON(t, &none)
		if len(none) != 0 {
			t.Fatalf("mallory lists %+v", none)
		}
	})

	t.Run("an invalid response is refused before sending", func(t *testing.T) {
		e.Run(t, form("respond", sent.ID[:10], "--choose", "other", "--signer", s.URI)...).ExpectErr(t, "invalid_input")
		e.Run(t, form("respond", sent.ID[:10], "--choose", "revert", "--answer", "1=4096", "--signer", s.URI)...).ExpectErr(t, "invalid_input")
		e.Run(t, form("respond", sent.ID[:10], "--choose", "revert,forward", "--signer", s.URI)...).ExpectErr(t, "invalid_input")
		e.Run(t, form("respond", sent.ID, "--choose", "revert", "--signer", mallory.Nsec)...).ExpectErr(t, "not_found")
		var v formView
		e.MustOK(t, form("show", sent.ID, "--signer", alice.Nsec)...).JSON(t, &v)
		if v.Tally.Responses != 0 {
			t.Fatalf("something was sent: %+v", v.Tally)
		}
	})

	t.Run("the agent answers by flags, bob on the terminal", func(t *testing.T) {
		var rs formSent
		e.MustOK(t, form("respond", sent.ID[:10], "--choose", "other", "--note", "other=roll the node back", "--answer", "1=512", "--signer", s.URI)...).JSON(t, &rs)
		if rs.Kind != 1019 || rs.Form != sent.ID || len(rs.Wraps) != 2 || rs.Report.Succeeded != 2 {
			t.Fatalf("response %+v", rs)
		}
		res := e.RunStdin(t, "revert\nafter lunch\n\n\ny\n", "form", "respond", sent.ID[:10], "-s", r.URL, "--signer", bob.Nsec)
		if res.Code != 0 || !strings.Contains(res.Stderr, "— recommended") || !strings.Contains(res.Stderr, "why recommended: The revert") {
			t.Fatalf("interactive\n%s", res)
		}
	})

	t.Run("the author sees both; closes it", func(t *testing.T) {
		var v formView
		e.MustOK(t, form("show", sent.ID[:8], "--signer", alice.Nsec)...).JSON(t, &v)
		if v.Tally.Responses != 2 || v.Tally.Questions[0].Counts["other"] != 1 || v.Tally.Questions[0].Counts["revert"] != 1 || len(v.Waiting) != 0 {
			t.Fatalf("alice's view %+v", v)
		}
		text := e.MustOK(t, "form", "show", sent.ID[:8], "-s", r.URL, "--signer", alice.Nsec).Stdout
		for _, want := range []string{"[recommended]", "[note required]", "roll the node back", "after lunch", "512"} {
			if !strings.Contains(text, want) {
				t.Errorf("show lacks %q\n%s", want, text)
			}
		}
		e.Run(t, form("result", sent.ID, "--status", "decided", "--choose", "revert", "--signer", bob.Nsec)...).ExpectErr(t, "auth")
		var rs formSent
		e.MustOK(t, form("result", sent.ID, "--status", "decided", "--choose", "revert", "--content", "reverted", "--signer", alice.Nsec)...).JSON(t, &rs)
		if rs.Kind != 1070 || len(rs.Wraps) != 3 {
			t.Fatalf("result %+v", rs)
		}
		var vs []formView
		e.MustOK(t, form("list", "--state", "decided", "--signer", bob.Nsec)...).JSON(t, &vs)
		if len(vs) != 1 || vs[0].Result == nil || vs[0].CanRespond {
			t.Fatalf("bob's decided %+v", vs)
		}
		e.Run(t, form("respond", sent.ID, "--choose", "forward", "--signer", bob.Nsec)...).ExpectErr(t, "conflict")
	})
}

func TestForms_GroupAndPublic(t *testing.T) {
	needsRelay(t)
	r := StartRelay(t, "", nil)
	e := NewEnv(t)
	alice, bob, carol := A(t, "alice"), A(t, "bob"), A(t, "carol")

	t.Run("group", func(t *testing.T) {
		g := func(args ...string) []string {
			return append(append([]string{"form"}, args...), "--group", "forms", "--relay", r.URL, "--json")
		}
		e.MustOK(t, "groups", "create", "forms", "--relay", r.URL, "--identity", alice.Nsec)
		e.MustOK(t, "groups", "members", "add", "forms", bob.Npub, "--relay", r.URL, "--identity", alice.Nsec)
		e.MustOK(t, "groups", "members", "add", "forms", carol.Npub, "--relay", r.URL, "--identity", alice.Nsec)
		var sent formSent
		e.MustOK(t, g("create", "--spec", formSpec(t, e, "group.json", bob.Npub, carol.Npub), "--signer", alice.Nsec)...).JSON(t, &sent)
		if sent.Where != "group" || sent.Report.Succeeded != 1 {
			t.Fatalf("sent %+v", sent)
		}
		e.MustOK(t, g("respond", sent.ID, "--choose", "forward", "--signer", bob.Nsec)...)
		e.MustOK(t, g("respond", sent.ID, "--choose", "revert", "--answer", "2=4102444000", "--signer", carol.Nsec)...)
		var v formView
		e.MustOK(t, g("show", sent.ID, "--signer", alice.Nsec)...).JSON(t, &v)
		if v.Where != "group" || v.Form.Group != "forms" || v.Tally.Responses != 2 {
			t.Fatalf("view %+v", v)
		}
		e.MustOK(t, g("withdraw", sent.ID, "--signer", bob.Nsec)...)
		e.MustOK(t, g("show", sent.ID, "--signer", alice.Nsec)...).JSON(t, &v)
		if v.Tally.Responses != 1 || !slices.Equal(v.Waiting, []string{bob.PubHex}) {
			t.Fatalf("after the withdrawal %+v", v)
		}
		var vs []formView
		e.MustOK(t, g("list", "--asked", "--signer", bob.Nsec)...).JSON(t, &vs)
		if len(vs) != 1 || vs[0].Form.ID != sent.ID {
			t.Fatalf("bob's asked %+v", vs)
		}
	})

	t.Run("public", func(t *testing.T) {
		at := []string{"-s", r.URL, "--json"}
		var sent formSent
		e.MustOK(t, append([]string{"form", "create", "--spec", formSpec(t, e, "public.json", bob.Npub)}, append(at, "--signer", alice.Nsec)...)...).JSON(t, &sent)
		if sent.Where != "public" {
			t.Fatalf("sent %+v", sent)
		}
		e.Run(t, append([]string{"form", "respond", sent.ID, "--choose", "revert", "--signer", carol.Nsec}, at...)...).ExpectErr(t, "auth")
		e.MustOK(t, append([]string{"form", "respond", sent.ID, "--choose", "revert", "--signer", bob.Nsec}, at...)...)
		var vs []formView
		e.MustOK(t, append([]string{"form", "list", "--signer", bob.Nsec}, at...)...).JSON(t, &vs)
		// the group's form names bob too, on the same relay: listed, as a group form
		i := slices.IndexFunc(vs, func(v formView) bool { return v.Form.ID == sent.ID })
		if len(vs) != 2 || i < 0 || vs[i].Where != "public" || vs[i].Tally.Responses != 1 {
			t.Fatalf("bob's list %+v", vs)
		}
		e.MustOK(t, append([]string{"form", "result", sent.ID, "--status", "cancelled", "--signer", alice.Nsec}, at...)...)
		out := e.MustOK(t, "form", "list", "-s", r.URL, "--signer", bob.Nsec).Stdout
		if !strings.Contains(out, "cancelled") || !strings.Contains(out, sent.ID[:12]) {
			t.Fatalf("text list\n%s", out)
		}
	})

	t.Run("read-only form", func(t *testing.T) {
		ev := nip01.NewEvent(1069, "Rate it")
		ev.Tags = [][]string{{"alt", "Form: Rate it"}, {"p", bob.PubHex}, {"question", "0", "How many stars?", "stars"}}
		ev.CreatedAt = 1793000000
		if err := ev.Sign(alice.PrivHex); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal([]*nip01.Event{ev})
		e.MustOK(t, "publish", "-e", e.WriteFile("ro.json", string(b)), "-s", r.URL)
		var v formView
		e.MustOK(t, "form", "show", ev.ID, "-s", r.URL, "--json", "--signer", bob.Nsec).JSON(t, &v)
		if !v.Form.ReadOnly || v.CanRespond {
			t.Fatalf("view %+v", v)
		}
		e.Run(t, "form", "respond", ev.ID, "--answer", "0=5", "-s", r.URL, "--json", "--signer", bob.Nsec).ExpectErr(t, "unsupported")
	})
}

func TestForms_Errors(t *testing.T) {
	e := NewEnv(t)
	alice := A(t, "alice")
	spec := formSpec(t, e, "spec.json")
	e.Run(t, "form", "--json").ExpectErr(t, "usage")
	e.Run(t, "form", "create", "--spec", spec, "--json", "--signer", alice.Nsec).ExpectErr(t, "usage")
	e.Run(t, "form", "create", "--spec", spec, "--group", "g", "--json", "--signer", alice.Nsec).ExpectErr(t, "usage")
	e.Run(t, "form", "create", "--spec", e.WriteFile("bad.json", `{"title": "t", "questions": [], "respondrs": []}`), "-s", "ws://127.0.0.1:1", "--json", "--signer", alice.Nsec).ExpectErr(t, "invalid_input")
	e.Run(t, "form", "create", "--spec", e.WriteFile("noq.json", `{"title": "t", "questions": []}`), "-s", "ws://127.0.0.1:1", "--json", "--signer", alice.Nsec).ExpectErr(t, "invalid_input")
	e.Run(t, "form", "result", "abcdef", "--json", "-s", "ws://127.0.0.1:1", "--signer", alice.Nsec).ExpectErr(t, "usage")
	e.Run(t, "form", "list", "--state", "closed", "--json", "-s", "ws://127.0.0.1:1", "--signer", alice.Nsec).ExpectErr(t, "invalid_input")
	e.Run(t, "form", "respond", "abcdef", "--note", "x", "--json", "-s", "ws://127.0.0.1:1", "--signer", alice.Nsec).ExpectErr(t, "invalid_input")
}
