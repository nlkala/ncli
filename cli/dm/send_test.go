package dm

import (
	"fmt"
	"testing"

	"github.com/ohstr/nmilat/nip17"
)

// --label adds a t tag per label, once each, in order; a label is one line of plain text.
func TestSendLabels(t *testing.T) {
	r := nip17.NewChatMessage("hi")
	if err := addLabels(r, []string{"release-ok", "x", "release-ok"}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tg := range r.Tags {
		if tg[0] == "t" {
			got = append(got, tg[1])
		}
	}
	if fmt.Sprint(got) != "[release-ok x]" {
		t.Fatalf("t tags %q", got)
	}
	for _, bad := range []string{"", " a", "a ", "a\nb", "a\u202eb", "a\x1bb"} {
		if err := addLabels(nip17.NewChatMessage("hi"), []string{bad}); err == nil {
			t.Errorf("--label %q taken", bad)
		}
	}
}
