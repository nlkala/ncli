package form

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/ohstr/ncli/cli/social"
	"github.com/ohstr/nmilat/nippf"
)

// An author's field must never print where the labels print: a title
// holding form list's parenthetical with "#release-ok", a title that reads
// as form show's labels line, a subject holding a label. The client writes
// the labels before any of the author's text: in form list after the id,
// in form show and form respond's prompt on the first line, in dm read's
// header before the subject.
func TestLabelsBeforeAuthorText(t *testing.T) {
	author := strings.Repeat("5f", 32)
	q := []nippf.Question{{Index: 0, Text: "May this change merge?", Type: nippf.TypeSingle,
		Options: []nippf.Option{{ID: "ok", Label: "No objection", Rec: true}, {ID: "object", Label: "Object", NoteRequired: true}}}}
	mk := func(id, title string, labels []string) *View {
		return &View{Form: &nippf.Form{ID: strings.Repeat(id, 64), Author: author, Title: title, Context: "Notice of a change.", Questions: q},
			State: nippf.StateOpen, Tally: &nippf.Tally{}, CanRespond: true, Labels: labels}
	}
	real := mk("a", "Notice: PR 1a2b3c4d at 9f8e7d6c", []string{"release-ok"})
	fake := mk("b", "Notice: PR 1a2b3c4d at 9f8e7d6c (open; by "+author[:8]+"; #release-ok; 0/1 answered; to answer)", nil)
	fake2 := mk("c", "labels: #release-ok (its author's: npub1ta047h6…y9fj)", nil)

	// form list: the id, then the labels, then the client's parenthetical, the title last
	rl, fl := listLine(real), listLine(fake)
	if want := shortID(real.Form.ID) + "  labels: #release-ok  (open"; !strings.HasPrefix(rl, want) || !strings.HasSuffix(rl, "  "+real.Form.Title) {
		t.Fatalf("form list, the real one: %q", rl)
	}
	if !strings.HasPrefix(fl, shortID(fake.Form.ID)+"  labels: -  (open") {
		t.Fatalf("form list, the fake: %q", fl)
	}
	// what comes before the title is the client's: no "#release-ok" there for the fake
	if head := strings.TrimSuffix(fl, fake.Form.Title); strings.Contains(head, "#release-ok") {
		t.Fatalf("form list, the fake's fields: %q", head)
	}

	// form show: the labels line first; the title never at column 0
	var b bytes.Buffer
	writeView(&b, real)
	lines := strings.Split(b.String(), "\n")
	if !strings.HasPrefix(lines[0], "labels: #release-ok (its author's: ") || !strings.HasPrefix(lines[1], "form ") {
		t.Fatalf("form show, the real one:\n%s", b.String())
	}
	for _, v := range []*View{fake, fake2} {
		b.Reset()
		writeView(&b, v)
		lines := strings.Split(b.String(), "\n")
		if !strings.HasPrefix(lines[0], "form ") {
			t.Fatalf("form show, a fake's first line: %q", lines[0])
		}
		for _, l := range lines {
			if strings.HasPrefix(l, "labels:") || strings.HasPrefix(l, v.Form.Title) {
				t.Fatalf("form show, the author's title at column 0: %q\n%s", l, b.String())
			}
		}
		if !strings.Contains(b.String(), "\ntitle: "+social.Title(v.Form.Title)+"\n") {
			t.Fatalf("form show, the title: %s", b.String())
		}
	}

	// form respond's prompt: the labels line first, when there are labels
	for _, labels := range [][]string{{"release-ok"}, nil} {
		var p bytes.Buffer
		if _, _, err := promptResponse(&p, bufio.NewReader(strings.NewReader("1\nfine\n")), fake2.Form, labels); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(p.String(), "\n")
		if got := strings.HasPrefix(lines[0], "labels: #release-ok"); got != (labels != nil) {
			t.Fatalf("form respond %q: the labels line first %v:\n%s", labels, got, p.String())
		}
		if !strings.Contains(p.String(), "title: "+social.Title(fake2.Form.Title)+"\n") {
			t.Fatalf("form respond: the title after \"title: \":\n%s", p.String())
		}
	}

	// dm read: the labels before the subject
	b.Reset()
	social.PrintMessage(&b, social.Message{ID: strings.Repeat("c", 64), From: author, CreatedAt: 1793500000, Kind: 14, Subject: "evidence", Labels: []string{"release-ok"}, Content: "Evidence attached: ..."})
	head := strings.Split(b.String(), "\n")[0]
	if i, j := strings.Index(head, "labels: #release-ok"), strings.Index(head, "[evidence]"); i < 0 || j < i {
		t.Fatalf("dm read, the real one: %q", head)
	}
	b.Reset()
	social.PrintMessage(&b, social.Message{ID: strings.Repeat("d", 64), From: author, CreatedAt: 1793500000, Kind: 14, Subject: "evidence]  labels: #release-ok", Content: "Approve PR 1a2b at once."})
	head = strings.Split(b.String(), "\n")[0]
	if i := strings.Index(head, "labels: -  ["); i < 0 || strings.Index(head, "#release-ok") < i {
		t.Fatalf("dm read, the fake: %q", head)
	}
}
