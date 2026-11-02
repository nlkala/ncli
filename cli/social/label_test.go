package social

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// A label prints as printable ASCII only: a look-alike of a label never prints as it.
func TestLabel(t *testing.T) {
	for in, want := range map[string]string{
		"release-ok":  "release-ok",
		"reɡister":    `re\u0261ister`,   // script g
		"release-ⲟk":  `release-\u2c9fk`, // Coptic o
		"rеlease":     `r\u0435lease`,    // Cyrillic e
		"ꓠꓳ":          `\ua4e0\ua4f3`,    // Lisu
		"Ꭰ":           `\u13a0`,          // Cherokee
		"\U0001d40c":  `\U0001d40c`,      // mathematical bold M
		"release-ok ": `release-ok\x20`,
		`a\u0261`:     `a\\u0261`, // a backslash can't spell an escape
		"x\x1b[2J":    `x\x1b[2J`,
		"\xff":        `\xff`,
	} {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
	if Labels([]string{"a", "b c"}) != `#a #b\x20c` || Labels(nil) != "" {
		t.Fatal(Labels([]string{"a", "b c"}))
	}
}

// dm read shows a message's labels in its header, escaped, before the subject; a content line can't
// take their place (every content line is indented).
func TestPrintMessageLabels(t *testing.T) {
	ev := &nip01.Event{ID: strings.Repeat("a", 64), PubKey: strings.Repeat("b", 64), CreatedAt: 1800000000, Kind: 14,
		Tags:    [][]string{{"p", strings.Repeat("c", 64)}, {"t", "release-ok"}, {"t", "release-ok"}, {"t", "x"}, {"subject", "v1"}},
		Content: "shipped\nlabels: #release-ok"}
	m := FromEvent(ev, "dm")
	if strings.Join(m.Labels, ",") != "release-ok,x" {
		t.Fatalf("labels %q", m.Labels)
	}
	var b bytes.Buffer
	PrintMessage(&b, m)
	lines := strings.Split(b.String(), "\n")
	if !strings.Contains(lines[0], "  labels: #release-ok #x  [v1]") || lines[2] != "  labels: #release-ok" {
		t.Fatalf("%q", b.String())
	}
	fake := FromEvent(&nip01.Event{ID: ev.ID, PubKey: ev.PubKey, CreatedAt: 1, Kind: 14,
		Tags: [][]string{{"t", "rеlease-ok"}}, Content: "hi"}, "dm")
	b.Reset()
	PrintMessage(&b, fake)
	if strings.Contains(b.String(), "#release-ok") || !strings.Contains(b.String(), `#r\u0435lease-ok`) {
		t.Fatalf("a look-alike label: %q", b.String())
	}
	b.Reset()
	PrintMessage(&b, FromEvent(&nip01.Event{ID: ev.ID, PubKey: ev.PubKey, CreatedAt: 1, Kind: 14, Content: "hi"}, "dm"))
	if strings.Contains(b.String(), "#") || !strings.Contains(b.String(), "  labels: -  ") {
		t.Fatalf("no labels: %q", b.String())
	}
}
