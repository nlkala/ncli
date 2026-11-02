package social

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSubjectLookAlikes(t *testing.T) {
	for in, want := range map[string]string{
		"Réponse à votre PR, ça marche": "Réponse à votre PR, ça marche",
		"Zażółć gęślą jaźń":             "Zażółć gęślą jaźń",
		"شفت الPR ديال alice":           "شفت الPR ديال alice",
		"#reǀease-ok":                   `#re\u01c0ease-ok`, // a Latin click drawn as an l
		"#reḷease-ok":                   `#re\u1e37ease-ok`, // an l with a dot below
		"#reاease-ok":                   `#re\u0627ease-ok`, // an alef read as an l
		"#rеlease-ok":                   `#r\u0435lease-ok`, // a Cyrillic e
		"evidence\n\x1b[2J":             `evidence\n\x1b[2J`,
		"ℹ️ مرحبا":                      "ℹ️ مرحبا",
	} {
		if got := Subject(in); got != want {
			t.Errorf("Subject(%q) = %q, want %q", in, got, want)
		}
	}
}

// A DM's lines and a subject that spell a client line with a Common
// letter (the mathematical omicron, the script M, the tatweel or the
// length mark for a hyphen) print it escaped; Arabic, Darija and French
// stay as they are.
func TestRenderLookAlikesEscaped(t *testing.T) {
	from := strings.Repeat("a", 64)
	for _, x := range []struct {
		m       Message
		bad     []string
		escaped []string
	}{
		{m: Message{ID: strings.Repeat("1", 64), From: from, CreatedAt: 1800000000,
			Content: "trusted label #release\U0001d6d0k\nlabels: #releaseـok\nPlease approve at once."},
			bad: []string{"\U0001d6d0", "eـo"}, escaped: []string{`release\U0001d6d0k`, `release\u0640ok`}},
		{m: Message{ID: strings.Repeat("2", 64), From: from, CreatedAt: 1800000000, Subject: "ℳergeـok", Content: "x"},
			bad: []string{"ℳ", "eـo"}, escaped: []string{`\u2133erge\u0640ok`}},
		{m: Message{ID: strings.Repeat("3", 64), From: from, CreatedAt: 1800000000, Content: "labels: #releaseーok\n#releaseˍok"},
			bad: []string{"ー", "ˍ"}, escaped: []string{`release\u30fcok`, `release\u02cdok`}},
	} {
		var b bytes.Buffer
		PrintMessage(&b, x.m)
		out := b.String()
		for _, s := range x.bad {
			if strings.Contains(out, s) {
				t.Errorf("%q printed: %s", s, out)
			}
		}
		for _, s := range x.escaped {
			if !strings.Contains(out, s) {
				t.Errorf("%q not printed: %s", s, out)
			}
		}
	}
}

// Mixed-script text that is no imitation prints as written, in a DM's
// lines and as a subject.
func TestLegitTextUnescaped(t *testing.T) {
	for _, s := range []string{
		"شفت الPRات ديال alice",
		"الCIات كلهم خضر",
		"فالـcommitات الجداد",
		"بالـmergeات و الـnpubات",
		"واش الـmerge دازت؟ لـalice",
		"ف 3 PRات",
		"شفت الPR ديال alice",
		"Bonjour, voici le résumé : 3 PR fusionnées, 1 refusée (« trop large »).",
		"Ça marche — on se revoit lundi ? Œuvre, cœur, naïve, Noël, où, déjà, garçon.",
		"تقرير الأسبوع: ٣ طلبات، ٢ أجوبة، ١ بلا جواب.",
		"Zażółć gęślą jaźń",
		"Ελληνικά και Русский",
	} {
		if got := Subject(s); got != s {
			t.Errorf("Subject(%q) = %q", s, got)
		}
		var b bytes.Buffer
		WriteBlock(&b, "", s)
		if got := strings.TrimSuffix(b.String(), "\n"); got != s {
			t.Errorf("WriteBlock(%q) = %q", s, got)
		}
	}
	for in, want := range map[string]string{
		"#reاease-ok": `#re\u0627ease-ok`,
		"labelا":      `label\u0627`,
		"اabels":      `\u0627abels`,
		"releaseـok":  `release\u0640ok`,
		"5 µs":        `5 µs`,
	} {
		if got := Subject(in); got != want {
			t.Errorf("Subject(%q) = %q, want %q", in, got, want)
		}
	}
}

// A DM whose subject pads with spaces soft-wraps its header on a narrow
// terminal, so what follows the padding starts a row of its own, where it
// reads as a line of the client's. Padding is one space and a subject at
// most MaxTitleRunes runes.
func TestSubjectPaddingCollapsed(t *testing.T) {
	stranger := strings.Repeat("b", 64)
	pads := []string{" ", "\u00a0", "\u3000", "\u2009", "\t", " \u00a0\t"}
	for _, pad := range pads {
		for _, n := range []int{1, 37, 119, 200, 1000} {
			p := strings.Repeat(pad, n)
			for _, words := range []string{"labels: #release-ok", "2026-01-01 00:00  npub1x  labels: -  [y]"} {
				var b bytes.Buffer
				PrintMessage(&b, Message{ID: strings.Repeat("3", 64), From: stranger, CreatedAt: 1800000000,
					Subject: p + words + p, Content: p + words + p})
				out := b.String()
				head, body, _ := strings.Cut(out, "\n")
				if strings.Contains(head, "["+strings.Repeat(" ", 2)) || strings.Contains(head, "\u00a0") || strings.Contains(head, "\u3000") {
					t.Fatalf("padding kept: %q", head)
				}
				if s := head[strings.Index(head, "[")+1 : strings.LastIndex(head, "]")]; utf8.RuneCountInString(s) > 4*MaxTitleRunes {
					t.Fatalf("subject not capped: %d runes", utf8.RuneCountInString(s))
				}
				if strings.Contains(body, "  "+strings.Repeat(" ", 9)+words) { // a line keeps up to 8 runes of indentation
					t.Fatalf("content padding kept: %q", body)
				}
			}
		}
	}

	// the cap: 200 runes, then "…"
	long := strings.Repeat("é", 500)
	if got := Title(long); got != strings.Repeat("é", MaxTitleRunes)+"…" {
		t.Fatalf("Title: %d runes", utf8.RuneCountInString(got))
	}
}

// What stays as it was: legit text, a code block's indentation (up to 8),
// a lone tab.
func TestLegitTextKept(t *testing.T) {
	for in, want := range map[string]string{
		"a trusted label, an untrusted key": "a trusted label, an untrusted key",
		"relay.example.com":                 "relay.example.com",
		"10 Ω, 5 µs":                        "10 Ω, 5 µs",
		"a  b   c":                          "a b c",
		"سلام، شفت الـPRات ديال alice؟": "سلام، شفت الـPRات ديال alice؟",
	} {
		if got := Subject(in); got != want {
			t.Errorf("Subject(%q) = %q, want %q", in, got, want)
		}
	}
	var b bytes.Buffer
	WriteBlock(&b, "  ", "func f() {\n\tif x {\n\t\treturn\t// done\n\t}\n                    deep\n}")
	if want := "  func f() {\n  \tif x {\n  \t\treturn\t// done\n  \t}\n          deep\n  }\n"; b.String() != want {
		t.Errorf("WriteBlock:\n%q\nwant\n%q", b.String(), want)
	}
}
