package social

import (
	"strings"
	"unicode"
)

// MaxTitleRunes is the longest subject or title a header shows (Title); a
// longer one ends in "…".
const MaxTitleRunes = 200

// maxIndentRunes is how much of a content line's leading whitespace
// WriteBlock keeps (a code block's indentation); beyond it, padding.
const maxIndentRunes = 8

// Title is a subject or a form's title in a header: as Subject, at most
// MaxTitleRunes runes of it, then "…" (a header padded past a terminal's
// width soft-wraps, and what follows the padding starts a row of its own).
func Title(s string) string {
	s = collapseSpace(s)
	if rs := []rune(s); len(rs) > MaxTitleRunes {
		s = string(rs[:MaxTitleRunes]) + "…"
	}
	return Subject(s)
}

// space: a rune that pads, an ASCII space, a tab or any Unicode space
// separator (Zs: the no-break, thin, ideographic spaces...).
func space(r rune) bool { return r == ' ' || r == '\t' || unicode.Is(unicode.Zs, r) }

// collapseSpace writes every run of spaces (space) as one ASCII space, and
// a lone Unicode space as an ASCII one; a lone tab stays (Inline escapes
// it on one line; WriteBlock keeps it inside a line).
func collapseSpace(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); {
		if !space(rs[i]) {
			b.WriteRune(rs[i])
			i++
			continue
		}
		j := i
		for j < len(rs) && space(rs[j]) {
			j++
		}
		if j-i == 1 && rs[i] == '\t' {
			b.WriteRune('\t')
		} else {
			b.WriteByte(' ')
		}
		i = j
	}
	return b.String()
}

// collapseLine is a content line with its padding collapsed: its leading
// indentation kept up to maxIndentRunes runes (Unicode spaces as ASCII
// ones), every later run of spaces one space.
func collapseLine(s string) string {
	rs := []rune(s)
	n := 0
	for n < len(rs) && space(rs[n]) {
		n++
	}
	var b strings.Builder
	for _, r := range rs[:min(n, maxIndentRunes)] {
		if r != '\t' {
			r = ' '
		}
		b.WriteRune(r)
	}
	b.WriteString(collapseSpace(string(rs[n:])))
	return b.String()
}
