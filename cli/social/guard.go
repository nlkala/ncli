package social

import (
	"strconv"
	"strings"
	"unicode"
)

// Subject is a subject or a title on one line (Inline), with every
// non-ASCII letter or digit that sits beside an ASCII letter escaped, so
// a look-alike can't pass for the ASCII word it imitates ("keyho\u01c0der"
// for a Latin click drawn as an l, "rel\u0435ase" for a Cyrillic e).
// Left as they are: the accented letters of U+00C0-017F (French, German,
// Polish: "réponse"), Arabic letters other than alef beside Latin ones
// (mixed Arabic-Latin text such as "الPR"), the tatweel beside an Arabic
// letter ("الـmerge") and an alef before an Arabic letter ("PRات").
// Common letters are escaped too (the mathematical "𝛐", the letterlike
// "ℳ", the tatweel or "ー" standing for a hyphen). Every run of spaces is
// one space, so a padded subject can't soft-wrap a header.
func Subject(s string) string { return guard(Inline(collapseSpace(s))) }

// Guard is a line of text Inline or WriteBlock already escaped, with the
// letters Subject escapes beside ASCII letters escaped too.
func Guard(s string) string { return guard(s) }

func guard(s string) string {
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		if suspectAt(rs, i) {
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// suspectAt: rs[i] is a suspect letter beside an ASCII letter.
func suspectAt(rs []rune, i int) bool {
	r := rs[i]
	if !suspect(r) || (!asciiLetter(rs, i-1) && !asciiLetter(rs, i+1)) {
		return false
	}
	switch {
	case r == tatweel:
		return !arabicLetter(rs, i-1) && !arabicLetter(rs, i+1)
	case isAlef(r):
		// an alef read as an l: beside a Latin letter but before an Arabic one
		return !arabicLetter(rs, i+1)
	}
	return true
}

const tatweel = 0x640

func isAlef(r rune) bool { return strings.ContainsRune("اٱأإآ", r) }

func asciiLetter(rs []rune, i int) bool {
	return i >= 0 && i < len(rs) && rs[i] < 0x80 && unicode.IsLetter(rs[i])
}

// arabicLetter: rs[i] is an Arabic letter or a tatweel.
func arabicLetter(rs []rune, i int) bool {
	return i >= 0 && i < len(rs) && (rs[i] == tatweel || (unicode.Is(unicode.Arabic, rs[i]) && unicode.IsLetter(rs[i])))
}

// suspect: a letter or digit beyond ASCII that could stand for an ASCII one
// beside ASCII letters.
func suspect(r rune) bool {
	switch {
	case r < 0x80 || r == 0xb5 || (!unicode.IsLetter(r) && !unicode.IsDigit(r)):
		return false // the micro sign µ ("5 µs") reads as no ASCII letter
	case r >= 0xc0 && r < 0x180:
		return false
	case unicode.Is(unicode.Arabic, r) && unicode.IsLetter(r):
		return isAlef(r)
	}
	return true
}
