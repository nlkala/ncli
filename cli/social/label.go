package social

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Label is a t tag's value as text shows it: printable ASCII as it is, and
// every other rune — a space, a control, a letter of another script, a
// look-alike of an ASCII letter — written as a Go escape (\x20; \u0261 for a script g,
// \u2c9f for a Coptic o), invalid UTF-8 as \xNN. Two labels that print alike are the same
// bytes: a look-alike never shows as the label it imitates.
func Label(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			_, _ = fmt.Fprintf(&b, `\x%02x`, s[i])
		case r > 0x20 && r < 0x7f && r != '\\':
			b.WriteRune(r)
		case r == '\\':
			b.WriteString(`\\`)
		case r <= 0x20 || r == 0x7f:
			_, _ = fmt.Fprintf(&b, `\x%02x`, r)
		default:
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	return b.String()
}

// Labels are an event's labels as text shows them: "#label" each (Label),
// space-separated; "" for none.
func Labels(ls []string) string {
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, "#"+Label(l))
	}
	return strings.Join(out, " ")
}

// TagLabels are an event's t tags' values, each once, in order.
func TagLabels(tags [][]string) []string {
	var out []string
	for _, t := range tags {
		if len(t) < 2 || t[0] != "t" || t[1] == "" {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o == t[1]
		}
		if !dup {
			out = append(out, t[1])
		}
	}
	return out
}
