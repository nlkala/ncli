package social

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ohstr/ncli/client"
	"github.com/spf13/cobra"
)

// A relay's OK message and its URL are the relay's text: printed escaped.
func TestPrintReportLinesEscapes(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	PrintReportLines(cmd, &client.PublishReport{Results: []client.PublishResult{
		{ID: "e1", Relay: "wss://r\x1b[2J", Accepted: true},
		{ID: "e2", Relay: "wss://r", Error: "blocked\npublished e2 to wss://other\u200b"},
	}})
	got := out.String()
	if strings.ContainsAny(got, "\x1b\u200b") || strings.Count(got, "\n") != 2 ||
		!strings.Contains(got, `blocked\npublished e2 to wss://other\u200b`) {
		t.Fatalf("report lines: %q", got)
	}
}
