package dm

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ohstr/ncli/cli/common"
	"github.com/ohstr/ncli/cli/keyresolve"
	"github.com/ohstr/ncli/cli/social"
	"github.com/ohstr/ncli/client"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip09"
	"github.com/ohstr/nmilat/nip25"
	"github.com/ohstr/nmilat/nip59"
	"github.com/spf13/cobra"
)

// reacted is dm react's --json result.
type reacted struct {
	ID     string                `json:"id"` // the reaction rumor's
	To     string                `json:"to"`
	Target string                `json:"target"`
	Emoji  string                `json:"emoji"`
	Wraps  []string              `json:"wraps"`
	Report *client.PublishReport `json:"report"`
}

// unreacted is dm unreact's --json result.
type unreacted struct {
	ID      string                `json:"id"` // the deletion rumor's
	To      string                `json:"to"`
	Targets []string              `json:"targets"` // the reactions removed
	Wraps   []string              `json:"wraps"`
	Report  *client.PublishReport `json:"report"`
}

func newReactCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "react --to <who> <message-id> <emoji>",
		Short: "React to a private message",
		Long: `Sends a NIP-25 reaction (a kind 7 rumor: content the emoji, "e" the
message, "p" its author, "k" its kind with --kind) to a private message,
sealed and gift-wrapped like "dm send": to --to, and a copy to yourself,
which "dm unreact --target --emoji" finds it by.

<message-id> is the rumor's id ("id" in dm read, not "wrap"). Its author
is --to unless --author says otherwise (your own message: your key).
Prints the reaction's id: "dm unreact" takes it.

The signer is asked to sign two kind 13 seals and to nip44_encrypt to
--to and to yourself.`,
		Example: `  ncli dm react --to npub1... <message-id> 👀 -s wss://inbox.example --signer bunker+unix:///run/signer/agent.sock
  ncli dm react --to npub1... <message-id> 💬 --kind 14 -s wss://inbox.example --json`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return common.InvocationError(cmd, fmt.Errorf("a message id and an emoji are expected, got %d argument(s)", len(args)))
			}
			return nil
		},
		RunE: runReact,
	}
	cmd.Flags().String("to", "", "Recipient: npub, hex, nprofile, nip-05 or vault label (required)")
	cmd.Flags().String("author", "", "The message's author, if not --to")
	cmd.Flags().Int("kind", 0, `The message's kind, for the "k" tag (14 for a chat message); none by default`)
	cmd.Flags().Bool("no-self-copy", false, "Don't wrap a copy to yourself (dm unreact --target can't find it then)")
	social.AddRelaysFlag(cmd, "Comma-separated relays to publish to (required)")
	social.AddSignerFlag(cmd)
	return cmd
}

func newUnreactCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unreact --to <who> (<reaction-id>... | --target <message-id> --emoji <emoji>)",
		Short: "Remove your reaction to a private message",
		Long: `Sends a NIP-09 deletion (a kind 5 rumor: one "e" per reaction, "k" 7)
for your own reactions, sealed and gift-wrapped like "dm react": to --to
and a copy to yourself. Readers drop a reaction only for a deletion by
its own author.

Name the reactions by id ("dm react" printed it), or by --target and
--emoji: your reactions in this conversation with that emoji on that
message are looked up in your own copies on -s/--relays (opening only
your own seals); not_found if there are none. --since bounds the lookup.

The signer is asked to sign two kind 13 seals, to nip44_encrypt to --to
and to yourself, and, for --target, to nip44_decrypt your own copies.`,
		Example: `  ncli dm unreact --to npub1... <reaction-id> -s wss://inbox.example
  ncli dm unreact --to npub1... --target <message-id> --emoji 👀 -s wss://inbox.example --json`,
		RunE: runUnreact,
	}
	cmd.Flags().String("to", "", "Recipient: npub, hex, nprofile, nip-05 or vault label (required)")
	cmd.Flags().String("target", "", "The message reacted to: remove your reactions to it (with --emoji)")
	cmd.Flags().String("emoji", "", "With --target: the reaction's emoji")
	cmd.Flags().StringP("since", "S", "", `With --target: look only at reactions written since (unix time or duration, "7d")`)
	cmd.Flags().Duration("timeout", 30*time.Second, "With --target: max time to wait per relay")
	cmd.Flags().Bool("no-self-copy", false, "Don't wrap a copy to yourself")
	social.AddRelaysFlag(cmd, "Comma-separated relays to publish to, and look up on (required)")
	social.AddSignerFlag(cmd)
	return cmd
}

// newReactionRumor is a NIP-25 reaction to message target by author, in a
// conversation with to: "e" (with author), "p" author, "k" when kind > 0,
// and "p" to when it isn't the author, so the rumor names both sides as a
// NIP-17 message does. Unsigned, with no pubkey: sealing makes it a rumor.
func newReactionRumor(target, author string, kind int, emoji, to string) *nip01.Event {
	ev := nip01.NewEvent(nip25.KindReaction, emoji)
	ev.Tags = [][]string{{"e", target, "", author}, {"p", author}}
	if kind > 0 {
		ev.Tags = append(ev.Tags, []string{"k", strconv.Itoa(kind)})
	}
	if to != author {
		ev.Tags = append(ev.Tags, []string{"p", to})
	}
	return ev
}

// newUnreactRumor is a NIP-09 deletion of me's reactions ids ("e" each,
// "k" 7), with "p" to so it reads as part of the conversation.
func newUnreactRumor(me string, ids []string, to string) (*nip01.Event, error) {
	targets := make([]*nip01.Event, len(ids))
	for i, id := range ids {
		targets[i] = &nip01.Event{ID: id, PubKey: me, Kind: nip25.KindReaction}
	}
	ev, err := nip09.NewDeletionRequest(me, targets, "")
	if err != nil {
		return nil, err
	}
	ev.Tags = append(ev.Tags, []string{"p", to})
	return ev, nil
}

// ownReactions are the ids of me's reactions in ms with emoji on target, in
// the conversation with to (to among its "p"), that no deletion of me's in
// ms already removed. Oldest first.
func ownReactions(ms []social.Message, me, to, target, emoji string) []string {
	gone := map[string]bool{}
	for _, m := range ms {
		if m.Type == "delete" && m.From == me {
			for _, id := range m.Targets {
				gone[id] = true
			}
		}
	}
	social.SortMessages(ms)
	var ids []string
	for _, m := range ms {
		if m.Type == "reaction" && m.From == me && m.Target == target && m.Emoji == emoji &&
			slices.Contains(m.Mentions, to) && !gone[m.ID] && !slices.Contains(ids, m.ID) {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

func runReact(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	jsonMode, _ := cmd.Flags().GetBool("json")

	toFlag, _ := cmd.Flags().GetString("to")
	if toFlag == "" {
		return common.InvocationError(cmd, fmt.Errorf("--to is required"))
	}
	target, err := social.EventID(cmd, args[0])
	if err != nil {
		return err
	}
	emoji := args[1]
	if strings.TrimSpace(emoji) == "" {
		return common.InvalidInputError(cmd, "", errors.New("the emoji is empty"))
	}
	kind, _ := cmd.Flags().GetInt("kind")
	if kind < 0 {
		return common.InvalidInputError(cmd, strconv.Itoa(kind), errors.New("--kind can't be negative"))
	}
	targets, err := social.Relays(cmd)
	if err != nil {
		return err
	}
	to, err := keyresolve.Pubkey(cmd, toFlag)
	if err != nil {
		return err
	}
	author := to
	if a, _ := cmd.Flags().GetString("author"); a != "" {
		if author, err = keyresolve.Pubkey(cmd, a); err != nil {
			return err
		}
	}

	signer, closeSigner, err := social.Signer(cmd)
	if err != nil {
		return err
	}
	defer closeSigner()

	rumor := newReactionRumor(target, author, kind, emoji, to)
	rumor.CreatedAt = uint64(time.Now().Unix())
	wraps, err := wrapForBoth(cmd, signer, rumor, to)
	if err != nil {
		return err
	}
	report, err := social.Publish(ctx, cmd, targets, wraps, signer)
	if err != nil {
		return err
	}
	out := reacted{ID: rumor.ID, To: to, Target: target, Emoji: emoji, Report: report, Wraps: wrapIDs(wraps)}
	if jsonMode {
		common.PrintJSON(out)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "reacted %s on %s to %s: %s\n", emoji, target, social.Npub(to), rumor.ID)
		social.PrintReportLines(cmd, report)
	}
	return social.ReportError(cmd, report)
}

func runUnreact(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	f := cmd.Flags()
	jsonMode, _ := f.GetBool("json")

	toFlag, _ := f.GetString("to")
	if toFlag == "" {
		return common.InvocationError(cmd, fmt.Errorf("--to is required"))
	}
	targetFlag, _ := f.GetString("target")
	emoji, _ := f.GetString("emoji")
	switch {
	case targetFlag == "" && emoji == "" && len(args) == 0:
		return common.InvocationError(cmd, errors.New("name the reactions to remove by id, or by --target and --emoji"))
	case (targetFlag != "" || emoji != "") && len(args) > 0:
		return common.InvocationError(cmd, errors.New("reaction ids and --target/--emoji are either-or"))
	case (targetFlag == "") != (emoji == ""):
		return common.InvocationError(cmd, errors.New("--target and --emoji go together"))
	}
	var ids []string
	for _, a := range args {
		id, err := social.EventID(cmd, a)
		if err != nil {
			return err
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	var target string
	if targetFlag != "" {
		var err error
		if target, err = social.EventID(cmd, targetFlag); err != nil {
			return err
		}
	}
	var since uint64
	if v, _ := f.GetString("since"); v != "" {
		s, err := client.ParseDurationUnit(v, true)
		if err != nil {
			return common.InvalidInputError(cmd, v, fmt.Errorf("invalid --since: %w", err))
		}
		since = s
	}
	targets, err := social.Relays(cmd)
	if err != nil {
		return err
	}
	to, err := keyresolve.Pubkey(cmd, toFlag)
	if err != nil {
		return err
	}

	signer, closeSigner, err := social.Signer(cmd)
	if err != nil {
		return err
	}
	defer closeSigner()
	me := strings.ToLower(signer.PubKey())

	if target != "" {
		timeout, _ := f.GetDuration("timeout")
		own, err := readOwn(ctx, cmd, signer, targets, since, timeout)
		if err != nil {
			return readError(cmd, err)
		}
		if ids = ownReactions(own, me, to, target, emoji); len(ids) == 0 {
			return common.NotFoundError(cmd, target, fmt.Errorf("no reaction %s of yours on %s to %s", emoji, target, social.Npub(to)))
		}
	}

	rumor, err := newUnreactRumor(me, ids, to)
	if err != nil {
		return common.InvalidInputError(cmd, "", err)
	}
	rumor.CreatedAt = uint64(time.Now().Unix())
	wraps, err := wrapForBoth(cmd, signer, rumor, to)
	if err != nil {
		return err
	}
	report, err := social.Publish(ctx, cmd, targets, wraps, signer)
	if err != nil {
		return err
	}
	out := unreacted{ID: rumor.ID, To: to, Targets: ids, Report: report, Wraps: wrapIDs(wraps)}
	if jsonMode {
		common.PrintJSON(out)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed %s to %s: %s\n", strings.Join(ids, ", "), social.Npub(to), rumor.ID)
		social.PrintReportLines(cmd, report)
	}
	return social.ReportError(cmd, report)
}

// readOwn opens the gift wraps to the signer's key that hold its own seals
// (the copies it sent itself), written since.
func readOwn(ctx context.Context, cmd *cobra.Command, signer client.Crypto, targets *client.TargetsSpec, since uint64, timeout time.Duration) ([]social.Message, error) {
	me := strings.ToLower(signer.PubKey())
	filter := &nip01.SubscriptionFilter{Kinds: []int{nip59.KindGiftWrap}, Tags: map[string][]string{"p": {me}}}
	if back := uint64(wrapBackdate.Seconds()); since > back {
		filter.Since = since - back
	}
	var wraps []*nip01.Event
	err := common.WithSpinner(cmd, fmt.Sprintf("looking up your reactions on %d relay(s)", len(targets.Relays)), func() error {
		var qErr error
		wraps, qErr = client.QueryTargetsWithAuth(ctx, targets, nip01.NewSubscriptionFilterGroup(filter), timeout, signer)
		return qErr
	})
	if err != nil {
		return nil, err
	}
	r := &reader{signer: signer, from: []string{me}, since: since}
	ms := []social.Message{}
	for _, w := range wraps {
		m, show, _, err := r.open(ctx, w)
		if err != nil {
			return nil, err
		}
		if show {
			ms = append(ms, m)
		}
	}
	r.report()
	return ms, nil
}

func wrapIDs(wraps []*nip01.Event) []string {
	ids := []string{}
	for _, w := range wraps {
		ids = append(ids, w.ID)
	}
	return ids
}
