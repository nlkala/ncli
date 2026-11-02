package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/wire"
)

// ErrFollowLocal is --follow given a local .db target, which has no live
// feed.
var ErrFollowLocal = errors.New("--follow needs relay targets, not a local .db file")

// maxSeen bounds the delivered ids a FollowState remembers, and
// maxSeenOnly the ids of events it only saw (gift wraps that didn't open).
// They are two lists, so junk never pushes a delivered id out (a restart
// would print that message again).
const (
	maxSeen     = 5000
	maxSeenOnly = 5000
)

// ErrSkip, returned by FollowOptions.Emit, leaves an event unrecorded in the
// state: it is neither printed nor remembered, so a later run looks again.
var ErrSkip = errors.New("skip")

// ErrSeenOnly, returned by FollowOptions.Emit, records an event's id as
// delivered but leaves the relay's since where it was: an event that could
// not be opened or verified says nothing true about its time, and a junk
// one dated a year ahead must not make every later subscription ask only
// for events from then on.
var ErrSeenOnly = errors.New("seen only")

// sinceNow is the clock a since is held to; tests move it.
var sinceNow = time.Now

// FollowState is what a follow has delivered, so a restart resumes where it
// stopped: recently seen ids and, per relay, the newest created_at seen.
// Delivery across a crash is at least once: an id seen in the last second
// may come again; nothing is skipped.
type FollowState struct {
	path string
	mu   sync.Mutex

	seen      map[string]bool // delivered
	order     []string
	only      map[string]bool // seen only, never delivered
	onlyOrder []string
	since     map[string]int64
	dirty     bool
}

// followStateFile is the state on disk. A file from an older ncli has no
// seen_only: its seen holds both kinds, all kept as delivered.
type followStateFile struct {
	Seen     []string         `json:"seen"`
	SeenOnly []string         `json:"seen_only,omitempty"`
	Since    map[string]int64 `json:"since"`
}

// LoadFollowState reads path; a missing file is an empty state. path ""
// keeps the state in memory only.
func LoadFollowState(path string) (*FollowState, error) {
	s := &FollowState{path: path, seen: map[string]bool{}, only: map[string]bool{},
		since: map[string]int64{}}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f followStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("state file %s: %w", path, err)
	}
	for _, id := range f.Seen {
		s.add(id)
	}
	for _, id := range f.SeenOnly {
		s.addOnly(id)
	}
	// A since in the future (an older ncli recorded a junk event's
	// created_at) would blind every later subscription: forget it, so the
	// next one reads from its filter's own since again (delivery is at
	// least once; seen ids are not repeated).
	now := sinceNow().Unix()
	for k, v := range f.Since {
		if v > now {
			s.dirty = true
			continue
		}
		s.since[k] = v
	}
	return s, nil
}

func (s *FollowState) add(id string) {
	if s.seen[id] {
		return
	}
	s.seen[id] = true
	s.order = append(s.order, id)
	if len(s.order) > maxSeen {
		delete(s.seen, s.order[0])
		s.order = s.order[1:]
	}
}

func (s *FollowState) addOnly(id string) {
	if s.seen[id] || s.only[id] {
		return
	}
	s.only[id] = true
	s.onlyOrder = append(s.onlyOrder, id)
	if len(s.onlyOrder) > maxSeenOnly {
		delete(s.only, s.onlyOrder[0])
		s.onlyOrder = s.onlyOrder[1:]
	}
}

func (s *FollowState) known(id string) bool { return s.seen[id] || s.only[id] }

// Seen reports whether id was delivered or seen only.
func (s *FollowState) Seen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.known(id)
}

// Mark records id as delivered from relay. It reports false if id was
// already delivered. The relay's since moves up to createdAt, but never
// past now: an event dated ahead can't make a resume skip what comes later.
func (s *FollowState) Mark(id, relay string, createdAt int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.known(id) {
		return false
	}
	s.add(id)
	if now := sinceNow().Unix(); createdAt > now {
		createdAt = now
	}
	if createdAt > s.since[relay] {
		s.since[relay] = createdAt
	}
	s.dirty = true
	return true
}

// MarkSeen records id as delivered without moving any since: for an event
// whose time can't be trusted (a gift wrap that didn't open). It goes to
// its own bounded list, so no amount of junk pushes a delivered id out. It
// reports false if id was already known.
func (s *FollowState) MarkSeen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.known(id) {
		return false
	}
	s.addOnly(id)
	s.dirty = true
	return true
}

// Since is the newest created_at delivered from relay, 0 if none.
func (s *FollowState) Since(relay string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.since[relay]
}

// Save writes the state atomically if it changed.
func (s *FollowState) Save() error {
	s.mu.Lock()
	if s.path == "" || !s.dirty {
		s.mu.Unlock()
		return nil
	}
	f := followStateFile{Seen: append([]string(nil), s.order...),
		SeenOnly: append([]string(nil), s.onlyOrder...), Since: map[string]int64{}}
	for k, v := range s.since {
		f.Since[k] = v
	}
	s.dirty = false
	s.mu.Unlock()

	if err := s.write(f); err != nil {
		// Try again on the next Save.
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *FollowState) write(f followStateFile) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".ncli-state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Resume is the since a one-shot read with this state starts from: overlap
// before the newest event recorded from any relay, 0 when nothing is.
func (s *FollowState) Resume(overlap time.Duration) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var newest int64
	for _, v := range s.since {
		if v > newest {
			newest = v
		}
	}
	if newest == 0 {
		return 0
	}
	if r := newest - int64(overlap.Seconds()); r > 0 {
		return uint64(r)
	}
	return 0
}

// FollowOptions configures Follow.
type FollowOptions struct {
	// AuthSigner logs in (NIP-42) when a relay asks; nil stays anonymous.
	AuthSigner Signer
	// State dedupes across relays and restarts; nil keeps it in memory.
	State *FollowState
	// Overlap moves a resumed subscription's since this far before the
	// newest event seen, for events published late. Default 10 minutes.
	Overlap time.Duration
	// DialTimeout bounds one connection attempt. Default 30s.
	DialTimeout time.Duration
	// Emit receives each new event once, serialized. An error stops Follow.
	Emit func(ev *nip01.Event, relay string) error
	// Warn receives a relay's recoverable failure (it is retried).
	Warn func(relay string, err error)
}

// followBackoff bounds the wait between reconnects.
var followBackoff = [2]time.Duration{time.Second, 30 * time.Second}

// Follow subscribes to filters on every relay target and emits each new
// event once, until ctx is done (then it returns nil). A relay that drops
// is redialed with backoff. If no relay can be reached at the start it
// returns ErrNoReachableTargets; a refused login is returned as is.
func Follow(ctx context.Context, targets *TargetsSpec, filters *nip01.SubscriptionFilterGroup, opts FollowOptions) error {
	if opts.State == nil {
		opts.State, _ = LoadFollowState("")
	}
	if opts.Overlap == 0 {
		opts.Overlap = 10 * time.Minute
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 30 * time.Second
	}
	if opts.Warn == nil {
		opts.Warn = func(string, error) {}
	}
	var remotes []*FlowSpec
	for _, t := range targets.Relays {
		if t.Type != FlOW_REMOTE {
			return ErrFollowLocal
		}
		remotes = append(remotes, t)
	}
	if len(remotes) == 0 {
		return ErrNoReachableTargets
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f := &follower{opts: opts, filters: filters}

	// Save the state at most once a second, and on the way out.
	saveDone := make(chan struct{})
	go func() {
		defer close(saveDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if err := opts.State.Save(); err != nil {
					opts.Warn("", fmt.Errorf("saving state: %w", err))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	connected := make(chan bool, len(remotes))
	errs := make(chan error, len(remotes))
	var wg sync.WaitGroup
	for _, t := range remotes {
		wg.Add(1)
		go func(t *FlowSpec) {
			defer wg.Done()
			if err := f.run(ctx, t, connected); err != nil {
				errs <- err
				cancel()
			}
		}(t)
	}

	// Fail fast only if every relay is down at the start.
	failed := 0
	for failed < len(remotes) {
		ok := <-connected
		if ok {
			break
		}
		failed++
	}
	if failed == len(remotes) {
		cancel()
	}
	wg.Wait()
	cancel()
	<-saveDone
	saveErr := opts.State.Save()

	select {
	case err := <-errs:
		return err
	default:
	}
	if failed == len(remotes) {
		return ErrNoReachableTargets
	}
	return saveErr
}

type follower struct {
	opts    FollowOptions
	filters *nip01.SubscriptionFilterGroup
	emitMu  sync.Mutex
}

// run follows one relay until ctx is done. It reports the first connection
// attempt on connected. A login refusal or an Emit error ends it.
func (f *follower) run(ctx context.Context, t *FlowSpec, connected chan<- bool) error {
	relay := t.Label()
	first := true
	wait := followBackoff[0]
	for ctx.Err() == nil {
		// The connection lives as long as connCtx, so the dial timeout
		// cancels it only while dialing.
		connCtx, cancelConn := context.WithCancel(ctx)
		timer := time.AfterFunc(f.opts.DialTimeout, cancelConn)
		sess, err := dialRelay(connCtx, t.relayURI, t.relayFallbackURI, nil, f.opts.AuthSigner)
		timer.Stop()
		if first {
			connected <- err == nil
			first = false
		}
		if err == nil {
			wait = followBackoff[0]
			err = f.stream(connCtx, sess, relay)
			sess.Close()
		}
		cancelConn()
		var le *LoginError
		if errors.As(err, &le) || errors.Is(err, errEmit) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		f.opts.Warn(relay, err)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}
		if wait *= 2; wait > followBackoff[1] {
			wait = followBackoff[1]
		}
	}
	return nil
}

var errEmit = errors.New("emit failed")

// resumeFilters is f.filters with since moved up to where relay left off.
func (f *follower) resumeFilters(relay string) *nip01.SubscriptionFilterGroup {
	last := f.opts.State.Since(relay)
	if last == 0 {
		return f.filters
	}
	since := last - int64(f.opts.Overlap.Seconds())
	if since < 0 {
		since = 0
	}
	out := nip01.NewSubscriptionFilterGroup()
	for _, flt := range f.filters.GetAll() {
		c := *flt
		if int64(c.Since) < since {
			c.Since = uint64(since)
		}
		out.Add(&c)
	}
	return out
}

// stream runs one live subscription on sess until it drops. As for a
// one-shot read, a login only matters once the relay refuses the REQ for
// want of one. Its stored events are paged back past the relay's cap
// (followpage.go) while the live ones keep coming.
func (f *follower) stream(ctx context.Context, sess *relaySession, relay string) error {
	subID := uuid.NewString()
	var pg *followPager
	subscribe := func() error {
		filters := f.resumeFilters(relay)
		pg = newFollowPager(filters)
		pg.restart()
		if !sess.conn.SubscribeWithID(subID, filters) {
			return relayclient.ErrConnectionClosed
		}
		return nil
	}
	if err := subscribe(); err != nil {
		return err
	}
	// page asks the next page of stored events (until the oldest the last
	// one brought), or ends the paging
	page := func() error {
		if until, ok := pg.next(); ok {
			if !sess.conn.SubscribeWithID(pg.sub, pg.filters(until)) {
				return relayclient.ErrConnectionClosed
			}
		} else {
			if pg.cut != "" {
				f.opts.Warn(relay, errors.New(pg.cut))
			}
			if followPaged != nil {
				followPaged(relay)
			}
		}
		return nil
	}
	retried := false
	for {
		select {
		case msg, ok := <-sess.conn.Read():
			if !ok {
				return relayclient.ErrConnectionClosed
			}
			if sess.observe(msg) {
				continue
			}
			switch m := msg.(type) {
			case *wire.EventSubscriptionResponse:
				if (m.SubscriptionID != subID && m.SubscriptionID != pg.sub) || m.Event == nil || m.Event.Verify(nip01.WithoutPowCheck()) != nil {
					continue
				}
				if m.SubscriptionID == pg.sub || pg.stored {
					pg.saw(m.Event)
				}
				if err := f.emit(m.Event, relay); err != nil {
					return err
				}
			case *wire.EOSESubscriptionResponse:
				switch {
				case m.SubscriptionID == subID && pg.stored:
					pg.stored = false // live from here on
					if err := page(); err != nil {
						return err
					}
				case m.SubscriptionID == pg.sub && pg.sub != "":
					sess.conn.CloseSubscription(pg.sub)
					if err := page(); err != nil {
						return err
					}
				}
			case *wire.ClosedSubscriptionResponse:
				if m.SubscriptionID == pg.sub && pg.sub != "" {
					// a page refused: the live subscription goes on, the rest unpaged
					f.opts.Warn(relay, fmt.Errorf("relay closed a page of stored events: %s", m.Message))
					pg.stop()
					continue
				}
				if m.SubscriptionID != subID {
					continue
				}
				if refusedForLogin(m.Message) && !retried {
					if err := sess.awaitLogin(ctx, m.Message, nil); err != nil {
						return err
					}
					retried = true
					if err := subscribe(); err != nil {
						return err
					}
					continue
				}
				if refusedForLogin(m.Message) || strings.HasPrefix(m.Message, restrictedPrefix) {
					return &LoginError{Relay: relay, Reason: LoginRelayRefused, Detail: m.Message}
				}
				return fmt.Errorf("relay closed the subscription: %s", m.Message)
			}
		case err := <-sess.conn.Errors():
			return err
		case <-sess.conn.Closed():
			return relayclient.ErrConnectionClosed
		case <-ctx.Done():
			return nil
		}
	}
}

// emit hands ev to Emit once. It is recorded as delivered only after Emit
// succeeds; ErrSkip leaves it unrecorded, to be looked at again; ErrSeenOnly
// records its id but not its time.
func (f *follower) emit(ev *nip01.Event, relay string) error {
	f.emitMu.Lock()
	defer f.emitMu.Unlock()
	if f.opts.State.Seen(ev.ID) {
		return nil
	}
	err := f.opts.Emit(ev, relay)
	switch {
	case errors.Is(err, ErrSkip):
		return nil
	case errors.Is(err, ErrSeenOnly):
		f.opts.State.MarkSeen(ev.ID)
		return nil
	case err != nil:
		return fmt.Errorf("%w: %w", errEmit, err)
	}
	f.opts.State.Mark(ev.ID, relay, int64(ev.CreatedAt))
	return nil
}
