package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/google/uuid"
	"github.com/ohstr/nmilat/utils"
)

func init() {
	utils.InitLogger()
}

func createFlowAttr() FlowAttr {
	return FlowAttr{
		Index:     1,
		FlagColor: ColorAccent,
	}
}

// An event read before the next one is logged is a row of its own. The read
// follows each log here, never a 100 ms sleep racing a spinning reader: on a
// loaded machine (-race, other suites at once) two events fell between reads,
// became one row of two, and the old test waited forever for its tenth row.
func TestLoggerSequences(t *testing.T) {
	logger := &FlowLogger{}
	for i := range 10 {
		id := uuid.NewString()
		logger.LogEvent(id, createFlowAttr())
		rows := logger.GetLastLogs()
		if len(rows) != 1 || !strings.Contains(strings.Join(rows[0], " "), "EVENT "+id) {
			t.Fatalf("event %d: rows %q, want one row naming %s", i, rows, id)
		}
	}
	if rows := logger.GetLastLogs(); len(rows) != 0 {
		t.Fatalf("nothing new logged, rows %q", rows)
	}
}

// Events logged between two reads are one row that counts them.
func TestLoggerAggregated(t *testing.T) {
	logger := &FlowLogger{}
	for range 10 {
		logger.LogEvent(uuid.NewString(), createFlowAttr())
	}
	rows := logger.GetLastLogs()
	if len(rows) != 1 || !strings.Contains(strings.Join(rows[0], " "), "EVENTS ") || !strings.HasSuffix(rows[0][len(rows[0])-1], "10") {
		t.Fatalf("rows %q, want one row of 10 events", rows)
	}
}

// TestGetLastLogsConcurrent proves GetLastLogs is safe to call from more
// than one goroutine at once. GetLastLogs mutates fl.lastIndex (a plain
// int), so calling it under only an RLock -- as it used to -- is a genuine
// data race the moment two callers overlap; a single-reader test (as in
// TestLoggerSequences/TestLoggerAggregated above) can never catch that,
// since the race only manifests with concurrent callers. This must be clean
// under `go test -race`.
func TestGetLastLogsConcurrent(t *testing.T) {
	logger := &FlowLogger{}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			logger.LogEvent(uuid.NewString(), createFlowAttr())
		}
	}()

	const readers = 8
	wg.Add(readers)
	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					logger.GetLastLogs()
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestLoggerWidget(t *testing.T) {
	app := NewApp().Init()

	logger := &FlowLogger{}
	loggerWidget := NewLogger(app, logger).Init(context.Background())

	app.Load(loggerWidget)

	go func() {
		i := 0
		for range time.Tick(time.Second * 3) {
			logger.Log(fmt.Sprintf("%d-Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce posuere dolor libero, a fermentum leo molestie vel. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Sed sit amet sapien vitae quam vestibulum vehicula. Nulla facilities. Morbi vel massa sed eros fermentum mollis. Mauris mollis", i), createFlowAttr())
			i++
		}
	}()

	go func() {
		i := 0
		for range time.Tick(time.Millisecond * 500) {
			logger.LogEvent(uuid.NewString(), createFlowAttr())
			i++
		}
	}()

	go func() {
		i := 0
		for range time.Tick(time.Millisecond * 900) {
			logger.LogEvent(uuid.NewString(), createFlowAttr())
			i++
		}
	}()

	go func() {
		for i := 5; i > 0; i-- {
			app.Debug(fmt.Sprintf("Closed in %d seconds...", i))
			time.Sleep(time.Second * 1)

		}
	}()

	go func() {
		<-time.After(time.Second * 5)
		app.Stop()
	}()

	_ = app.Run()
}

// TestLoggerInputCaptureIsScopedToThisWidget guards against a regression
// back to the old design, where 'w'/'s' were registered globally on the App
// (firing for every keypress regardless of focus) instead of on the Logger
// itself (Box.SetInputCapture, only consulted while this widget -- or its
// focused child t.logs -- actually has focus).
func TestLoggerInputCaptureIsScopedToThisWidget(t *testing.T) {
	app := NewApp()
	logger := NewLogger(app, &FlowLogger{})
	logger.Init(t.Context())

	if logger.GetInputCapture() == nil {
		t.Fatal("expected Init to install an input capture on the Logger itself")
	}
	if app.GetInputCapture() != nil {
		t.Fatal("expected Init not to install a global App-level input capture")
	}
}

func TestLoggerWSKeysToggleWrapAndAutoscroll(t *testing.T) {
	app := NewApp()
	logger := NewLogger(app, &FlowLogger{})
	logger.Init(t.Context())

	if logger.wrap {
		t.Fatal("expected wrap to default to false")
	}
	if !logger.autoscroll {
		t.Fatal("expected autoscroll to default to true")
	}

	capture := logger.GetInputCapture()

	wKey := tcell.NewEventKey(tcell.KeyRune, 'w', tcell.ModNone)
	if got := capture(wKey); got != nil {
		t.Fatal("expected 'w' to be swallowed (capture returns nil)")
	}
	if !logger.wrap {
		t.Fatal("expected 'w' to toggle wrap on")
	}

	sKey := tcell.NewEventKey(tcell.KeyRune, 's', tcell.ModNone)
	if got := capture(sKey); got != nil {
		t.Fatal("expected 's' to be swallowed (capture returns nil)")
	}
	if logger.autoscroll {
		t.Fatal("expected 's' to toggle autoscroll off")
	}
}
