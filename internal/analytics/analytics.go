package analytics

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/mihiragrawal/agentgate/internal/core"
	"github.com/mihiragrawal/agentgate/internal/observability"
	"github.com/mihiragrawal/agentgate/internal/store"
)

type Sink struct {
	st        store.Store
	log       *zap.Logger
	ch        chan core.Event
	batchSize int
	flushIv   time.Duration
	wg        sync.WaitGroup
}

func New(st store.Store, log *zap.Logger, buffer, batchSize int, flushIv time.Duration) *Sink {
	if buffer <= 0 {
		buffer = 10000
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	if flushIv <= 0 {
		flushIv = 2 * time.Second
	}
	return &Sink{
		st:        st,
		log:       log,
		ch:        make(chan core.Event, buffer),
		batchSize: batchSize,
		flushIv:   flushIv,
	}
}

func (s *Sink) Record(ev core.Event) {
	if ev.Ts.IsZero() {
		ev.Ts = time.Now()
	}
	select {
	case s.ch <- ev:
	default:
		observability.AnalyticsDropped.Inc()
	}
}

func (s *Sink) Start() {
	s.wg.Add(1)
	go s.loop()
}

func (s *Sink) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushIv)
	defer ticker.Stop()

	buf := make([]core.Event, 0, s.batchSize)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.st.InsertAnalytics(ctx, buf); err != nil {
			s.log.Warn("analytics flush failed", zap.Int("events", len(buf)), zap.Error(err))
		}
		cancel()
		buf = buf[:0]
	}

	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, ev)
			if len(buf) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *Sink) Stop() {
	close(s.ch)
	s.wg.Wait()
}
