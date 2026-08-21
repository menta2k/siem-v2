package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/data/jetstream"
)

// flowPublisher forwards completed flows to the SIEM_FLOWS conveyor for the
// traffic profiler, without ever blocking the store path.
//
// OnFlow fires inside Pipeline.Flush — on the flow STORAGE path. Anything
// slow here would turn a profiler backlog into ingest latency, which
// Constitution I forbids. So the hand-off is a bounded channel with an
// explicit drop policy: full channel → drop the flow, count it, and log at a
// rate a human can read. Profiles degrade; collection never does.
type flowPublisher struct {
	stream  *jetstream.FlowStream
	ch      chan *flow.Flow
	logger  *slog.Logger
	dropped atomic.Int64
	// published is exported through logs for the zero-output-while-input-
	// continues check (Constitution IV).
	published atomic.Int64
}

func newFlowPublisher(stream *jetstream.FlowStream, logger *slog.Logger) *flowPublisher {
	return &flowPublisher{
		stream: stream,
		ch:     make(chan *flow.Flow, 8192),
		logger: logger,
	}
}

// enqueue is the Pipeline.OnFlow hook. Non-blocking by construction.
func (p *flowPublisher) enqueue(f *flow.Flow) {
	select {
	case p.ch <- f:
	default:
		p.dropped.Add(1)
	}
}

// run drains the queue. A publish failure drops the flow (counted): the
// conveyor is best-effort freshness, and retrying here would back the queue up
// into the drop path anyway. NATS reconnects transparently underneath.
func (p *flowPublisher) run(ctx context.Context) {
	report := time.NewTicker(time.Minute)
	defer report.Stop()
	var lastDropped, lastPublished int64
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-p.ch:
			payload, err := json.Marshal(f)
			if err != nil {
				p.dropped.Add(1)
				continue
			}
			if err := p.stream.Publish(payload); err != nil {
				p.dropped.Add(1)
				continue
			}
			p.published.Add(1)
		case <-report.C:
			dropped, published := p.dropped.Load(), p.published.Load()
			if dropped > lastDropped {
				// A drop is a policy decision, but a SILENT drop is a defect.
				p.logger.Warn("flows dropped before profiling (bounded hand-off; collection unaffected)",
					"dropped_last_minute", dropped-lastDropped,
					"dropped_total", dropped,
					"published_last_minute", published-lastPublished)
			}
			lastDropped, lastPublished = dropped, published
		}
	}
}
