//go:build linux

// consumer.go — ring buffer poller and event dispatcher.
//
// The Consumer goroutine continuously reads from the eBPF ring buffer,
// decodes each raw record into an EnrichedEvent, and sends it to an
// output channel that the correlator/detector pipeline consumes.
//
// Ring buffer (BPF_MAP_TYPE_RINGBUF) vs perf buffer:
//   - Single shared buffer (no per-CPU fragmentation)
//   - Strict ordering across CPUs
//   - Lower memory overhead
//   - Available since kernel 5.8 — well within our 5.15 minimum
//
// Drop tracking:
//
//	When the ring buffer fills faster than userspace drains it, the
//	kernel drops events and sets a "lost" counter. We log a warning
//	when this happens. The solution at that point is to increase the
//	ringbuf max_entries in the BPF Makefile, or reduce eBPF event rate.
package consumer

import (
	"context"
	"errors"
	"fmt"

	"github.com/ClawGuard-Labs/akmon/internal/aiprofile"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// Consumer polls the eBPF ring buffer and dispatches decoded events.
type Consumer struct {
	rd     *ringbuf.Reader
	logger *zap.Logger
	cfg    *aiprofile.Profile

	// Stats
	decoded   uint64
	dropped   uint64
	decodeErr uint64
}

// New creates a Consumer attached to the given ring buffer map.
func New(eventsMap *ebpf.Map, logger *zap.Logger, cfg *aiprofile.Profile) (*Consumer, error) {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}
	return &Consumer{rd: rd, logger: logger, cfg: cfg}, nil
}

// Start begins reading events and returns a channel that emits them.
// The channel is closed when ctx is cancelled or the ring buffer is closed.
// This function starts a background goroutine and returns immediately.
func (c *Consumer) Start(ctx context.Context) <-chan *EnrichedEvent {
	out := make(chan *EnrichedEvent, 4096)

	go func() {
		defer close(out)
		defer c.rd.Close()

		for {
			// Check for shutdown first
			select {
			case <-ctx.Done():
				c.logger.Info("consumer shutting down",
					zap.Uint64("decoded", c.decoded),
					zap.Uint64("dropped", c.dropped),
					zap.Uint64("decode_errors", c.decodeErr),
				)
				return
			default:
			}

			// Read blocks until an event is available or the reader is closed.
			record, err := c.rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				c.logger.Warn("ring buffer read error", zap.Error(err))
				continue
			}

			// Note: unlike perf buffers, ring buffers do not carry a per-record
			// lost-samples counter. Kernel-side drops are tracked in the map's
			// internal stats — query via bpftool map show if needed.

			if len(record.RawSample) == 0 {
				continue
			}

			ev, err := Decode(record.RawSample, c.cfg)

			if err != nil {
				c.decodeErr++
				c.logger.Debug("decode error", zap.Error(err),
					zap.Int("raw_len", len(record.RawSample)))
				continue
			}

			c.decoded++

			// Non-blocking send: if the downstream pipeline is slow and the
			// channel fills, we drop here rather than blocking the ring buffer
			// reader (which would cause the kernel-side ring to overflow).
			select {
			case out <- ev:
			default:
				c.dropped++
				c.logger.Warn("consumer output channel full, dropping event",
					zap.String("event_type", ev.EventType),
					zap.Uint32("pid", ev.Pid),
				)
			}
		}
	}()

	return out
}

// Stats returns a snapshot of consumer counters.
func (c *Consumer) Stats() (decoded, dropped, decodeErrors uint64) {
	return c.decoded, c.dropped, c.decodeErr
}
