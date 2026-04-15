//go:build linux

package chagg

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Writer periodically rewrites the compact chain log file with the current
// aggregated chains. It uses atomic write (temp file + rename) so readers
// never see a partial file.
type Writer struct {
	agg      *Aggregator
	path     string
	interval time.Duration
}

// NewWriter returns a Writer that rewrites path every 5 seconds with the
// current chain snapshot from agg.
func NewWriter(agg *Aggregator, path string) *Writer {
	return &Writer{
		agg:      agg,
		path:     path,
		interval: 5 * time.Second,
	}
}

// Start runs the periodic rewrite loop. Blocks until ctx is cancelled.
func (w *Writer) Start(ctx context.Context) {
	tick := time.NewTicker(w.interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			w.writeLog()
			return
		case <-tick.C:
			w.writeLog()
		}
	}
}

// writeLog atomically rewrites the chain log file.
func (w *Writer) writeLog() {
	chains := w.agg.Snapshot()
	if len(chains) == 0 {
		return
	}

	dir := filepath.Dir(w.path)
	tmp, err := os.CreateTemp(dir, ".chagg-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()

	enc := json.NewEncoder(tmp)
	for i := range chains {
		if err := enc.Encode(&chains[i]); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return
		}
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return
	}

	if err := os.Rename(tmpName, w.path); err != nil {
		os.Remove(tmpName)
	}
}
