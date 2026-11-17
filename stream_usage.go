package main

import "io"

const streamUsageChunkBytes = 32 * 1024

// Commit usage after forwarding each chunk, including on write failure. Keeping
// the commit inside Write bounds pending records and keeps shutdown synchronous.
type streamUsageWriter struct {
	w       io.Writer
	record  func(RequestUsage)
	pending []RequestUsage
}

func (w *streamUsageWriter) add(usage RequestUsage) {
	w.pending = append(w.pending, usage)
}

func (w *streamUsageWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), streamUsageChunkBytes)]
		n, err := w.w.Write(chunk)
		for _, usage := range w.pending {
			w.record(usage)
		}
		clear(w.pending)
		w.pending = w.pending[:0]
		total += n
		if err != nil {
			return total, err
		}
		if n != len(chunk) {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}

// Observe the original upstream events outside translation and filtering. The
// bounded writer commits observations after each forwarding attempt, including
// the events in a received chunk after a downstream failure.
func newUsageStream(w io.Writer, observe func([]byte, func(RequestUsage)), record func(RequestUsage)) io.Writer {
	usage := &streamUsageWriter{record: record}
	usage.w = &sseInterceptWriter{w: w, callback: func(data []byte) {
		observe(data, usage.add)
	}}
	return usage
}
