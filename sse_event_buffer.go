package main

// Event bytes stay buffered until the framer finds a complete boundary. Adapters
// retain their own terminal policy and decide when to observe the original data.
type sseEventBuffer struct {
	framer sseFramer
	buf    []byte
}

func (b *sseEventBuffer) writeEvents(p []byte, process func([]byte), writeErr *error) (int, error) {
	if writeErr != nil && *writeErr != nil {
		return 0, *writeErr
	}
	b.buf = append(b.buf, p...)
	for {
		if writeErr != nil && *writeErr != nil {
			b.buf = nil
			return len(p), *writeErr
		}
		event, advance, ok := b.framer.next(b.buf)
		if !ok {
			return len(p), nil
		}
		b.buf = b.buf[advance:]
		process(event)
	}
}
