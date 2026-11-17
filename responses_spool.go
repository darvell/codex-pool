package main

import "os"

type streamedResponsesRequest struct {
	File                    *os.File
	Size                    int64
	OriginalFile            *os.File
	OriginalSize            int64
	Model                   string
	ServiceTier             string
	ClientWantsNonStreaming bool
	contextMetadata         map[string]any
}

func (s *streamedResponsesRequest) Close() {
	if s != nil {
		closeAndRemoveTemp(s.File)
		closeAndRemoveTemp(s.OriginalFile)
		s.File = nil
		s.OriginalFile = nil
	}
}

func closeAndRemoveTemp(f *os.File) {
	if f != nil {
		n := f.Name()
		_ = f.Close()
		_ = os.Remove(n)
	}
}
