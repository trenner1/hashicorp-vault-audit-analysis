package jobs

import (
	"net/http"
	"sync"
)

// Broker manages SSE subscriptions, one channel set per job ID.
type Broker struct {
	mu          sync.Mutex
	subscribers map[string][]chan string
}

// NewBroker creates a new SSE broker.
func NewBroker() *Broker {
	return &Broker{
		subscribers: make(map[string][]chan string),
	}
}

// Subscribe returns a receive channel for job lines and an unsubscribe func.
func (b *Broker) Subscribe(jobID string) (<-chan string, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan string, 64) // buffered — never blocks Publish
	b.subscribers[jobID] = append(b.subscribers[jobID], ch)

	unsubscribe := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		subs := b.subscribers[jobID]
		for i, s := range subs {
			if s == ch {
				b.subscribers[jobID] = append(subs[:i], subs[i+1:]...)
				// Don't close here — CloseJob does it when the job finishes.
				break
			}
		}
	}
	return ch, unsubscribe
}

// Publish sends a line to all current subscribers of the job.
func (b *Broker) Publish(jobID, line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subscribers[jobID] {
		select {
		case ch <- line:
		default: // drop if subscriber is too slow
		}
	}
}

// CloseJob closes all subscriber channels for a finished job so EventSource ends.
func (b *Broker) CloseJob(jobID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subscribers[jobID] {
		close(ch)
	}
	delete(b.subscribers, jobID)
}

// ServeSSE streams job output to an HTTP client using Server-Sent Events.
func ServeSSE(w http.ResponseWriter, r *http.Request, jobID string, broker *Broker) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering for SSE

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch, unsubscribe := broker.Subscribe(jobID)
	defer unsubscribe()

	for {
		select {
		case line, open := <-ch:
			if !open {
				// Job finished — send a terminal event so the client knows.
				w.Write([]byte("event: done\ndata: \n\n")) //nolint:errcheck
				flusher.Flush()
				return
			}
			w.Write([]byte("data: " + line + "\n\n")) //nolint:errcheck
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
