// Package events provides a tiny in-process publish/subscribe broker used to
// fan out domain events (e.g. security exception inserts) to long-lived HTTP
// subscribers such as the SSE stream.
package events

import "sync"

type Event struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

type Subscriber chan Event

var (
	mu          sync.RWMutex
	subscribers = map[Subscriber]struct{}{}
)

func Subscribe() Subscriber {
	ch := make(Subscriber, 16)
	mu.Lock()
	subscribers[ch] = struct{}{}
	mu.Unlock()
	return ch
}

func Unsubscribe(ch Subscriber) {
	mu.Lock()
	if _, ok := subscribers[ch]; ok {
		delete(subscribers, ch)
		close(ch)
	}
	mu.Unlock()
}

// Publish delivers e to every subscriber. Slow consumers (full buffers) drop
// the event rather than blocking the publisher.
func Publish(e Event) {
	mu.RLock()
	defer mu.RUnlock()
	for ch := range subscribers {
		select {
		case ch <- e:
		default:
		}
	}
}
