package apiserver

import (
	"sync"
	"time"
)

type EventKind string

const (
	EventAuth         EventKind = "auth"
	EventKey          EventKind = "key"
	EventSubscription EventKind = "subscription"
	EventUser         EventKind = "user"
	EventSystem       EventKind = "system"
	EventML           EventKind = "ml"
)

type EventSeverity string

const (
	SeverityInfo  EventSeverity = "info"
	SeverityWarn  EventSeverity = "warn"
	SeverityError EventSeverity = "error"
)

type LogEvent struct {
	Time     time.Time             `json:"time"`
	Kind     EventKind             `json:"kind"`
	Severity EventSeverity         `json:"severity"`
	Message  string                `json:"message"`
	Fields   map[string]string     `json:"fields,omitempty"`
}

const eventRingSize = 500

type eventRing struct {
	mu     sync.Mutex
	buf    [eventRingSize]LogEvent
	head   int
	count  int
}

var globalEventRing = &eventRing{}

// AppendEvent adds an event to the in-memory ring buffer.
func AppendEvent(kind EventKind, severity EventSeverity, msg string, fields map[string]string) {
	globalEventRing.append(LogEvent{
		Time:     time.Now(),
		Kind:     kind,
		Severity: severity,
		Message:  msg,
		Fields:   fields,
	})
}

func (r *eventRing) append(e LogEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.head] = e
	r.head = (r.head + 1) % eventRingSize
	if r.count < eventRingSize {
		r.count++
	}
}

// Recent returns the last n events, newest first.
func (r *eventRing) Recent(n int) []LogEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > r.count {
		n = r.count
	}
	out := make([]LogEvent, n)
	for i := 0; i < n; i++ {
		idx := (r.head - 1 - i + eventRingSize) % eventRingSize
		out[i] = r.buf[idx]
	}
	return out
}

// RecentEvents returns the last n structured events from the ring buffer.
func RecentEvents(n int) []LogEvent {
	return globalEventRing.Recent(n)
}
