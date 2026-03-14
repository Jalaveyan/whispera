package events

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

type NATSEventBus struct {
	nc          *nats.Conn
	prefix      string
	mu          sync.RWMutex
	subscribers map[string][]*natsSub
	allSubs     []*natsSub
	closed      bool
}

type natsSub struct {
	ch      chan Event
	handler EventHandler
	nSub    *nats.Subscription
}

func NewNATSEventBus(url, prefix string) (EventBus, error) {
	nc, err := nats.Connect(url,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.PingInterval(20*time.Second),
		nats.MaxPingsOutstanding(5),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	if prefix == "" {
		prefix = "whispera"
	}

	return &NATSEventBus{
		nc:          nc,
		prefix:      prefix,
		subscribers: make(map[string][]*natsSub),
	}, nil
}

func (nb *NATSEventBus) Publish(event Event) error {
	nb.mu.RLock()
	if nb.closed {
		nb.mu.RUnlock()
		return ErrEventBusClosed
	}
	nb.mu.RUnlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	subject := nb.prefix + "." + event.Type
	return nb.nc.Publish(subject, data)
}

func (nb *NATSEventBus) PublishAsync(event Event) {
	go nb.Publish(event)
}

func (nb *NATSEventBus) Subscribe(eventType string) <-chan Event {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	ch := make(chan Event, 256)
	subject := nb.prefix + "." + eventType

	nSub, err := nb.nc.Subscribe(subject, func(msg *nats.Msg) {
		var event Event
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			return
		}
		select {
		case ch <- event:
		default:
		}
	})
	if err != nil {
		close(ch)
		return ch
	}

	sub := &natsSub{ch: ch, nSub: nSub}
	nb.subscribers[eventType] = append(nb.subscribers[eventType], sub)
	return ch
}

func (nb *NATSEventBus) SubscribeFunc(eventType string, handler EventHandler) func() {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	subject := nb.prefix + "." + eventType

	nSub, err := nb.nc.Subscribe(subject, func(msg *nats.Msg) {
		var event Event
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			return
		}
		handler(event)
	})
	if err != nil {
		return func() {}
	}

	sub := &natsSub{handler: handler, nSub: nSub}
	nb.subscribers[eventType] = append(nb.subscribers[eventType], sub)

	return func() {
		nSub.Unsubscribe()
		nb.mu.Lock()
		defer nb.mu.Unlock()
		subs := nb.subscribers[eventType]
		for i, s := range subs {
			if s == sub {
				nb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
	}
}

func (nb *NATSEventBus) SubscribeAll() <-chan Event {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	ch := make(chan Event, 256)
	subject := nb.prefix + ".>"

	nSub, err := nb.nc.Subscribe(subject, func(msg *nats.Msg) {
		var event Event
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			return
		}
		select {
		case ch <- event:
		default:
		}
	})
	if err != nil {
		close(ch)
		return ch
	}

	sub := &natsSub{ch: ch, nSub: nSub}
	nb.allSubs = append(nb.allSubs, sub)
	return ch
}

func (nb *NATSEventBus) Unsubscribe(eventType string, ch <-chan Event) {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	subs := nb.subscribers[eventType]
	for i, sub := range subs {
		if sub.ch == ch {
			sub.nSub.Unsubscribe()
			close(sub.ch)
			nb.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
			return
		}
	}

	for i, sub := range nb.allSubs {
		if sub.ch == ch {
			sub.nSub.Unsubscribe()
			close(sub.ch)
			nb.allSubs = append(nb.allSubs[:i], nb.allSubs[i+1:]...)
			return
		}
	}
}

func (nb *NATSEventBus) Close() {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	if nb.closed {
		return
	}
	nb.closed = true

	for _, subs := range nb.subscribers {
		for _, sub := range subs {
			sub.nSub.Unsubscribe()
			if sub.ch != nil {
				close(sub.ch)
			}
		}
	}
	for _, sub := range nb.allSubs {
		sub.nSub.Unsubscribe()
		if sub.ch != nil {
			close(sub.ch)
		}
	}

	nb.nc.Drain()
	nb.nc.Close()
}

func (nb *NATSEventBus) IsConnected() bool {
	return nb.nc.IsConnected()
}
