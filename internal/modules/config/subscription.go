package config

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

var subscriptionClient = &http.Client{Timeout: 30 * time.Second}

func subscriptionHTTPGet(rawURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Whispera/2.0 subscription-client")

	resp, err := subscriptionClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from subscription endpoint", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // cap at 4 MB
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// SubscriptionManager periodically refreshes a subscription URL and calls
// onChange with the new key list whenever the content changes.
type SubscriptionManager struct {
	url      string
	interval time.Duration
	onChange func([]*ConnectionKey)
	stop     chan struct{}
	lastKeys []*ConnectionKey
}

func NewSubscriptionManager(subURL string, interval time.Duration, onChange func([]*ConnectionKey)) *SubscriptionManager {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &SubscriptionManager{
		url:      subURL,
		interval: interval,
		onChange: onChange,
		stop:     make(chan struct{}),
	}
}

func (s *SubscriptionManager) Start() {
	go s.run()
}

func (s *SubscriptionManager) Stop() {
	close(s.stop)
}

func (s *SubscriptionManager) ForceRefresh() ([]*ConnectionKey, error) {
	return s.fetch()
}

func (s *SubscriptionManager) run() {
	// Fetch immediately on start.
	if keys, err := s.fetch(); err == nil {
		s.lastKeys = keys
		if s.onChange != nil {
			s.onChange(keys)
		}
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			keys, err := s.fetch()
			if err != nil || len(keys) == 0 {
				continue
			}
			s.lastKeys = keys
			if s.onChange != nil {
				s.onChange(keys)
			}
		}
	}
}

func (s *SubscriptionManager) fetch() ([]*ConnectionKey, error) {
	return FetchSubscription(s.url)
}
