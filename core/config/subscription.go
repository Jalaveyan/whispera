package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

func isBlockedSubscriptionIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

var subscriptionClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
			Control: func(network, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				if isBlockedSubscriptionIP(net.ParseIP(host)) {
					return errors.New("subscription: refusing to connect to internal/private address (SSRF guard)")
				}
				return nil
			},
		}).DialContext,
	},
}

func subscriptionHTTPGet(rawURL string) (string, error) {
	if u, perr := url.Parse(rawURL); perr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("subscription: only http/https URLs are allowed")
	}

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

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
