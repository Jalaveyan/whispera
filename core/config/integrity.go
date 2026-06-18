package config

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var integrityKey = func() string {
	if key := os.Getenv("WHISPERA_INTEGRITY_KEY"); key != "" {
		return key
	}
	return "DEVELOPMENT-ONLY-REPLACE-IN-PRODUCTION"
}()

const (
	checksumFile = ".config.checksum"
	telegramAPI  = "https://api.telegram.org/bot%s/sendMessage"
	hostName     = "Whispera Server"
)

type NotificationConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Token   string `yaml:"token" json:"token"`
	ChatID  string `yaml:"chat_id" json:"chat_id"`
}

func (p *Provider) CalculateChecksum() (string, error) {
	if p.configPath == "" {
		return "", fmt.Errorf("config path is empty")
	}

	data, err := os.ReadFile(p.configPath)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, []byte(integrityKey))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *Provider) UpdateChecksum() error {
	sum, err := p.CalculateChecksum()
	if err != nil {
		return err
	}

	dir := filepath.Dir(p.configPath)
	checksumPath := filepath.Join(dir, checksumFile)

	return os.WriteFile(checksumPath, []byte(sum), 0644)
}

func (p *Provider) VerifyIntegrity() error {
	if _, err := os.Stat(p.configPath); os.IsNotExist(err) {
		return nil
	}

	dir := filepath.Dir(p.configPath)
	checksumPath := filepath.Join(dir, checksumFile)

	savedSumBytes, err := os.ReadFile(checksumPath)
	if os.IsNotExist(err) {
		return p.UpdateChecksum()
	} else if err != nil {
		return fmt.Errorf("failed to read checksum file: %w", err)
	}

	currentSum, err := p.CalculateChecksum()
	if err != nil {
		return fmt.Errorf("failed to calculate current checksum: %w", err)
	}

	savedSum := string(savedSumBytes)

	if currentSum != savedSum {
		return fmt.Errorf("INTEGRITY_VIOLATION: Config checksum mismatch! Expected %s, got %s", savedSum, currentSum)
	}

	return nil
}

func (p *Provider) SendNotification(message string) error {
	p.mu.RLock()
	cfg := p.config.Notifications
	p.mu.RUnlock()

	if !cfg.Enabled || cfg.Token == "" || cfg.ChatID == "" {
		return nil
	}

	fullMsg := fmt.Sprintf("🔒 *%s*\n\n%s\n\n🕒 %s", hostName, message, time.Now().Format(time.RFC1123))

	apiURL := fmt.Sprintf(telegramAPI, cfg.Token)
	vals := url.Values{
		"chat_id":    {cfg.ChatID},
		"text":       {fullMsg},
		"parse_mode": {"Markdown"},
	}
	postReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, apiURL, strings.NewReader(vals.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(postReq)

	if err != nil {
		return fmt.Errorf("failed to send telegram notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram api error: %s", string(body))
	}

	return nil
}

func (p *Provider) AlertAndDie(reason string) {
	fmt.Printf("CRITICAL SECURITY ALERT: %s\n", reason)

	done := make(chan struct{})
	go func() {
		_ = p.SendNotification(fmt.Sprintf("🚨 **CRITICAL SECURITY ALERT** 🚨\n\nServer is shutting down due to integrity violation!\n\nReason: %s", reason))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}

	os.Exit(1)
}
