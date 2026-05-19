package geoip

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"whispera/internal/logger"
)

var log = logger.Module("geoip")

type Service struct {
	db       *GeoIPDatabase
	dbPath   string
	mu       sync.RWMutex
	autoLoad bool
}

func NewService(dbPath string, autoLoad bool) *Service {
	service := &Service{
		db:       NewGeoIPDatabase(),
		dbPath:   dbPath,
		autoLoad: autoLoad,
	}

	if autoLoad {
		if err := service.Load(); err != nil {
			log.Warn("Failed to load database: %v", err)
		}
	}

	return service
}

func (s *Service) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dbPath == "" {
		return fmt.Errorf("database path not set")
	}

	if _, err := os.Stat(s.dbPath); os.IsNotExist(err) {
		return fmt.Errorf("geoip database file not found: %s", s.dbPath)
	}

	return s.db.LoadFromFile(s.dbPath)
}

func (s *Service) LookupCountry(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.LookupCountry(ip)
}

func (s *Service) LookupCountryByIP(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.LookupCountry(ip)
}

func (s *Service) IsInCountry(ipStr, countryCode string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.IsInCountry(ip, countryCode)
}

func (s *Service) GetCountryCIDRs(countryCode string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.GetCountryCIDRs(countryCode)
}

const DefaultGeoIPURL = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"

func (s *Service) DownloadDatabase() error {
	return s.DownloadDatabaseFrom(DefaultGeoIPURL)
}

func (s *Service) DownloadDatabaseFrom(url string) error {
	dir := filepath.Dir(s.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	log.Info("Downloading database from %s...", url)
	if err := DownloadGeoIP(url, s.dbPath); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}

	log.Info("Database downloaded successfully to %s", s.dbPath)

	return s.Load()
}

func (s *Service) EnsureDatabase() error {
	if _, err := os.Stat(s.dbPath); os.IsNotExist(err) {
		log.Info("Database not found, downloading...")
		return s.DownloadDatabase()
	}

	return s.Load()
}
