package geosite

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"whispera/internal/logger"
)

var log = logger.Module("geosite")

type Service struct {
	db       *GeoSiteDatabase
	dbPath   string
	mu       sync.RWMutex
	autoLoad bool
}

func NewService(dbPath string, autoLoad bool) *Service {
	service := &Service{
		db:       NewGeoSiteDatabase(),
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
		return fmt.Errorf("geosite database file not found: %s", s.dbPath)
	}

	return s.db.LoadFromFile(s.dbPath)
}

func (s *Service) GetDomains(countryCode string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.GetDomains(countryCode)
}

func (s *Service) IsDomainInCountry(domain, countryCode string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.IsDomainInCountry(domain, countryCode)
}

const DefaultGeoSiteURL = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"

func (s *Service) DownloadDatabase() error {
	return s.DownloadDatabaseFrom(DefaultGeoSiteURL)
}

func (s *Service) DownloadDatabaseFrom(url string) error {
	dir := filepath.Dir(s.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	log.Info("Downloading database from %s...", url)
	if err := DownloadGeoSite(url, s.dbPath); err != nil {
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

func (s *Service) GetCategories(countryCode string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.GetCategories(countryCode)
}

func (s *Service) IsDomainInCategory(domain, category string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.IsDomainInCategory(domain, category)
}
