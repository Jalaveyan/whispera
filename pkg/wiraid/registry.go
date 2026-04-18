package wiraid

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type InstalledModule struct {
	Manifest    Manifest          `json:"manifest"`
	Dir         string            `json:"dir"`
	Binary      string            `json:"binary,omitempty"`
	Enabled     bool              `json:"enabled"`
	InstalledAt int64             `json:"installed_at"`
	Params      map[string]string `json:"params,omitempty"`
}

type Registry struct {
	mu      sync.RWMutex
	baseDir string
	path    string
	modules map[string]*InstalledModule
}

func LoadRegistry(baseDir string) (*Registry, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	r := &Registry{
		baseDir: baseDir,
		path:    filepath.Join(baseDir, "registry.json"),
		modules: make(map[string]*InstalledModule),
	}
	if data, err := os.ReadFile(r.path); err == nil {
		var list []*InstalledModule
		if err := json.Unmarshal(data, &list); err == nil {
			for _, m := range list {
				if m != nil && m.Manifest.Module.Name != "" {
					r.modules[m.Manifest.Module.Name] = m
				}
			}
		}
	}
	return r, nil
}

func (r *Registry) save() error {
	list := make([]*InstalledModule, 0, len(r.modules))
	for _, m := range r.modules {
		list = append(list, m)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0o644)
}

func (r *Registry) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.save()
}

func (r *Registry) Add(m *InstalledModule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m.InstalledAt == 0 {
		m.InstalledAt = time.Now().Unix()
	}
	r.modules[m.Manifest.Module.Name] = m
	return r.save()
}

func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.modules[name]; !ok {
		return fmt.Errorf("module %q not found", name)
	}
	delete(r.modules, name)
	return r.save()
}

func (r *Registry) Get(name string) (*InstalledModule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[name]
	return m, ok
}

func (r *Registry) SetEnabled(name string, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.modules[name]
	if !ok {
		return fmt.Errorf("module %q not found", name)
	}
	m.Enabled = enabled
	if enabled {
		_, _ = FillMissingParams(m)
	}
	return r.save()
}

func (r *Registry) SetParams(name string, params map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.modules[name]
	if !ok {
		return fmt.Errorf("module %q not found", name)
	}
	m.Params = params
	return r.save()
}

func (r *Registry) List() []*InstalledModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*InstalledModule, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m)
	}
	return out
}

func (r *Registry) BaseDir() string {
	return r.baseDir
}
