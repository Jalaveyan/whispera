package wiraid

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

type ModuleSummary struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Description  string       `json:"description"`
	Lang         ModuleLang   `json:"lang"`
	Capabilities Capabilities `json:"capabilities"`
	Enabled      bool         `json:"enabled"`
	HasBinary    bool         `json:"has_binary"`
	Running      bool         `json:"running"`
	Port         int          `json:"port,omitempty"`
}

func (e *Engine) Summaries() []ModuleSummary {
	mods := e.Registry.List()
	out := make([]ModuleSummary, 0, len(mods))
	for _, m := range mods {
		out = append(out, ModuleSummary{
			Name:         m.Manifest.Module.Name,
			Version:      m.Manifest.Module.Version,
			Description:  m.Manifest.Module.Description,
			Lang:         m.Manifest.Module.Lang,
			Capabilities: m.Manifest.Capabilities,
			Enabled:      m.Enabled,
			HasBinary:    m.Binary != "",
			Running:      e.IsRunning(m.Manifest.Module.Name),
			Port:         e.RunningPort(m.Manifest.Module.Name),
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (e *Engine) RegisterRoutes(handle func(pattern string, handler http.HandlerFunc)) {
	handle("/api/wiraid/public/list", e.handlePublicList)
	handle("/api/wiraid/public/pair/", e.handlePairConfig)
	handle("/api/wiraid/public/uri/", e.handlePublicURI)
	handle("/api/wiraid/list", e.handleList)
	handle("/api/wiraid/install", e.handleInstall)
	handle("/api/wiraid/uninstall", e.handleUninstall)
	handle("/api/wiraid/enable", e.handleEnable)
	handle("/api/wiraid/start", e.handleStart)
	handle("/api/wiraid/stop", e.handleStop)
	handle("/api/wiraid/rebuild", e.handleRebuild)
	handle("/api/wiraid/status", e.handleStatus)
}

func (e *Engine) handlePairConfig(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/wiraid/public/pair/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "wiraid_id required")
		return
	}
	// Optional: client can advertise its minimum required server version
	clientMinVer := r.Header.Get("X-Min-Version")

	serverHost := os.Getenv("WHISPERA_PUBLIC_HOST")
	for _, m := range e.Registry.List() {
		if !m.Enabled {
			continue
		}
		if m.Manifest.Module.WiraidID != id {
			continue
		}
		// Check version compatibility: server module must meet client's min requirement
		if clientMinVer != "" && !semverGTE(m.Manifest.Module.Version, clientMinVer) {
			writeError(w, http.StatusPreconditionFailed,
				"server module version "+m.Manifest.Module.Version+" < required "+clientMinVer)
			return
		}
		ctx := &RenderContext{
			Binary:     m.Binary,
			ModuleDir:  m.Dir,
			ListenHost: serverHost,
			ListenPort: e.RunningPort(m.Manifest.Module.Name),
			ServerHost: serverHost,
			Params:     m.Params,
		}
		exported := make(map[string]string, len(m.Manifest.Module.PairExports))
		for k, tmpl := range m.Manifest.Module.PairExports {
			exported[k] = ctx.Render(tmpl)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"wiraid_id":   id,
			"version":     m.Manifest.Module.Version,
			"server_host": serverHost,
			"params":      exported,
		})
		return
	}
	writeError(w, http.StatusNotFound, "no enabled module with this wiraid_id")
}

func (e *Engine) handlePublicURI(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/wiraid/public/uri/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "wiraid_id required")
		return
	}
	serverHost := os.Getenv("WHISPERA_PUBLIC_HOST")
	for _, m := range e.Registry.List() {
		if !m.Enabled || m.Manifest.Module.WiraidID != id {
			continue
		}
		tmpl := m.Manifest.Module.URIExportTemplate
		if tmpl == "" {
			writeError(w, http.StatusNotFound, "module has no uri_export_template")
			return
		}
		ctx := &RenderContext{
			Binary:     m.Binary,
			ModuleDir:  m.Dir,
			ListenHost: serverHost,
			ListenPort: e.RunningPort(m.Manifest.Module.Name),
			ServerHost: serverHost,
			Params:     m.Params,
		}
		uri := ctx.Render(tmpl)
		writeJSON(w, http.StatusOK, map[string]string{
			"wiraid_id": id,
			"uri":       uri,
		})
		return
	}
	writeError(w, http.StatusNotFound, "no enabled module with this wiraid_id")
}

type PublicModule struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	WiraidID  string    `json:"wiraid_id,omitempty"`
	Peer      *PeerSpec `json:"peer,omitempty"`
	Transport bool      `json:"transport"`
	Enabled   bool      `json:"enabled"`
	Running   bool      `json:"running"`
	HasURI    bool      `json:"has_uri,omitempty"`
}

func (e *Engine) handlePublicList(w http.ResponseWriter, r *http.Request) {
	mods := e.Registry.List()
	out := make([]PublicModule, 0, len(mods))
	for _, m := range mods {
		out = append(out, PublicModule{
			Name:      m.Manifest.Module.Name,
			Version:   m.Manifest.Module.Version,
			WiraidID:  m.Manifest.Module.WiraidID,
			Peer:      m.Manifest.Module.Peer,
			Transport: m.Manifest.Capabilities.Transport,
			Enabled:   m.Enabled,
			Running:   e.IsRunning(m.Manifest.Module.Name),
			HasURI:    m.Manifest.Module.URIExportTemplate != "",
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (e *Engine) handleList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, e.Summaries())
}

func (e *Engine) handleInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Source) == "" {
		writeError(w, http.StatusBadRequest, "source required")
		return
	}
	name, err := e.InstallFromURL(req.Source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (e *Engine) handleUninstall(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if err := e.Uninstall(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleEnable(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	enabled := r.URL.Query().Get("enabled") == "true"
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if err := e.Registry.SetEnabled(name, enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleStart(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	port, err := e.Start(name, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"port": port})
}

func (e *Engine) handleStop(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if err := e.Stop(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleRebuild(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if err := e.Rebuild(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (e *Engine) handleStatus(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	m, ok := e.Registry.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":       m.Manifest.Module.Name,
		"running":    e.IsRunning(name),
		"port":       e.RunningPort(name),
		"has_binary": m.Binary != "",
		"enabled":    m.Enabled,
	})
}
