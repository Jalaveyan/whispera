package wiraid

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ModuleLang string

const (
	LangGo     ModuleLang = "go"
	LangRust   ModuleLang = "rust"
	LangBinary ModuleLang = "binary"
	LangPython ModuleLang = "python"
	LangC      ModuleLang = "c"
)

type Capabilities struct {
	Transport bool `json:"transport"`
	DNS       bool `json:"dns"`
	Filter    bool `json:"filter"`
	Analyzer  bool `json:"analyzer"`
	Tool      bool `json:"tool"`
}

type ModuleInfo struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Author      string     `json:"author"`
	Source      string     `json:"source"`
	Lang        ModuleLang `json:"lang"`
	Entry       string     `json:"entry"`
	Platforms   []string   `json:"platforms"`
	Args        []string   `json:"args"`
	WiraidID          string            `json:"wiraid_id,omitempty"`
	Peer              *PeerSpec         `json:"peer,omitempty"`
	PairExports       map[string]string `json:"pair_exports,omitempty"`
	URI               *URISpec          `json:"uri,omitempty"`
	URIExportTemplate string            `json:"uri_export_template,omitempty"`
}

type URISpec struct {
	Schemes         []string          `json:"schemes,omitempty"`
	Style           string            `json:"style,omitempty"`
	SchemeTo        string            `json:"scheme_to,omitempty"`
	UserinfoTo      string            `json:"userinfo_to,omitempty"`
	UserinfoUserTo  string            `json:"userinfo_user_to,omitempty"`
	UserinfoPassTo  string            `json:"userinfo_pass_to,omitempty"`
	HostTo          string            `json:"host_to,omitempty"`
	PortTo          string            `json:"port_to,omitempty"`
	PathTo          string            `json:"path_to,omitempty"`
	FragmentTo      string            `json:"fragment_to,omitempty"`
	RawTo           string            `json:"raw_to,omitempty"`
	QueryMap        map[string]string `json:"query_map,omitempty"`
	JSONMap         map[string]string `json:"json_map,omitempty"`
	QueryConditions map[string]string `json:"query_conditions,omitempty"`
}

type PeerSpec struct {
	ID         string `json:"id"`
	MinVersion string `json:"min_version,omitempty"`
}

type ManifestTransport struct {
	Listen   string `json:"listen,omitempty"`
	Upstream string `json:"upstream,omitempty"`
}

type ManifestAPI struct {
	Health string `json:"health,omitempty"`
}

type PortDiscovery struct {
	Mode    string `json:"mode,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	File    string `json:"file,omitempty"`
}

type ReadySignal struct {
	Mode    string `json:"mode,omitempty"`
	Value   string `json:"value,omitempty"`
	Timeout int    `json:"timeout_ms,omitempty"`
}

type Runtime struct {
	Cmd              []string          `json:"cmd,omitempty"`
	PreCmd           [][]string        `json:"pre_cmd,omitempty"`
	PostCmd          [][]string        `json:"post_cmd,omitempty"`
	Env              map[string]string `json:"env,omitempty"`
	ConfigTemplate     string `json:"config_template,omitempty"`
	ConfigTemplateFile string `json:"config_template_file,omitempty"`
	ConfigPath         string `json:"config_path,omitempty"`
	Protocol         string            `json:"protocol,omitempty"`
	PortDiscovery    PortDiscovery     `json:"port_discovery,omitempty"`
	Ready            ReadySignal       `json:"ready_signal,omitempty"`
}

type ParamSchema struct {
	Type        string   `json:"type,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Default     string   `json:"default,omitempty"`
	Description string   `json:"description,omitempty"`
	Generator   string   `json:"generator,omitempty"`
	Length      int      `json:"length,omitempty"`
	Value       string   `json:"value,omitempty"`
	Env         string   `json:"env,omitempty"`
	ExecCmd     []string `json:"exec_cmd,omitempty"`
	ExecRegex   string   `json:"exec_regex,omitempty"`
	ExecGroup   int      `json:"exec_group,omitempty"`
}

type Manifest struct {
	Schema       int                    `json:"schema,omitempty"`
	Module       ModuleInfo             `json:"module"`
	Capabilities Capabilities           `json:"capabilities"`
	Transport    ManifestTransport      `json:"transport"`
	API          ManifestAPI            `json:"api"`
	Runtime      Runtime                `json:"runtime,omitempty"`
	ParamsSchema map[string]ParamSchema `json:"params_schema,omitempty"`
}

func (m *Manifest) UpgradeToV2() {
	if m.Schema >= 2 {
		return
	}
	m.Schema = 2
	if len(m.Runtime.Cmd) == 0 {
		m.Runtime.Cmd = []string{"{binary}"}
	}
	if m.Runtime.ConfigPath == "" {
		m.Runtime.ConfigPath = "config.json"
	}
	if m.Runtime.Protocol == "" {
		m.Runtime.Protocol = "socks5"
	}
	if m.Runtime.PortDiscovery.Mode == "" {
		m.Runtime.PortDiscovery.Mode = "fixed"
	}
	if m.Runtime.Ready.Mode == "" {
		m.Runtime.Ready.Mode = "delay"
		if m.Runtime.Ready.Timeout == 0 {
			m.Runtime.Ready.Timeout = 500
		}
	}
}

func ScaffoldManifest(name string, lang ModuleLang) Manifest {
	m := Manifest{
		Schema: 2,
		Module: ModuleInfo{
			Name:      name,
			Version:   "0.1.0",
			Lang:      lang,
			Platforms: []string{"linux-x86_64"},
		},
		Capabilities: Capabilities{Transport: true},
		API:          ManifestAPI{Health: "/health"},
		Runtime: Runtime{
			Cmd:           []string{"{binary}", "--listen", "127.0.0.1:{listen_port}", "--config", "{config_path}"},
			ConfigPath:    "config.json",
			Protocol:      "socks5",
			PortDiscovery: PortDiscovery{Mode: "fixed"},
			Ready:         ReadySignal{Mode: "delay", Timeout: 200},
		},
	}
	return m
}

func LoadManifest(dir string) (Manifest, error) {
	path := filepath.Join(dir, "module.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	m.UpgradeToV2()
	return m, nil
}

func SaveManifest(dir string, m Manifest) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "module.json"), data, 0o644)
}
