package wiraid

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ValidateReport struct {
	Name         string            `json:"name"`
	Schema       int               `json:"schema"`
	WiraidID     string            `json:"wiraid_id,omitempty"`
	PeerID       string            `json:"peer_id,omitempty"`
	BinaryPath   string            `json:"binary_path"`
	BinaryExists bool              `json:"binary_exists"`
	ConfigPath   string            `json:"config_path"`
	ConfigSample string            `json:"config_sample,omitempty"`
	RenderedCmd  []string          `json:"rendered_cmd"`
	PreCmds      [][]string        `json:"pre_cmds,omitempty"`
	PostCmds     [][]string        `json:"post_cmds,omitempty"`
	Params       map[string]string `json:"params"`
	MissingParam []string          `json:"missing_params,omitempty"`
	PairExports  map[string]string `json:"pair_exports_rendered,omitempty"`
	PublicHost   string            `json:"public_host"`
	Warnings     []string          `json:"warnings,omitempty"`
	Errors       []string          `json:"errors,omitempty"`
}

func (e *Engine) Validate(name string) (*ValidateReport, error) {
	m, ok := e.Registry.Get(name)
	if !ok {
		return nil, fmt.Errorf("module %q not found", name)
	}
	m.Manifest.UpgradeToV2()
	rt := m.Manifest.Runtime

	rep := &ValidateReport{
		Name:       name,
		Schema:     m.Manifest.Schema,
		WiraidID:   m.Manifest.Module.WiraidID,
		BinaryPath: m.Binary,
		Params:     m.Params,
		PublicHost: os.Getenv("WHISPERA_PUBLIC_HOST"),
	}
	if m.Manifest.Module.Peer != nil {
		rep.PeerID = m.Manifest.Module.Peer.ID
	}

	if m.Binary == "" {
		rep.Errors = append(rep.Errors, "binary not built (run: whispera wiraid rebuild "+name+")")
	} else if _, err := os.Stat(m.Binary); err != nil {
		rep.Errors = append(rep.Errors, "binary missing on disk: "+m.Binary)
	} else {
		rep.BinaryExists = true
	}

	for k, schema := range m.Manifest.ParamsSchema {
		if _, ok := m.Params[k]; ok {
			continue
		}
		if schema.Required {
			rep.MissingParam = append(rep.MissingParam, k)
		}
	}
	if len(rep.MissingParam) > 0 {
		rep.Errors = append(rep.Errors, "missing required params: "+strings.Join(rep.MissingParam, ", "))
	}

	configPath := rt.ConfigPath
	if configPath == "" {
		configPath = "config.json"
	}
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(m.Dir, configPath)
	}
	rep.ConfigPath = configPath

	ctx := &RenderContext{
		Binary:       m.Binary,
		ModuleDir:    m.Dir,
		ConfigPath:   configPath,
		ListenHost:   "127.0.0.1",
		ListenPort:   10800,
		UpstreamHost: "127.0.0.1",
		UpstreamPort: 1080,
		Params:       m.Params,
	}

	rep.RenderedCmd = ctx.RenderAll(rt.Cmd)
	if len(rep.RenderedCmd) == 0 {
		rep.Errors = append(rep.Errors, "empty rendered cmd")
	}
	for _, pre := range rt.PreCmd {
		if r := ctx.RenderAll(pre); len(r) > 0 {
			rep.PreCmds = append(rep.PreCmds, r)
		}
	}
	for _, post := range rt.PostCmd {
		if r := ctx.RenderAll(post); len(r) > 0 {
			rep.PostCmds = append(rep.PostCmds, r)
		}
	}

	if rt.ConfigTemplate != "" {
		rep.ConfigSample = ctx.Render(rt.ConfigTemplate)
	}

	if len(m.Manifest.Module.PairExports) > 0 {
		rep.PairExports = make(map[string]string, len(m.Manifest.Module.PairExports))
		serverHost := rep.PublicHost
		if serverHost == "" {
			rep.Warnings = append(rep.Warnings, "WHISPERA_PUBLIC_HOST not set — pair_exports will have empty {server_host}")
		}
		for k, tmpl := range m.Manifest.Module.PairExports {
			rep.PairExports[k] = ctx.Render(strings.ReplaceAll(tmpl, "{server_host}", serverHost))
		}
	}

	if _, unresolved := findUnresolvedPlaceholders(rep.RenderedCmd); unresolved {
		rep.Warnings = append(rep.Warnings, "cmd still contains unresolved {placeholders} after render")
	}
	if rep.ConfigSample != "" {
		if strings.Contains(rep.ConfigSample, "{params.") || strings.Contains(rep.ConfigSample, "{server_host}") {
			rep.Warnings = append(rep.Warnings, "config_template still contains unresolved placeholders after render")
		}
	}

	return rep, nil
}

func findUnresolvedPlaceholders(parts []string) ([]string, bool) {
	var out []string
	for _, p := range parts {
		if i := strings.IndexByte(p, '{'); i >= 0 {
			if j := strings.IndexByte(p[i:], '}'); j > 0 {
				out = append(out, p[i:i+j+1])
			}
		}
	}
	return out, len(out) > 0
}
