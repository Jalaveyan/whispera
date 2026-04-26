package wiraid

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type runningProc struct {
	cmd        *exec.Cmd
	listenPort int
}

type Engine struct {
	Registry  *Registry
	mu        sync.Mutex
	running   map[string]*runningProc
	useSystemd bool
}

func NewEngine(baseDir string) (*Engine, error) {
	reg, err := LoadRegistry(baseDir)
	if err != nil {
		return nil, err
	}
	useSystemd := os.Getenv("WHISPERA_WIRAID_SYSTEMD") == "1"
	return &Engine{
		Registry:   reg,
		running:    make(map[string]*runningProc),
		useSystemd: useSystemd,
	}, nil
}

func (e *Engine) InstallFromURL(url string) (string, error) {
	if st, err := os.Stat(url); err == nil && st.IsDir() {
		name := sanitizeModuleName(strings.ToLower(filepath.Base(url)))
		moduleDir := filepath.Join(e.Registry.BaseDir(), name)
		if err := copyDir(url, moduleDir); err != nil {
			return "", fmt.Errorf("copy %s → %s: %w", url, moduleDir, err)
		}
		manifest, err := e.detectOrCreateManifest(moduleDir, name)
		if err != nil {
			return "", err
		}
		binary := ""
		if b, err := e.tryBuild(moduleDir, manifest); err == nil {
			binary = b
		}
		im := &InstalledModule{Manifest: manifest, Dir: moduleDir, Binary: binary}
		_, _ = FillMissingParams(im)
		if err := e.Registry.Add(im); err != nil {
			return "", err
		}
		return name, nil
	}

	name := RepoNameFromURL(url)
	moduleDir := filepath.Join(e.Registry.BaseDir(), name)

	if strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tgz") ||
		strings.HasSuffix(url, ".zip") || strings.Contains(url, "/releases/download/") {
		if err := os.MkdirAll(moduleDir, 0o755); err != nil {
			return "", err
		}
		bin, err := DownloadBinary(url, moduleDir)
		if err != nil {
			return "", err
		}
		manifest := ScaffoldManifest(name, LangBinary)
		if err := SaveManifest(moduleDir, manifest); err != nil {
			return "", err
		}
		im := &InstalledModule{
			Manifest: manifest,
			Dir:      moduleDir,
			Binary:   bin,
		}
		_, _ = FillMissingParams(im)
		if err := e.Registry.Add(im); err != nil {
			return "", err
		}
		return name, nil
	}

	if err := GitClone(url, moduleDir); err != nil {
		return "", err
	}
	manifest, err := e.detectOrCreateManifest(moduleDir, name)
	if err != nil {
		return "", err
	}
	binary := ""
	if b, err := e.tryBuild(moduleDir, manifest); err == nil {
		binary = b
	}
	im := &InstalledModule{
		Manifest: manifest,
		Dir:      moduleDir,
		Binary:   binary,
	}
	_, _ = FillMissingParams(im)
	if err := e.Registry.Add(im); err != nil {
		return "", err
	}
	return name, nil
}

// copyDir: src → dst recursive. Used by InstallFromURL local-path branch.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

func (e *Engine) Uninstall(name string) error {
	e.Stop(name)
	m, ok := e.Registry.Get(name)
	if !ok {
		return fmt.Errorf("module %q not found", name)
	}
	dir := m.Dir
	if err := e.Registry.Remove(name); err != nil {
		return err
	}
	_ = os.RemoveAll(dir)
	return nil
}

func (e *Engine) Rebuild(name string) error {
	m, ok := e.Registry.Get(name)
	if !ok {
		return fmt.Errorf("module %q not found", name)
	}
	bin, err := BuildModule(m.Dir, m.Manifest.Module.Lang, m.Manifest.Module.Entry, m.Manifest.Module.Name)
	if err != nil {
		return err
	}
	m.Binary = bin
	return e.Registry.Save()
}

func (e *Engine) Start(name string, upstreamPort int) (int, error) {
	m, ok := e.Registry.Get(name)
	if !ok {
		return 0, fmt.Errorf("module %q not found", name)
	}
	if e.useSystemd {
		return e.startSystemd(m)
	}
	if m.Binary == "" {
		return 0, fmt.Errorf("module %q has no binary", name)
	}
	if _, err := os.Stat(m.Binary); err != nil {
		return 0, fmt.Errorf("binary missing: %s", m.Binary)
	}
	if changed, err := FillMissingParams(m); err == nil && changed {
		_ = e.Registry.Save()
	}
	m.Manifest.UpgradeToV2()
	rt := m.Manifest.Runtime

	port, err := findFreePort()
	if err != nil {
		return 0, err
	}

	configPath := rt.ConfigPath
	if configPath == "" {
		configPath = "config.json"
	}
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(m.Dir, configPath)
	}

	ctx := &RenderContext{
		Binary:     m.Binary,
		ModuleDir:  m.Dir,
		ConfigPath: configPath,
		ListenHost: "127.0.0.1",
		ListenPort: port,
		ServerHost: os.Getenv("WHISPERA_PUBLIC_HOST"),
		Params:     m.Params,
	}
	if upstreamPort > 0 {
		ctx.UpstreamHost = "127.0.0.1"
		ctx.UpstreamPort = upstreamPort
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return 0, err
	}
	selectedTemplate := rt.ConfigTemplate
	if rt.ConfigTemplateFile != "" {
		tmplPath := rt.ConfigTemplateFile
		if !filepath.IsAbs(tmplPath) {
			tmplPath = filepath.Join(m.Dir, tmplPath)
		}
		if data, err := os.ReadFile(tmplPath); err == nil {
			selectedTemplate = string(data)
		}
	}
	if selectedTemplate != "" {
		rendered := ctx.RenderTemplate(selectedTemplate)
		if err := os.WriteFile(configPath, []byte(rendered), 0o644); err != nil {
			return 0, fmt.Errorf("write config: %w", err)
		}
	} else if _, err := os.Stat(configPath); err != nil {
		cfgData := map[string]interface{}{
			"listen": fmt.Sprintf("127.0.0.1:%d", port),
		}
		if upstreamPort > 0 {
			cfgData["upstream"] = fmt.Sprintf("127.0.0.1:%d", upstreamPort)
		}
		for k, v := range m.Params {
			cfgData[k] = v
		}
		if data, err := json.MarshalIndent(cfgData, "", "  "); err == nil {
			_ = os.WriteFile(configPath, data, 0o644)
		}
	}

	for i, pre := range rt.PreCmd {
		parts := ctx.RenderAll(pre)
		if len(parts) == 0 {
			continue
		}
		pc := exec.CommandContext(context.Background(), parts[0], parts[1:]...)
		pc.Dir = m.Dir
		pc.Stdout = os.Stderr
		pc.Stderr = os.Stderr
		if len(rt.Env) > 0 {
			pc.Env = os.Environ()
			for k, v := range rt.Env {
				pc.Env = append(pc.Env, k+"="+ctx.Render(v))
			}
		}
		if err := pc.Run(); err != nil {
			return 0, fmt.Errorf("pre_cmd[%d] failed: %w", i, err)
		}
	}

	cmdParts := ctx.RenderAll(rt.Cmd)
	if len(cmdParts) == 0 {
		return 0, fmt.Errorf("empty cmd template")
	}
	exe := cmdParts[0]
	args := cmdParts[1:]
	if m.Manifest.Module.Lang == LangPython && exe == m.Binary {
		exe = "python3"
		args = append([]string{m.Binary}, args...)
	}

	cmd := exec.CommandContext(context.Background(), exe, args...)
	cmd.Dir = m.Dir
	if len(rt.Env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range rt.Env {
			cmd.Env = append(cmd.Env, k+"="+ctx.Render(v))
		}
	}

	needStdoutScan := rt.Ready.Mode == "stdout_contains" || rt.PortDiscovery.Mode == "stdout_regex"
	var stdoutPipe io.ReadCloser
	if needStdoutScan {
		p, err := cmd.StdoutPipe()
		if err != nil {
			return 0, err
		}
		stdoutPipe = p
	} else {
		cmd.Stdout = os.Stderr
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start failed: %w", err)
	}

	discoveredPort := port
	readyOK := true
	if needStdoutScan {
		var portRe *regexp.Regexp
		if rt.PortDiscovery.Mode == "stdout_regex" && rt.PortDiscovery.Pattern != "" {
			portRe, _ = regexp.Compile(rt.PortDiscovery.Pattern)
		}
		readyOK = false
		done := make(chan struct{})
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			gotPort := portRe == nil
			gotReady := rt.Ready.Mode != "stdout_contains"
			for scanner.Scan() {
				line := scanner.Text()
				fmt.Fprintln(os.Stderr, line)
				if !gotPort && portRe != nil {
					if mt := portRe.FindStringSubmatch(line); len(mt) > 1 {
						if p, err := strconv.Atoi(mt[1]); err == nil {
							discoveredPort = p
							gotPort = true
						}
					}
				}
				if !gotReady && strings.Contains(line, rt.Ready.Value) {
					gotReady = true
				}
				if gotPort && gotReady {
					select {
					case <-done:
					default:
						close(done)
					}
				}
			}
			io.Copy(io.Discard, stdoutPipe)
		}()
		timeout := time.Duration(rt.Ready.Timeout) * time.Millisecond
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		select {
		case <-done:
			readyOK = true
		case <-time.After(timeout):
		}
	} else {
		switch rt.Ready.Mode {
		case "tcp_connect":
			readyOK = waitTCP("127.0.0.1", discoveredPort, time.Duration(rt.Ready.Timeout)*time.Millisecond)
		default:
			d := time.Duration(rt.Ready.Timeout) * time.Millisecond
			if d <= 0 {
				d = 200 * time.Millisecond
			}
			time.Sleep(d)
		}
	}

	if rt.PortDiscovery.Mode == "file" && rt.PortDiscovery.File != "" {
		fp := rt.PortDiscovery.File
		if !filepath.IsAbs(fp) {
			fp = filepath.Join(m.Dir, fp)
		}
		if data, err := os.ReadFile(fp); err == nil {
			if p, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				discoveredPort = p
			}
		}
	}

	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return 0, fmt.Errorf("module exited immediately")
	}
	if !readyOK {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("module not ready within timeout")
	}

	e.mu.Lock()
	e.running[name] = &runningProc{cmd: cmd, listenPort: discoveredPort}
	e.mu.Unlock()
	return discoveredPort, nil
}

func waitTCP(host string, port int, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{Timeout: 200 * time.Millisecond}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		c, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
		cancel()
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (e *Engine) Stop(name string) error {
	if e.useSystemd {
		return exec.CommandContext(context.Background(), "systemctl", "stop", "whispera-wiraid@"+name+".service").Run()
	}
	e.mu.Lock()
	rp, ok := e.running[name]
	if ok {
		delete(e.running, name)
	}
	e.mu.Unlock()
	if !ok {
		return nil
	}
	if rp.cmd.Process != nil {
		rp.cmd.Process.Kill()
		rp.cmd.Wait()
	}
	if m, ok := e.Registry.Get(name); ok && len(m.Manifest.Runtime.PostCmd) > 0 {
		ctx := &RenderContext{
			Binary:    m.Binary,
			ModuleDir: m.Dir,
			Params:    m.Params,
		}
		for _, post := range m.Manifest.Runtime.PostCmd {
			parts := ctx.RenderAll(post)
			if len(parts) == 0 {
				continue
			}
			pc := exec.CommandContext(context.Background(), parts[0], parts[1:]...)
			pc.Dir = m.Dir
			pc.Stdout = os.Stderr
			pc.Stderr = os.Stderr
			_ = pc.Run()
		}
	}
	return nil
}

func (e *Engine) startSystemd(m *InstalledModule) (int, error) {
	unit := "whispera-wiraid@" + m.Manifest.Module.Name + ".service"
	if out, err := exec.CommandContext(context.Background(), "systemctl", "start", unit).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("systemctl start %s: %s", unit, string(out))
	}
	port := 0
	configPath := filepath.Join(m.Dir, "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var cfg map[string]interface{}
		if json.Unmarshal(data, &cfg) == nil {
			if listen, ok := cfg["listen"].(string); ok {
				if i := strings.LastIndex(listen, ":"); i >= 0 {
					_, _ = fmt.Sscanf(listen[i+1:], "%d", &port)
				}
			}
		}
	}
	return port, nil
}

func (e *Engine) StartEnabled() {
	for _, m := range e.Registry.List() {
		if !m.Enabled || m.Binary == "" {
			continue
		}
		name := m.Manifest.Module.Name
		if e.IsRunning(name) {
			continue
		}
		port, err := e.Start(name, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[wiraid] auto-start %q failed: %v\n", name, err)
		} else {
			fmt.Fprintf(os.Stderr, "[wiraid] auto-started %q on port %d\n", name, port)
		}
	}
}

func (e *Engine) StopAll() {
	e.mu.Lock()
	procs := e.running
	e.running = make(map[string]*runningProc)
	e.mu.Unlock()
	for _, rp := range procs {
		if rp.cmd.Process != nil {
			rp.cmd.Process.Kill()
			rp.cmd.Wait()
		}
	}
}

func (e *Engine) IsRunning(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.running[name]
	return ok
}

func (e *Engine) RunningPort(name string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rp, ok := e.running[name]; ok {
		return rp.listenPort
	}
	return 0
}

func (e *Engine) detectOrCreateManifest(dir, name string) (Manifest, error) {
	if _, err := os.Stat(filepath.Join(dir, "module.json")); err == nil {
		return LoadManifest(dir)
	}
	lang := LangBinary
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		lang = LangGo
	} else if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
		lang = LangGo
	} else if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
		lang = LangRust
	} else if _, err := os.Stat(filepath.Join(dir, "main.py")); err == nil {
		lang = LangPython
	} else if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		lang = LangPython
	} else if _, err := os.Stat(filepath.Join(dir, "CMakeLists.txt")); err == nil {
		lang = LangC
	} else if _, err := os.Stat(filepath.Join(dir, "main.c")); err == nil {
		lang = LangC
	} else if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
		lang = LangC
	}
	entry := ""
	if lang == LangGo {
		if _, err := os.Stat(filepath.Join(dir, "cmd")); err == nil {
			entry = detectGoEntry(dir)
		} else {
			entry = "."
		}
	}
	m := ScaffoldManifest(name, lang)
	m.Module.Entry = entry
	if err := SaveManifest(dir, m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (e *Engine) tryBuild(dir string, m Manifest) (string, error) {
	buildDir := dir
	if m.Module.Entry != "" {
		candidate := filepath.Join(dir, m.Module.Entry)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			buildDir = candidate
		}
	}
	return BuildModule(buildDir, m.Module.Lang, m.Module.Entry, m.Module.Name)
}

func detectGoEntry(dir string) string {
	cmdDir := filepath.Join(dir, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		return "."
	}
	for _, e := range entries {
		if e.IsDir() {
			return "./cmd/" + e.Name()
		}
	}
	return "."
}

func findFreePort() (int, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
