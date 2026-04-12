package wiraid

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type LiveReport struct {
	*ValidateReport
	Live       bool     `json:"live"`
	MockBinary string   `json:"mock_binary"`
	StartedOK  bool     `json:"started_ok"`
	ExitedOK   bool     `json:"exited_ok"`
	LivePort   int      `json:"live_port,omitempty"`
	Steps      []string `json:"steps"`
	LiveError  string   `json:"live_error,omitempty"`
}

// LiveValidate runs the module through the real engine.Start/Stop path
// with a mock binary, to verify that templates render, the process
// lifecycle works, and Stop cleans up. It does NOT test the real
// bypass tool — use a real binary for that.
func (e *Engine) LiveValidate(name string) (*LiveReport, error) {
	base, err := e.Validate(name)
	if err != nil {
		return nil, err
	}
	rep := &LiveReport{ValidateReport: base, Live: true}

	m, ok := e.Registry.Get(name)
	if !ok {
		return rep, fmt.Errorf("module %q not found", name)
	}
	if len(base.Errors) > 0 {
		rep.LiveError = "static validate has errors, skipping live run"
		return rep, nil
	}

	tmpDir, err := os.MkdirTemp("", "wiraid-live-"+name+"-*")
	if err != nil {
		rep.LiveError = "mkdtemp: " + err.Error()
		return rep, nil
	}
	defer os.RemoveAll(tmpDir)
	rep.Steps = append(rep.Steps, "tmpdir="+tmpDir)

	cloneDir := filepath.Join(tmpDir, "clone")
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		rep.LiveError = "mkdir clone: " + err.Error()
		return rep, nil
	}

	// Pick a free port ourselves so mock can bind to it
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		rep.LiveError = "pick port: " + err.Error()
		return rep, nil
	}
	livePort := l.Addr().(*net.TCPAddr).Port
	l.Close()
	rep.LivePort = livePort

	mockPath := filepath.Join(cloneDir, "mock.sh")
	mockScript := "#!/bin/sh\n" +
		"echo \"wiraid-mock READY on ${LIVE_PORT}\"\n" +
		"python3 -c 'import socket,sys,time,os\n" +
		"s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n" +
		"s.bind((\"127.0.0.1\", int(os.environ[\"LIVE_PORT\"]))); s.listen(1)\n" +
		"print(\"mock listening\", flush=True)\n" +
		"time.sleep(3)' 2>/dev/null || sleep 3\n"
	if err := os.WriteFile(mockPath, []byte(mockScript), 0o755); err != nil {
		rep.LiveError = "write mock: " + err.Error()
		return rep, nil
	}
	rep.MockBinary = mockPath
	rep.Steps = append(rep.Steps, "mock written")

	// Clone the installed module with mock binary, cleared pre/post,
	// and forced ready=delay so we don't depend on tool-specific signals.
	clonedManifest := m.Manifest
	clonedManifest.Runtime.Cmd = []string{"sh", mockPath}
	clonedManifest.Runtime.PreCmd = nil
	clonedManifest.Runtime.PostCmd = nil
	clonedManifest.Runtime.PortDiscovery = PortDiscovery{Mode: "fixed"}
	clonedManifest.Runtime.Ready = ReadySignal{Mode: "delay", Timeout: 400}
	clonedManifest.Runtime.Env = map[string]string{"LIVE_PORT": strconv.Itoa(livePort)}

	testName := name + "@livetest-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	clonedManifest.Module.Name = testName
	tmpMod := &InstalledModule{
		Manifest: clonedManifest,
		Dir:      cloneDir,
		Binary:   mockPath,
		Params:   m.Params,
	}
	if err := e.Registry.Add(tmpMod); err != nil {
		rep.LiveError = "registry add: " + err.Error()
		return rep, nil
	}
	defer e.Registry.Remove(testName)

	port, err := e.Start(testName, 0)
	if err != nil {
		rep.LiveError = "engine.Start: " + err.Error()
		return rep, nil
	}
	rep.StartedOK = true
	rep.Steps = append(rep.Steps, fmt.Sprintf("started, engine port=%d", port))

	if err := e.Stop(testName); err != nil {
		rep.LiveError = "engine.Stop: " + err.Error()
		return rep, nil
	}
	rep.ExitedOK = true
	rep.Steps = append(rep.Steps, "stopped cleanly")

	cfgPath := base.ConfigPath
	if cfgPath != "" && !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(cloneDir, filepath.Base(cfgPath))
	}
	if _, err := os.Stat(cfgPath); err == nil {
		rep.Steps = append(rep.Steps, "config file materialized at "+cfgPath)
	}

	return rep, nil
}
