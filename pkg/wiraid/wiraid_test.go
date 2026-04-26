package wiraid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findExamplesDir поднимается вверх от cwd пока не найдёт examples/wiraid/.
// Иначе go test ./... падает с относительным путём.
func findExamplesDir(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "examples", "wiraid")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("examples/wiraid not found — пропускаю смок-тест")
	return ""
}

// Все 22+ example модулей должны парситься без ошибок. Если кто-то добавил
// сломанный module.json — этот тест моментально его поймает.
func TestParseAllExampleManifests(t *testing.T) {
	root := findExamplesDir(t)
	if root == "" {
		return
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir %s: %v", root, err)
	}

	parsed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		modDir := filepath.Join(root, e.Name())
		manifestPath := filepath.Join(modDir, "module.json")
		if _, err := os.Stat(manifestPath); err != nil {
			continue
		}

		m, err := LoadManifest(modDir)
		if err != nil {
			t.Errorf("LoadManifest(%s): %v", e.Name(), err)
			continue
		}
		if m.Module.Name == "" {
			t.Errorf("%s: module.name empty", e.Name())
		}
		if m.Schema < 1 || m.Schema > 2 {
			t.Errorf("%s: schema = %d (want 1 или 2)", e.Name(), m.Schema)
		}
		// V2-апгрейд должен дать runtime.cmd.
		if len(m.Runtime.Cmd) == 0 {
			t.Errorf("%s: runtime.cmd empty after UpgradeToV2", e.Name())
		}
		parsed++
	}

	if parsed == 0 {
		t.Fatalf("0 manifests parsed — examples dir empty?")
	}
	t.Logf("parsed %d example manifests", parsed)
}

// Smoke: новый Engine на tempdir поднимается, list пустой.
func TestEngineNewEmpty(t *testing.T) {
	dir := t.TempDir()
	e, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.Registry == nil {
		t.Fatal("Registry nil")
	}
	if got := len(e.Registry.List()); got != 0 {
		t.Errorf("empty engine: registry size = %d want 0", got)
	}
}

// Полный install + validate flow через публичную API. После фикса
// InstallFromURL умеет local paths — README обещание сдержано.
func TestInstallExampleAndValidate(t *testing.T) {
	root := findExamplesDir(t)
	if root == "" {
		return
	}
	src := filepath.Join(root, "xray-client")
	if _, err := os.Stat(filepath.Join(src, "module.json")); err != nil {
		t.Skipf("xray-client example missing: %v", err)
	}

	e, err := NewEngine(t.TempDir())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Главное: InstallFromURL теперь принимает локальный path.
	name, err := e.InstallFromURL(src)
	if err != nil {
		t.Fatalf("InstallFromURL(%s): %v", src, err)
	}
	if name != "xray-client" {
		t.Errorf("installed name = %q want xray-client", name)
	}
	if got := len(e.Registry.List()); got != 1 {
		t.Errorf("after install: registry size = %d want 1", got)
	}

	rep, err := e.Validate(name)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rep.Name != "xray-client" {
		t.Errorf("validate name = %q want xray-client", rep.Name)
	}
	if len(rep.MissingParam) == 0 {
		t.Errorf("xray-client без params: MissingParam expected non-empty, got %+v", rep.MissingParam)
	}
	if !strings.Contains(rep.ConfigSample, "vless") {
		t.Errorf("config sample must contain 'vless' for xray-client, got: %s", rep.ConfigSample)
	}
}
