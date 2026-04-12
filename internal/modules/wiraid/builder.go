package wiraid

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func GitClone(url, dest string) error {
	if err := checkTool("git"); err != nil {
		return err
	}
	if _, err := os.Stat(dest); err == nil {
		if err := os.RemoveAll(dest); err != nil {
			return fmt.Errorf("cleanup: %w", err)
		}
	}
	cmd := exec.Command("git", "clone", "--depth=1", url, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %s", string(out))
	}
	return nil
}

func BuildModule(dir string, lang ModuleLang, entry, name string) (string, error) {
	switch lang {
	case LangGo:
		return buildGo(dir, entry, name)
	case LangBinary:
		return findBinary(dir, name)
	case LangRust:
		return buildRust(dir, name)
	case LangPython:
		return findPythonEntry(dir, entry, name)
	case LangC:
		return buildC(dir, entry, name)
	default:
		return "", fmt.Errorf("unsupported lang: %s", lang)
	}
}

// buildC compiles a C project. Tries cmake → make in that order, then plain gcc/clang.
func buildC(dir, entry, name string) (string, error) {
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	out := filepath.Join(binDir, name)

	// CMake build
	cmakeLists := filepath.Join(dir, "CMakeLists.txt")
	if _, err := os.Stat(cmakeLists); err == nil {
		if err2 := checkTool("cmake"); err2 == nil {
			buildDir := filepath.Join(dir, "_cmake_build")
			_ = os.MkdirAll(buildDir, 0o755)
			cfg := exec.Command("cmake", "..", "-DCMAKE_BUILD_TYPE=Release")
			cfg.Dir = buildDir
			if combined, err3 := cfg.CombinedOutput(); err3 != nil {
				return "", fmt.Errorf("cmake config failed: %s", string(combined))
			}
			bld := exec.Command("cmake", "--build", ".", "--config", "Release")
			bld.Dir = buildDir
			if combined, err3 := bld.CombinedOutput(); err3 != nil {
				return "", fmt.Errorf("cmake build failed: %s", string(combined))
			}
			// find the produced binary
			found := findExecutableRecursive(buildDir)
			if found == "" {
				found = findExecutableRecursive(dir)
			}
			if found == "" {
				return "", fmt.Errorf("cmake build succeeded but no executable found")
			}
			if err3 := copyFile(found, out); err3 != nil {
				return "", err3
			}
			_ = os.Chmod(out, 0o755)
			return out, nil
		}
	}

	// Makefile build
	makefile := filepath.Join(dir, "Makefile")
	if _, err := os.Stat(makefile); err == nil {
		if err2 := checkTool("make"); err2 == nil {
			cmd := exec.Command("make")
			cmd.Dir = dir
			if combined, err3 := cmd.CombinedOutput(); err3 != nil {
				return "", fmt.Errorf("make failed: %s", string(combined))
			}
			if found := findExecutableRecursive(dir); found != "" {
				if err3 := copyFile(found, out); err3 != nil {
					return "", err3
				}
				_ = os.Chmod(out, 0o755)
				return out, nil
			}
		}
	}

	// Direct gcc/clang compilation
	compiler := "gcc"
	if err2 := checkTool("gcc"); err2 != nil {
		if err3 := checkTool("clang"); err3 != nil {
			return "", fmt.Errorf("no C compiler (gcc/clang) found in PATH")
		}
		compiler = "clang"
	}
	src := entry
	if src == "" {
		// look for main.c or the entry file
		for _, candidate := range []string{"main.c", name + ".c", "src/main.c"} {
			if _, err := os.Stat(filepath.Join(dir, candidate)); err == nil {
				src = candidate
				break
			}
		}
	}
	if src == "" {
		return "", fmt.Errorf("no entry .c file specified and main.c not found")
	}
	cmd := exec.Command(compiler, src, "-O2", "-o", out)
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s compile failed: %s", compiler, string(combined))
	}
	_ = os.Chmod(out, 0o755)
	return out, nil
}

func findPythonEntry(dir, entry, name string) (string, error) {
	if err := checkTool("python3"); err != nil {
		return "", err
	}
	candidates := []string{}
	if entry != "" {
		candidates = append(candidates, filepath.Join(dir, entry))
	}
	candidates = append(candidates,
		filepath.Join(dir, "main.py"),
		filepath.Join(dir, name+".py"),
		filepath.Join(dir, "src", "main.py"),
	)
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("no python entry found in %s", dir)
}

func buildGo(dir, entry, name string) (string, error) {
	if err := checkTool("go"); err != nil {
		return "", err
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	out := filepath.Join(binDir, name)
	target := "."
	if entry != "" {
		if strings.HasSuffix(entry, ".go") {
			target = entry
		} else {
			target = "./" + entry
		}
	}
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, target)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %s", string(combined))
	}
	return out, nil
}

func buildRust(dir, name string) (string, error) {
	if err := checkTool("cargo"); err != nil {
		return "", err
	}
	cmd := exec.Command("cargo", "build", "--release")
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("cargo build failed: %s", string(combined))
	}
	src := filepath.Join(dir, "target", "release", name)
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("binary not found at %s", src)
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(binDir, name)
	if err := copyFile(src, dest); err != nil {
		return "", err
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		return "", err
	}
	return dest, nil
}

func findBinary(dir, name string) (string, error) {
	binDir := filepath.Join(dir, "bin")
	candidates := []string{
		filepath.Join(binDir, name),
		filepath.Join(dir, name),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if found := findExecutableRecursive(binDir); found != "" {
		return found, nil
	}
	if found := findExecutableRecursive(dir); found != "" {
		return found, nil
	}
	return "", fmt.Errorf("no binary found for %q in %s", name, binDir)
}

func DownloadBinary(url, destDir string) (string, error) {
	binDir := filepath.Join(destDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	fileName := url
	if i := strings.LastIndex(url, "/"); i >= 0 {
		fileName = url[i+1:]
	}
	if fileName == "" {
		fileName = "module.bin"
	}
	tmpPath := filepath.Join(binDir, fileName)

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return "", err
	}
	f.Close()

	lower := strings.ToLower(fileName)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return extractAndFind(tmpPath, binDir, "tar", "-xzf")
	case strings.HasSuffix(lower, ".zip"):
		return extractAndFind(tmpPath, binDir, "unzip", "-o")
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return "", err
	}
	return tmpPath, nil
}

func extractAndFind(archive, binDir, tool string, flags ...string) (string, error) {
	extractDir := filepath.Join(binDir, "_extract")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return "", err
	}
	args := append([]string{}, flags...)
	if tool == "tar" {
		args = append(args, archive, "-C", extractDir)
	} else {
		args = append(args, archive, "-d", extractDir)
	}
	cmd := exec.Command(tool, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s extract failed: %s", tool, string(out))
	}
	os.Remove(archive)
	found := findExecutableRecursive(extractDir)
	if found == "" {
		return "", fmt.Errorf("no executable found in archive")
	}
	dest := filepath.Join(binDir, filepath.Base(found))
	if err := copyFile(found, dest); err != nil {
		return "", err
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		return "", err
	}
	os.RemoveAll(extractDir)
	return dest, nil
}

func findExecutableRecursive(dir string) string {
	var best string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.Mode()&0o111 == 0 {
			return nil
		}
		name := strings.ToLower(info.Name())
		if best == "" {
			best = path
			return nil
		}
		if strings.Contains(name, "client") || strings.Contains(name, "proxy") {
			best = path
		}
		return nil
	})
	return best
}

func checkTool(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%q not found in PATH", name)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func RepoNameFromURL(url string) string {
	u := strings.TrimSuffix(strings.TrimRight(url, "/"), ".git")
	parts := strings.Split(u, "/")
	name := parts[len(parts)-1]
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".zip")
	name = strings.TrimSuffix(name, ".tar.gz")
	name = strings.TrimSuffix(name, ".tgz")
	name = strings.ReplaceAll(name, " ", "-")
	if i := strings.Index(name, "-v"); i > 0 && i+2 < len(name) {
		c := name[i+2]
		if c >= '0' && c <= '9' {
			name = name[:i]
		}
	}
	if name == "" {
		return "module"
	}
	return name
}
