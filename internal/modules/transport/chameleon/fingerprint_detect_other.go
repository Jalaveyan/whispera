//go:build !windows

package chameleon

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	utls "github.com/refraction-networking/utls"
)

func detectDefaultBrowserID() utls.ClientHelloID {
	if b := os.Getenv("BROWSER"); b != "" {
		return mapBrowserToFingerprint(b)
	}

	switch runtime.GOOS {
	case "linux":
		if out, err := exec.Command("xdg-mime", "query", "default", "x-scheme-handler/https").Output(); err == nil {
			return mapBrowserToFingerprint(strings.TrimSpace(string(out)))
		}
		for _, candidate := range []string{"google-chrome", "chromium", "firefox", "safari"} {
			if _, err := exec.LookPath(candidate); err == nil {
				return mapBrowserToFingerprint(candidate)
			}
		}
	case "darwin":
		out, err := exec.Command("defaults", "read", "com.apple.LaunchServices/com.apple.launchservices.secure", "LSHandlers").Output()
		if err == nil {
			s := string(out)
			if strings.Contains(strings.ToLower(s), "firefox") {
				return utls.HelloFirefox_148
			}
			if strings.Contains(strings.ToLower(s), "safari") {
				return utls.HelloSafari_26_3
			}
		}
	}

	return utls.HelloChrome_133
}
