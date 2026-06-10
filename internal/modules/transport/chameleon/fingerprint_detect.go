package chameleon

import (
	"strings"

	utls "github.com/refraction-networking/utls"
)

func mapBrowserToFingerprint(s string) utls.ClientHelloID {
	s = strings.ToLower(s)
	if strings.Contains(s, "firefox") {
		return utls.HelloFirefox_148
	}
	if (strings.Contains(s, "safari") || strings.Contains(s, "webkit")) &&
		!strings.Contains(s, "chrome") && !strings.Contains(s, "chromium") {
		return utls.HelloSafari_26_3
	}
	return utls.HelloChrome_133
}
