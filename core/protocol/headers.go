package protocol

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var chromeDesktopUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.205 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
}

var chromeMobileUAs = []string{
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.53 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.260 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; M2101K6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.53 Mobile Safari/537.36",
}

var edgeDesktopUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
}

var firefoxDesktopUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:148.0) Gecko/20100101 Firefox/148.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
}

var safariDesktopUAs = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
}

var iosSafariUAs = []string{
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
}

var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
	"de-DE,de;q=0.9,en;q=0.8",
	"fr-FR,fr;q=0.9,en;q=0.8",
	"tr-TR,tr;q=0.9,en;q=0.8",
	"uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7",
	"zh-CN,zh;q=0.9,en;q=0.8",
	"es-ES,es;q=0.9,en;q=0.8",
	"ar-SA,ar;q=0.9,en;q=0.8",
}

// browserKind is the HTTP header dialect a fingerprint must speak so the
// HTTP layer never contradicts the TLS ClientHello (e.g. Firefox JA3 +
// Chrome User-Agent + Chromium client hints is a dead giveaway).
type browserKind int

const (
	kindChromium browserKind = iota // Chrome, Edge, Android Chrome
	kindFirefox
	kindSafari // desktop Safari + iOS
)

func uaForFingerprint(id utls.ClientHelloID) string {
	client := strings.ToLower(id.Client)
	switch {
	case strings.Contains(client, "firefox"):
		return firefoxDesktopUAs[rand.Intn(len(firefoxDesktopUAs))]
	case strings.Contains(client, "edge"):
		return edgeDesktopUAs[rand.Intn(len(edgeDesktopUAs))]
	case strings.Contains(client, "ios"):
		return iosSafariUAs[rand.Intn(len(iosSafariUAs))]
	case strings.Contains(client, "safari"):
		return safariDesktopUAs[rand.Intn(len(safariDesktopUAs))]
	case strings.Contains(client, "android"):
		return chromeMobileUAs[rand.Intn(len(chromeMobileUAs))]
	default:
		return chromeDesktopUAs[rand.Intn(len(chromeDesktopUAs))]
	}
}

func kindForFingerprint(id utls.ClientHelloID) browserKind {
	client := strings.ToLower(id.Client)
	switch {
	case strings.Contains(client, "firefox"):
		return kindFirefox
	case strings.Contains(client, "ios"), strings.Contains(client, "safari"):
		return kindSafari
	default:
		return kindChromium // Chrome/Edge/Android + harvested HelloCustom
	}
}

// browserProfile is a coherent UA + header set chosen ONCE per session and
// reused for every request, the way a real browser keeps one identity for the
// life of a connection (picking a fresh UA per request is itself a signature).
type browserProfile struct {
	ua         string
	lang       string
	kind       browserKind
	chBrands   string
	chMobile   string
	chPlatform string
}

func newBrowserProfile(id utls.ClientHelloID) browserProfile {
	p := browserProfile{
		ua:   uaForFingerprint(id),
		lang: acceptLanguages[rand.Intn(len(acceptLanguages))],
		kind: kindForFingerprint(id),
	}
	if p.kind == kindChromium {
		p.chBrands, p.chMobile, p.chPlatform = chromiumClientHints(p.ua)
	}
	return p
}

func (p browserProfile) apply(req *http.Request, origin string) {
	req.Header.Set("User-Agent", p.ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", p.lang)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	// Client hints are a Chromium-only signal; emit them only for Chromium UAs.
	if p.kind == kindChromium {
		req.Header.Set("sec-ch-ua", p.chBrands)
		req.Header.Set("sec-ch-ua-mobile", p.chMobile)
		req.Header.Set("sec-ch-ua-platform", p.chPlatform)
	}

	// Sec-Fetch metadata is sent by Chromium and Firefox, not by Safari.
	if p.kind != kindSafari {
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}

	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
}

// chromiumClientHints builds sec-ch-ua headers whose version and platform match
// the chosen UA, so the low-entropy hints don't contradict the UA string.
func chromiumClientHints(ua string) (brands, mobile, platform string) {
	major := chromeMajor(ua)
	if strings.Contains(ua, "Edg/") {
		brands = fmt.Sprintf(`"Microsoft Edge";v="%s", "Chromium";v="%s", "Not(A:Brand";v="24"`, major, major)
	} else {
		brands = fmt.Sprintf(`"Chromium";v="%s", "Not(A:Brand";v="99", "Google Chrome";v="%s"`, major, major)
	}

	mobile, platform = "?0", `"Windows"`
	switch {
	case strings.Contains(ua, "Android"):
		mobile, platform = "?1", `"Android"`
	case strings.Contains(ua, "Mac OS X"):
		platform = `"macOS"`
	case strings.Contains(ua, "Linux"):
		platform = `"Linux"`
	}
	return
}

func chromeMajor(ua string) string {
	i := strings.Index(ua, "Chrome/")
	if i < 0 {
		return "133"
	}
	v := ua[i+len("Chrome/"):]
	if j := strings.IndexByte(v, '.'); j >= 0 {
		return v[:j]
	}
	return "133"
}
