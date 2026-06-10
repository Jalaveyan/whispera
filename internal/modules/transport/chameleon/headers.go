package chameleon

import (
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

var firefoxDesktopUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:148.0) Gecko/20100101 Firefox/148.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
}

var safariDesktopUAs = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
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

func uaForFingerprint(id utls.ClientHelloID) string {
	client := strings.ToLower(id.Client)
	if strings.Contains(client, "firefox") {
		return firefoxDesktopUAs[rand.Intn(len(firefoxDesktopUAs))]
	}
	if strings.Contains(client, "safari") {
		return safariDesktopUAs[rand.Intn(len(safariDesktopUAs))]
	}
	if strings.Contains(client, "android") || strings.Contains(client, "ios") || strings.Contains(client, "mobile") {
		return chromeMobileUAs[rand.Intn(len(chromeMobileUAs))]
	}
	return chromeDesktopUAs[rand.Intn(len(chromeDesktopUAs))]
}

func applyBrowserHeaders(req *http.Request, origin string) {
	detectOnce.Do(func() {
		detectedBrowserID = detectDefaultBrowserID()
	})

	ua := uaForFingerprint(detectedBrowserID)
	lang := acceptLanguages[rand.Intn(len(acceptLanguages))]

	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", lang)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
}
