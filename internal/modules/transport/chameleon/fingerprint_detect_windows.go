//go:build windows

package chameleon

import (
	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/windows/registry"
)

func detectDefaultBrowserID() utls.ClientHelloID {
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return utls.HelloChrome_133
	}
	defer k.Close()
	progID, _, err := k.GetStringValue("ProgId")
	if err != nil {
		return utls.HelloChrome_133
	}
	return mapBrowserToFingerprint(progID)
}
