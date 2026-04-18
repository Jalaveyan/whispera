package marionette

import (
	"sort"
	"strings"

	"whispera/internal/obfuscation/behavioral"
)

type profileFactory func() *behavioral.MessengerProfile

var namedProfiles = map[string]profileFactory{
	"vk":             behavioral.VKMessengerProfile,
	"vk_ios":         behavioral.VKMessengerIOSProfile,
	"vk_music":       behavioral.VKMusicProfile,
	"vk_video":       behavioral.VKVideoProfile,
	"vk_video_live":  behavioral.VKVideoStreamProfile,
	"telegram":       behavioral.TelegramProfile,
	"telegram_ios":   behavioral.TelegramIOSProfile,
	"max":            behavioral.MaxMessengerProfile,
	"wechat":         behavioral.WeChatProfile,
	"wechat_ios":     behavioral.WeChatIOSProfile,
	"instagram":      behavioral.InstagramProfile,
	"instagram_ios":  behavioral.InstagramIOSProfile,
	"facebook":       behavioral.FacebookMessengerProfile,
	"facebook_ios":   behavioral.FacebookMessengerIOSProfile,
	"youtube":        behavioral.YouTubeProfile,
	"spotify":        behavioral.SpotifyProfile,
	"yandex_music":   behavioral.YandexMusicProfile,
}

func ProfileByName(name string) *behavioral.MessengerProfile {
	key := strings.ToLower(strings.TrimSpace(name))
	f, ok := namedProfiles[key]
	if !ok {
		return nil
	}
	return f()
}

func KnownProfiles() []string {
	names := make([]string, 0, len(namedProfiles))
	for k := range namedProfiles {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
