package vkwebrtc


import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	vkAnonClientID     = "6287487"
	vkAnonClientSecret = "QbYic1K3lEV5kTGiqlq2"

	okCDNAppKey   = "CGMMEJLGDIHBABABA"
	okCDNEndpoint = "https://calls.okcdn.ru/fb.do"

	vkLoginEndpoint = "https://login.vk.ru/?act=get_anonym_token"
	vkAPIBase       = "https://api.vk.ru/method"
)

type VKCallSession struct {
	CallID     string
	JoinLink   string
	OkJoinLink string
}

type callsStartResp struct {
	Response struct {
		CallID     string `json:"call_id"`
		JoinLink   string `json:"join_link"`
		OkJoinLink string `json:"ok_join_link"`
	} `json:"response"`
	Error struct {
		Code    int    `json:"error_code"`
		Message string `json:"error_msg"`
	} `json:"error"`
}

type okcdnTurnServer struct {
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	URLs       []string `json:"urls"`
}

func StartVKCall(client *http.Client, token string, groupID int64) (*VKCallSession, error) {
	params := url.Values{
		"access_token": {token},
		"v":            {"5.199"},
	}
	if groupID > 0 {
		params.Set("group_id", fmt.Sprintf("%d", groupID))
	}

	resp, err := client.Get("https://api.vk.com/method/calls.start?" + params.Encode())
	if err != nil {
		return nil, fmt.Errorf("calls.start: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result callsStartResp
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("calls.start decode: %w", err)
	}
	if result.Error.Code != 0 {
		return nil, fmt.Errorf("VK API error %d: %s", result.Error.Code, result.Error.Message)
	}

	return &VKCallSession{
		CallID:     result.Response.CallID,
		JoinLink:   result.Response.JoinLink,
		OkJoinLink: result.Response.OkJoinLink,
	}, nil
}

func FetchICEServersFromVK(ctx context.Context, _, joinLink string) ([]ICEServerConfig, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	log.Printf("FetchICEServersFromVK: starting 6-step credential flow")

	tok1, err := vkGetAnonToken(ctx, client, "", "")
	if err != nil {
		return nil, fmt.Errorf("step1 (anon token): %w", err)
	}
	log.Printf("FetchICEServersFromVK: step1 OK")

	payload, err := vkGetCallsPayload(ctx, client, tok1)
	if err != nil {
		return nil, fmt.Errorf("step2 (calls payload): %w", err)
	}
	log.Printf("FetchICEServersFromVK: step2 OK")

	tok3, err := vkGetAnonToken(ctx, client, payload, "messages")
	if err != nil {
		return nil, fmt.Errorf("step3 (upgraded token): %w", err)
	}
	log.Printf("FetchICEServersFromVK: step3 OK")

	callTok, err := vkGetAnonymousCallToken(ctx, client, tok3, joinLink)
	if err != nil {
		return nil, fmt.Errorf("step4 (call token): %w", err)
	}
	log.Printf("FetchICEServersFromVK: step4 OK")

	sessionKey, err := okcdnAnonLogin(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("step5 (okcdn login): %w", err)
	}
	log.Printf("FetchICEServersFromVK: step5 OK")

	hash := extractJoinHash(joinLink)
	if hash == "" {
		return nil, fmt.Errorf("cannot extract hash from join_link %q", joinLink)
	}

	servers, err := okcdnJoinConversation(ctx, client, sessionKey, callTok, hash)
	if err != nil {
		return nil, fmt.Errorf("step6 (join conversation): %w", err)
	}

	log.Printf("FetchICEServersFromVK: got %d ICE servers", len(servers))
	return servers, nil
}

func vkGetAnonToken(ctx context.Context, client *http.Client, payload, tokenType string) (string, error) {
	form := url.Values{
		"client_id":     {vkAnonClientID},
		"client_secret": {vkAnonClientSecret},
		"version":       {"1"},
		"app_id":        {vkAnonClientID},
	}
	if payload != "" {
		form.Set("payload", payload)
		form.Set("token_type", tokenType)
	} else {
		form.Set("scopes", "audio_anonymous,video_anonymous,photos_anonymous,profile_anonymous")
		form.Set("isApiOauthAnonymEnabled", "false")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", vkLoginEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w (body: %s)", err, body)
	}
	if result.Data.AccessToken == "" {
		return "", fmt.Errorf("empty token (body: %s)", body)
	}
	return result.Data.AccessToken, nil
}

func vkGetCallsPayload(ctx context.Context, client *http.Client, anonToken string) (string, error) {
	endpoint := vkAPIBase + "/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=" + vkAnonClientID

	form := url.Values{"access_token": {anonToken}}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Response struct {
			Payload string `json:"payload"`
		} `json:"response"`
		Error struct {
			Code int    `json:"error_code"`
			Msg  string `json:"error_msg"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if result.Error.Code != 0 {
		return "", fmt.Errorf("VK error %d: %s", result.Error.Code, result.Error.Msg)
	}
	return result.Response.Payload, nil
}

func vkGetAnonymousCallToken(ctx context.Context, client *http.Client, anonToken, joinLink string) (string, error) {
	endpoint := vkAPIBase + "/calls.getAnonymousToken?v=5.264"

	form := url.Values{
		"vk_join_link": {joinLink},
		"name":         {"Anonymous"},
		"access_token": {anonToken},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Response struct {
			Token string `json:"token"`
		} `json:"response"`
		Error struct {
			Code int    `json:"error_code"`
			Msg  string `json:"error_msg"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if result.Error.Code != 0 {
		return "", fmt.Errorf("VK error %d: %s", result.Error.Code, result.Error.Msg)
	}
	return result.Response.Token, nil
}

func okcdnAnonLogin(ctx context.Context, client *http.Client) (string, error) {
	deviceID := generateDeviceID()

	sessionData, _ := json.Marshal(map[string]interface{}{
		"version":        2,
		"device_id":      deviceID,
		"client_version": 1.1,
		"client_type":    "SDK_JS",
	})

	form := url.Values{
		"session_data":    {string(sessionData)},
		"method":          {"auth.anonymLogin"},
		"format":          {"JSON"},
		"application_key": {okCDNAppKey},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", okCDNEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		SessionKey string `json:"session_key"`
		ErrorCode  int    `json:"error_code"`
		ErrorMsg   string `json:"error_message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w (body: %s)", err, body)
	}
	if result.ErrorCode != 0 {
		return "", fmt.Errorf("okcdn error %d: %s", result.ErrorCode, result.ErrorMsg)
	}
	return result.SessionKey, nil
}

func okcdnJoinConversation(ctx context.Context, client *http.Client, sessionKey, callToken, hash string) ([]ICEServerConfig, error) {
	form := url.Values{
		"joinLink":        {hash},
		"isVideo":         {"false"},
		"protocolVersion": {"5"},
		"anonymToken":     {callToken},
		"method":          {"vchat.joinConversationByLink"},
		"format":          {"JSON"},
		"application_key": {okCDNAppKey},
		"session_key":     {sessionKey},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", okCDNEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		TurnServer *okcdnTurnServer `json:"turn_server"`
		ErrorCode  int              `json:"error_code"`
		ErrorMsg   string           `json:"error_message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse: %w (body: %s)", err, body)
	}
	if result.ErrorCode != 0 {
		return nil, fmt.Errorf("okcdn error %d: %s (body: %s)", result.ErrorCode, result.ErrorMsg, body)
	}
	if result.TurnServer == nil {
		return nil, fmt.Errorf("no turn_server in response (body: %s)", body)
	}

	return []ICEServerConfig{{
		URLs:       result.TurnServer.URLs,
		Username:   result.TurnServer.Username,
		Credential: result.TurnServer.Credential,
	}}, nil
}

func extractJoinHash(joinLink string) string {
	u, err := url.Parse(joinLink)
	if err != nil {
		return ""
	}
	if idx := strings.Index(u.Path, "/call/join/"); idx >= 0 {
		return u.Path[idx+len("/call/join/"):]
	}
	if idx := strings.Index(u.Path, "/calls/join/"); idx >= 0 {
		return u.Path[idx+len("/calls/join/"):]
	}
	return u.Query().Get("join")
}

func generateDeviceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

func GenerateHMACTURNCredentials(sharedSecret, userID string, ttl time.Duration) (username, password string) {
	expires := time.Now().Add(ttl).Unix()
	username = fmt.Sprintf("%d:%s", expires, userID)
	mac := hmac.New(sha1.New, []byte(sharedSecret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

func ForceFinishCall(client *http.Client, token, callID string) error {
	params := url.Values{
		"access_token": {token},
		"call_id":      {callID},
		"v":            {"5.199"},
	}
	resp, err := client.Get("https://api.vk.com/method/calls.forceFinish?" + params.Encode())
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
