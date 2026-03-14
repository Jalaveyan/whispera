package yatelemost


import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

const (
	teleMostConferenceURL = "https://cloud-api.yandex.ru/telemost_front/v2/telemost/conferences"
	teleMostOrigin        = "https://telemost.yandex.ru"
)

type TeleMostConference struct {
	WssURL        string `json:"wss"`
	RoomID        string `json:"roomId"`
	ParticipantID string `json:"participantId"`
	Credentials   struct {
		Token string `json:"token"`
	} `json:"credentials"`
}

type helloRequest struct {
	ID          string          `json:"id"`
	Participant participantInfo `json:"participantInfo"`
	SDK         sdkInfo         `json:"sdk"`
}

type participantInfo struct {
	Name          string `json:"name"`
	Role          string `json:"role"`
	Audio         bool   `json:"audio"`
	Video         bool   `json:"video"`
	RoomID        string `json:"roomId"`
	ParticipantID string `json:"participantId"`
	Token         string `json:"token,omitempty"`
}

type sdkInfo struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type wssResponse struct {
	Type            string          `json:"type"`
	RtcConfiguration *rtcConfig     `json:"rtcConfiguration"`
}

type rtcConfig struct {
	ICEServers []iceServerEntry `json:"iceServers"`
}

type iceServerEntry struct {
	URLs       interface{} `json:"urls"`
	Username   string      `json:"username"`
	Credential string      `json:"credential"`
}

type ICEServerConfig struct {
	URLs       []string
	Username   string
	Credential string
}

func CreateConference(ctx context.Context, sessionID string) (*TeleMostConference, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "POST",
		teleMostConferenceURL+"?next_gen_media_platform_allowed=false",
		strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", teleMostOrigin)
	req.Header.Set("Referer", teleMostOrigin+"/")
	req.AddCookie(&http.Cookie{Name: "Session_id", Value: sessionID})

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create conference: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create conference: HTTP %d (body: %s)", resp.StatusCode, body)
	}

	var conf TeleMostConference
	if err := json.Unmarshal(body, &conf); err != nil {
		return nil, fmt.Errorf("decode conference: %w (body: %s)", err, body)
	}
	if conf.WssURL == "" {
		return nil, fmt.Errorf("no wss URL in conference response (body: %s)", body)
	}
	return &conf, nil
}

func FetchICEServers(ctx context.Context, sessionID string, conf *TeleMostConference) ([]ICEServerConfig, error) {
	headers := http.Header{
		"Origin":     []string{teleMostOrigin},
		"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		"Cookie":     []string{"Session_id=" + sessionID},
	}

	ws, _, err := websocket.Dial(ctx, conf.WssURL, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		return nil, fmt.Errorf("dial telemost wss: %w", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	ws.SetReadLimit(512 * 1024)

	hello := helloRequest{
		ID: generateID(),
		Participant: participantInfo{
			Name:          "user",
			Role:          "participant",
			Audio:         false,
			Video:         false,
			RoomID:        conf.RoomID,
			ParticipantID: conf.ParticipantID,
			Token:         conf.Credentials.Token,
		},
		SDK: sdkInfo{Type: "browser", Version: "5.15.0"},
	}
	helloBytes, _ := json.Marshal(hello)
	if err := ws.Write(ctx, websocket.MessageText, helloBytes); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		msgCtx, cancel := context.WithDeadline(ctx, deadline)
		_, data, err := ws.Read(msgCtx)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("read wss: %w", err)
		}

		var msg wssResponse
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.RtcConfiguration == nil || len(msg.RtcConfiguration.ICEServers) == 0 {
			continue
		}

		return extractTURN(msg.RtcConfiguration.ICEServers), nil
	}

	return nil, fmt.Errorf("timeout waiting for rtcConfiguration from Telemost")
}

func extractTURN(entries []iceServerEntry) []ICEServerConfig {
	var out []ICEServerConfig
	for _, e := range entries {
		var urls []string
		switch v := e.URLs.(type) {
		case string:
			urls = []string{v}
		case []interface{}:
			for _, u := range v {
				if s, ok := u.(string); ok {
					urls = append(urls, s)
				}
			}
		}

		var filtered []string
		for _, u := range urls {
			lower := strings.ToLower(u)
			if !strings.HasPrefix(lower, "turn:") && !strings.HasPrefix(lower, "turns:") {
				continue
			}
			if strings.Contains(lower, "transport=tcp") {
				continue
			}
			filtered = append(filtered, u)
		}
		if len(filtered) == 0 {
			continue
		}

		out = append(out, ICEServerConfig{
			URLs:       filtered,
			Username:   e.Username,
			Credential: e.Credential,
		})
	}
	return out
}

func generateID() string {
	return fmt.Sprintf("whispera-%d", time.Now().UnixNano())
}

func SendSignal(ctx context.Context, ws *websocket.Conn, msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return ws.Write(ctx, websocket.MessageText, data)
}

func ReadSignal(ctx context.Context, ws *websocket.Conn) ([]byte, error) {
	_, data, err := ws.Read(ctx)
	return data, err
}
