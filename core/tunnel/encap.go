package tunnel

import (
	"context"
	"fmt"
	"net"
)

func EncapsulatedConfig(innerCfg *Config, outer *Manager) *Config {
	cfg := *innerCfg
	serverAddr := innerCfg.ServerAddr

	cfg.CustomDialFn = func(ctx context.Context) (net.Conn, error) {
		if !outer.IsConnected() {
			return nil, fmt.Errorf("encap: outer tunnel not connected")
		}
		return outer.DialStream(ctx, "tcp", serverAddr)
	}

	return &cfg
}
