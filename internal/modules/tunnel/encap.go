package tunnel

import (
	"context"
	"fmt"
	"net"
)

// EncapsulatedConfig возвращает копию innerCfg, у которой CustomDialFn
// направляет соединение через уже поднятый outer Manager (tunnel-in-tunnel).
//
// Схема трафика:
//
//	Client → [innerTunnel: обфускация/крипто] → [outerTunnel: транспорт] → Bridge → Server
//
// Требования: outer должен быть в состоянии Connected до вызова DialStream.
func EncapsulatedConfig(innerCfg *Config, outer *Manager) *Config {
	cfg := *innerCfg // shallow copy полей
	serverAddr := innerCfg.ServerAddr

	cfg.CustomDialFn = func(ctx context.Context) (net.Conn, error) {
		if !outer.IsConnected() {
			return nil, fmt.Errorf("encap: outer tunnel not connected")
		}
		return outer.DialStream(ctx, "tcp", serverAddr)
	}

	return &cfg
}

// EncapChain строит цепочку из N туннелей, где каждый следующий
// использует предыдущий как транспорт.
//
//	chain[0] — самый внешний (подключается напрямую)
//	chain[N-1] — самый внутренний (финальное соединение с сервером)
//
// Возвращает срез Manager-ов в том же порядке.
// Caller должен Connect() их начиная с chain[0].
func EncapChain(configs []*Config) ([]*Manager, error) {
	if len(configs) == 0 {
		return nil, fmt.Errorf("encap chain: no configs provided")
	}

	managers := make([]*Manager, len(configs))

	// Самый внешний создаётся без обёртки.
	m0, err := New(configs[0])
	if err != nil {
		return nil, fmt.Errorf("encap chain[0]: %w", err)
	}
	managers[0] = m0

	// Каждый следующий оборачивается в предыдущий.
	for i := 1; i < len(configs); i++ {
		wrapped := EncapsulatedConfig(configs[i], managers[i-1])
		mi, err := New(wrapped)
		if err != nil {
			return nil, fmt.Errorf("encap chain[%d]: %w", i, err)
		}
		managers[i] = mi
	}

	return managers, nil
}
