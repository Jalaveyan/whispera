// Package chain реализует стекирование транспортов:
// один транспорт (outer) работает поверх соединения, открытого другим (inner).
//
// Пример: Shadowsocks поверх Meek —
//   meek.Dial() → meekConn (HTTP-туннель к fronted-серверу)
//   ss.DialConn(meekConn, target) → ssConn (зашифрованный поверх meekConn)
//
// Использование:
//   combo, _ := chain.New(ss, meek, meekFrontAddr, interfaces.TransportSSMeek)
//   selector.RegisterTransport(combo)
package chain

import (
	"context"
	"fmt"
	"net"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "transport.chain"
	ModuleVersion = "1.0.0"
)

// ChainedTransport соединяет два транспорта в стек.
// inner открывает TCP/HTTP/WebRTC соединение до промежуточной точки.
// outer выполняет свой handshake поверх этого соединения.
type ChainedTransport struct {
	*base.Module
	outer     interfaces.DialableTransport
	inner     interfaces.Transport
	outerAddr string // адрес к которому коннектится inner (адрес outer-сервера)
	chainType interfaces.TransportType
}

// New создаёт ChainedTransport.
//
//   outer      — транспорт, реализующий DialableTransport (SS, Obfs4, …)
//   inner      — транспорт, открывающий соединение (Meek, TCP, WebSocket, …)
//   outerAddr  — адрес outer-сервера, до которого inner открывает соединение
//   chainType  — логическое имя комбинации (interfaces.TransportSSMeek и т.д.)
func New(
	outer interfaces.DialableTransport,
	inner interfaces.Transport,
	outerAddr string,
	chainType interfaces.TransportType,
) (*ChainedTransport, error) {
	if outer == nil || inner == nil {
		return nil, fmt.Errorf("chain: outer and inner transports must not be nil")
	}
	if outerAddr == "" {
		return nil, fmt.Errorf("chain: outerAddr must not be empty")
	}
	return &ChainedTransport{
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		outer:     outer,
		inner:     inner,
		outerAddr: outerAddr,
		chainType: chainType,
	}, nil
}

// Type возвращает тип комбо-транспорта (например "shadowsocks+meek").
func (c *ChainedTransport) Type() interfaces.TransportType {
	return c.chainType
}

// Dial открывает соединение через цепочку:
//  1. inner.Dial(ctx, outerAddr) — соединение до outer-сервера
//  2. outer.DialConn(ctx, innerConn, addr) — handshake outer-протокола поверх него
func (c *ChainedTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	innerConn, err := c.inner.Dial(ctx, c.outerAddr)
	if err != nil {
		return nil, fmt.Errorf("chain(%s): inner dial to %s: %w",
			c.chainType, c.outerAddr, err)
	}

	outerConn, err := c.outer.DialConn(ctx, innerConn, addr)
	if err != nil {
		innerConn.Close()
		return nil, fmt.Errorf("chain(%s): outer handshake to %s: %w",
			c.chainType, addr, err)
	}

	return outerConn, nil
}

// Listen не поддерживается — ChainedTransport только для клиентской стороны.
func (c *ChainedTransport) Listen(_ string) error {
	return fmt.Errorf("chain: server mode not supported")
}

func (c *ChainedTransport) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("chain: server mode not supported")
}

func (c *ChainedTransport) Close() error {
	var errs []error
	if err := c.outer.Close(); err != nil {
		errs = append(errs, fmt.Errorf("outer: %w", err))
	}
	if err := c.inner.Close(); err != nil {
		errs = append(errs, fmt.Errorf("inner: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("chain close: %v", errs)
	}
	return nil
}

func (c *ChainedTransport) HealthCheck() interfaces.HealthStatus {
	s := c.Module.HealthCheck()
	s.Details["outer"] = string(c.outer.Type())
	s.Details["inner"] = string(c.inner.Type())
	s.Details["outer_addr"] = c.outerAddr
	outerH := c.outer.HealthCheck()
	innerH := c.inner.HealthCheck()
	s.Healthy = outerH.Healthy && innerH.Healthy
	if !s.Healthy {
		s.Message = fmt.Sprintf("outer=%v inner=%v", outerH.Healthy, innerH.Healthy)
	}
	return s
}
