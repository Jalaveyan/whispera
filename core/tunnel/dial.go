package tunnel

import (
	"context"
	"fmt"
	"time"
	"whispera/common/mux"
)

func (m *Manager) dialManagedConn(ctx context.Context, id string) (*managedConn, error) {
	dial := m.gameDial()
	if dial == nil {
		return nil, fmt.Errorf("dial: no whispera dialer available")
	}

	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}

	sess, err := mux.Client(conn, m.getMuxConfig())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mux: %w", err)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("open stream: %w", err)
	}

	return &managedConn{
		Conn:      stream,
		session:   sess,
		id:        id,
		createdAt: time.Now(),
		closing:   make(chan struct{}),
	}, nil
}
