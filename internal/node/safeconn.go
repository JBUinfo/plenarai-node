package node

import (
	"sync"

	"github.com/gorilla/websocket"
)

// SafeConn wraps a websocket.Conn so concurrent writes from multiple
// goroutines don't trigger gorilla's "concurrent write" panic.
type SafeConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// maxWebSocketMessageSize bounds relay frames while leaving room for the
// encrypted score batches used by the node protocol.
const maxWebSocketMessageSize int64 = 8 << 20

func NewSafeConn(c *websocket.Conn) *SafeConn {
	setReadLimit(c)
	return &SafeConn{conn: c}
}

// Swap replaces the underlying connection (used on reconnect) and returns
// the previous one so the caller can close it.
func (s *SafeConn) Swap(c *websocket.Conn) *websocket.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	setReadLimit(c)
	old := s.conn
	s.conn = c
	return old
}

func (s *SafeConn) WriteMessage(messageType int, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return websocket.ErrCloseSent
	}
	return s.conn.WriteMessage(messageType, data)
}

func (s *SafeConn) ReadMessage() (int, []byte, error) {
	// Reads come from a single goroutine (Run loop), no lock needed.
	return s.conn.ReadMessage()
}

func (s *SafeConn) Close() error {
	return s.conn.Close()
}

func setReadLimit(c *websocket.Conn) {
	if c != nil {
		c.SetReadLimit(maxWebSocketMessageSize)
	}
}
