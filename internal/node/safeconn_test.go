package node

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestSafeConnRejectsOversizedFrame(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	serverConnCh := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConnCh <- conn
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn := <-serverConnCh
	defer serverConn.Close()

	safe := NewSafeConn(clientConn)
	if old := safe.Swap(clientConn); old != clientConn {
		t.Fatalf("Swap returned %v, want the previous connection", old)
	}
	readErr := make(chan error, 1)
	go func() {
		_, _, err := safe.ReadMessage()
		readErr <- err
	}()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- serverConn.WriteMessage(websocket.BinaryMessage, bytes.Repeat([]byte{'x'}, int(maxWebSocketMessageSize+1)))
	}()
	if err := <-readErr; err == nil || !strings.Contains(err.Error(), "read limit exceeded") {
		t.Fatalf("ReadMessage error = %v, want read limit exceeded", err)
	}
	_ = clientConn.Close()
	<-writeDone // The peer may report the close while flushing the oversized frame.
}
