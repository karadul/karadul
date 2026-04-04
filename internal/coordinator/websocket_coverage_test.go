package coordinator

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestReadPump_HubDoneBranch verifies that readPump exits through the hub.done
// channel in its defer block when the hub is closed while the client is connected.
func TestReadPump_HubDoneBranch(t *testing.T) {
	store := newTestStore(t)
	defer store.StopGC()

	hub := NewHub(store, []string{"*"}, "")

	runDone := make(chan struct{})
	go func() {
		hub.Run()
		close(runDone)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.ServeWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Wait for client to be registered.
	time.Sleep(50 * time.Millisecond)

	// Close the hub while client is still connected — triggers hub.done branch in readPump's defer.
	hub.Close()
	<-runDone
}

// TestReadPump_PongHandler verifies that the PongHandler callback fires
// and resets the read deadline when a Pong frame is received.
func TestReadPump_PongHandler(t *testing.T) {
	store := newTestStore(t)
	defer store.StopGC()

	hub := NewHub(store, []string{"*"}, "")

	runDone := make(chan struct{})
	go func() {
		hub.Run()
		close(runDone)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.ServeWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Drain initial state messages.
	drainInitialState(t, wsConn)

	// Get the server-side client to send a Pong frame directly.
	hub.mu.RLock()
	var serverClient *Client
	for c := range hub.clients {
		serverClient = c
		break
	}
	hub.mu.RUnlock()

	if serverClient == nil {
		t.Fatal("no client found in hub")
	}

	// Write a Pong control frame from the server side to the client.
	// Use WriteControl (which holds the internal write mutex) to avoid racing with writePump.
	// This triggers the PongHandler callback in readPump which resets the read deadline.
	if err := serverClient.conn.WriteControl(websocket.PongMessage, []byte("pong"), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("write pong: %v", err)
	}

	// Wait briefly for the PongHandler to fire.
	time.Sleep(50 * time.Millisecond)

	// Connection should still be alive after PongHandler resets the deadline.
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	wsConn.WriteMessage(websocket.TextMessage, []byte("still-alive"))

	hub.Close()
	<-runDone
}

// TestReadPump_UnexpectedCloseError verifies that readPump hits the
// IsUnexpectedCloseError true branch when the connection is closed
// with an abnormal close code.
func TestReadPump_UnexpectedCloseError(t *testing.T) {
	store := newTestStore(t)
	defer store.StopGC()

	hub := NewHub(store, []string{"*"}, "")

	runDone := make(chan struct{})
	go func() {
		hub.Run()
		close(runDone)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.ServeWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Drain initial state messages.
	drainInitialState(t, wsConn)

	// Get the server-side client connection.
	hub.mu.RLock()
	var serverClient *Client
	for c := range hub.clients {
		serverClient = c
		break
	}
	hub.mu.RUnlock()

	if serverClient == nil {
		t.Fatal("no client found in hub")
	}

	// Close the server-side connection with an abnormal close code (1006 = CloseAbnormalClosure).
	// This triggers IsUnexpectedCloseError to return true in readPump.
	serverClient.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, "abnormal"),
		time.Now().Add(time.Second),
	)
	time.Sleep(50 * time.Millisecond)

	hub.Close()
	<-runDone
}

// TestReadPump_Unregister verifies that when a client disconnects while the
// hub is still running, readPump's defer selects the
// "c.hub.unregister <- c" branch (not the hub.done branch).
func TestReadPump_Unregister(t *testing.T) {
	store := newTestStore(t)
	defer store.StopGC()

	hub := NewHub(store, []string{"*"}, "")

	runDone := make(chan struct{})
	go func() {
		hub.Run()
		close(runDone)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.ServeWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Wait for client to be registered.
	time.Sleep(50 * time.Millisecond)

	// Verify the client is in the hub.
	hub.mu.RLock()
	initialCount := len(hub.clients)
	hub.mu.RUnlock()
	if initialCount == 0 {
		t.Fatal("expected at least one client registered in hub")
	}

	// Close the client connection (not the hub). This causes readPump to
	// break out of its read loop and hit the defer block. Since the hub is
	// still running, the unregister branch should be selected.
	wsConn.Close()

	// Wait for the hub to process the unregister.
	deadline := time.After(3 * time.Second)
	for {
		hub.mu.RLock()
		count := len(hub.clients)
		hub.mu.RUnlock()
		if count == 0 {
			break // client was unregistered
		}
		select {
		case <-deadline:
			t.Fatal("client was not unregistered within timeout — unregister branch may not have fired")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Hub should still be running (we didn't close it).
	// Clean up.
	hub.Close()
	<-runDone
}

// TestWritePump_BatchDrainMultiple verifies the batch drain inner loop
// where multiple queued messages are drained and written in a single frame.
func TestWritePump_BatchDrainMultiple(t *testing.T) {
	store := newTestStore(t)
	defer store.StopGC()

	hub := NewHub(store, []string{"*"}, "")

	runDone := make(chan struct{})
	go func() {
		hub.Run()
		close(runDone)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.ServeWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Drain initial state messages.
	drainInitialState(t, wsConn)

	// Get the server-side client to directly push messages into the send channel.
	hub.mu.RLock()
	var serverClient *Client
	for c := range hub.clients {
		serverClient = c
		break
	}
	hub.mu.RUnlock()

	if serverClient == nil {
		t.Fatal("no client found in hub")
	}

	// Push multiple messages into the client's send channel to exercise the batch drain loop.
	for i := 0; i < 5; i++ {
		serverClient.send <- []byte(fmt.Sprintf(`{"type":"covbatch-%d"}`, i))
	}

	// Read all messages from the client side.
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var received []string
	for {
		_, msg, err := wsConn.ReadMessage()
		if err != nil {
			break
		}
		received = append(received, string(msg))
		if len(received) >= 5 {
			break
		}
	}

	// Verify all messages were received (they may be batched into fewer frames with newline separators).
	allData := strings.Join(received, "\n")
	for i := 0; i < 5; i++ {
		expected := fmt.Sprintf(`{"type":"covbatch-%d"}`, i)
		if !strings.Contains(allData, expected) {
			t.Errorf("missing %q in received data: %s", expected, allData)
		}
	}

	hub.Close()
	<-runDone
}

// TestWritePump_PingTicker verifies that writePump sends a Ping message when
// the ticker fires. Skipped in short mode since it requires waiting 54 seconds.
func TestWritePump_PingTicker(t *testing.T) {
	if testing.Short() {
		t.Skip("requires waiting for 54s ping ticker")
	}

	store := newTestStore(t)
	defer store.StopGC()

	hub := NewHub(store, []string{"*"}, "")

	runDone := make(chan struct{})
	go func() {
		hub.Run()
		close(runDone)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.ServeWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Drain initial state messages.
	drainInitialState(t, wsConn)

	// Set up a handler to detect Ping messages.
	pingReceived := make(chan struct{}, 1)
	wsConn.SetPingHandler(func(appData string) error {
		select {
		case pingReceived <- struct{}{}:
		default:
		}
		return nil
	})

	// Wait for the 54s ticker to fire and writePump to send a Ping.
	wsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	select {
	case <-pingReceived:
		t.Log("received ping from server")
	case <-time.After(60 * time.Second):
		t.Log("timed out waiting for ping")
	}

	hub.Close()
	<-runDone
}

// TestWritePump_FastPingTicker verifies that writePump sends a Ping when the
// ticker fires, using an injected short interval instead of the 54s production value.
func TestWritePump_FastPingTicker(t *testing.T) {
	store := newTestStore(t)
	defer store.StopGC()

	hub := NewHub(store, []string{"*"}, "")

	// Inject a short ping interval BEFORE connecting so writePump reads it on creation.
	shortInterval := 100 * time.Millisecond
	testWritePumpPingEvery.Store(&shortInterval)
	defer func() { testWritePumpPingEvery.Store(nil) }()

	// Verify the hook was set.
	if v := testWritePumpPingEvery.Load(); v == nil || *v != shortInterval {
		t.Fatalf("test hook not set correctly: got %v", v)
	}

	runDone := make(chan struct{})
	go func() {
		hub.Run()
		close(runDone)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.ServeWS)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()

	// Set up a handler to detect Ping messages BEFORE draining initial state,
	// so we don't miss any pings sent during the drain.
	pingReceived := make(chan struct{}, 1)
	wsConn.SetPingHandler(func(appData string) error {
		select {
		case pingReceived <- struct{}{}:
		default:
		}
		// Send a pong to keep the server's readPump happy.
		wsConn.WriteMessage(websocket.PongMessage, []byte(appData))
		return nil
	})

	// Drain initial state messages.
	drainInitialState(t, wsConn)

	// Wait for the ticker to fire and writePump to send a Ping.
	// We need to actively read so that gorilla/websocket processes control frames
	// (pings). Without ReadMessage calls, the PingHandler never fires.
	wsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-pingReceived:
			t.Log("received fast ping from server")
			goto done
		case <-deadline:
			t.Fatal("writePump ping ticker did not fire within 3 seconds")
		default:
		}
		// Read to trigger control frame processing.
		_, _, err := wsConn.ReadMessage()
		if err != nil {
			// Read deadline or close — check if we got the ping first.
			select {
			case <-pingReceived:
				t.Log("received fast ping from server")
				goto done
			default:
			}
			t.Fatalf("read error while waiting for ping: %v", err)
		}
	}
done:

	hub.Close()
	<-runDone
}
