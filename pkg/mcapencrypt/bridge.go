package mcapencrypt

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/gorilla/websocket"
)

// wsFoxgloveSubprotocol is the WebSocket subprotocol negotiated with Foxglove Studio.
const wsFoxgloveSubprotocol = "foxglove.websocket.v1"

// wsBinaryOpMessageData is the binary opcode for MESSAGE_DATA frames in the
// Foxglove ws-protocol (https://github.com/foxglove/ws-protocol).
const wsBinaryOpMessageData = byte(0x01)

// --- ws-protocol JSON message types ---

type wsServerInfo struct {
	Op                 string   `json:"op"`
	Name               string   `json:"name"`
	Capabilities       []string `json:"capabilities"`
	SupportedEncodings []string `json:"supportedEncodings"`
}

type wsChannel struct {
	ID             uint32 `json:"id"`
	Topic          string `json:"topic"`
	Encoding       string `json:"encoding"`
	SchemaName     string `json:"schemaName"`
	Schema         string `json:"schema"`         // base64-encoded schema bytes
	SchemaEncoding string `json:"schemaEncoding"` // e.g. "ros2msg", "proto", "jsonschema"
}

type wsAdvertise struct {
	Op       string      `json:"op"`
	Channels []wsChannel `json:"channels"`
}

type wsSubscription struct {
	ID        uint32 `json:"id"`
	ChannelID uint32 `json:"channelId"`
}

type wsClientSubscribe struct {
	Op            string           `json:"op"`
	Subscriptions []wsSubscription `json:"subscriptions"`
}

// --- In-memory bridge state ---

// bridgeMsg is a single decrypted message loaded into memory.
type bridgeMsg struct {
	channelID uint16
	logTime   uint64
	data      []byte
}

// bridgeState holds everything loaded from the encrypted MCAP file.
type bridgeState struct {
	schemas    []*mcap.Schema
	channels   []*mcap.Channel
	messages   []*bridgeMsg
	schemaByID map[uint16]*mcap.Schema
}

// BridgeState holds all data loaded from an encrypted MCAP file, ready to
// serve over the Foxglove WebSocket protocol. Obtain via LoadBridgeState.
type BridgeState = bridgeState

// LoadBridgeState decrypts the encrypted MCAP at mcapPath and loads all
// schemas, channels, and messages into memory. The intermediate decrypted file
// is written to a temporary location and removed after loading.
func LoadBridgeState(mcapPath, privKeyPath string) (*BridgeState, error) {
	return loadBridgeState(mcapPath, privKeyPath)
}

func loadBridgeState(mcapPath, privKeyPath string) (*bridgeState, error) {
	tmp, err := os.CreateTemp("", "mcap-bridge-*.mcap")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	// Remove the empty temp file so Decrypt can create it at the same path.
	os.Remove(tmpPath)
	defer os.Remove(tmpPath)

	if err := Decrypt(mcapPath, tmpPath, privKeyPath); err != nil {
		return nil, err
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("open decrypted temp: %w", err)
	}
	defer f.Close()

	reader, err := mcap.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("create MCAP reader: %w", err)
	}
	defer reader.Close()

	info, err := reader.Info()
	if err != nil {
		return nil, fmt.Errorf("read MCAP info: %w", err)
	}

	state := &bridgeState{
		schemaByID: make(map[uint16]*mcap.Schema, len(info.Schemas)),
	}
	for _, s := range info.Schemas {
		cp := &mcap.Schema{
			ID:       s.ID,
			Name:     s.Name,
			Encoding: s.Encoding,
			Data:     make([]byte, len(s.Data)),
		}
		copy(cp.Data, s.Data)
		state.schemas = append(state.schemas, cp)
		state.schemaByID[s.ID] = cp
	}
	for _, c := range info.Channels {
		cp := &mcap.Channel{
			ID:              c.ID,
			SchemaID:        c.SchemaID,
			Topic:           c.Topic,
			MessageEncoding: c.MessageEncoding,
			Metadata:        c.Metadata,
		}
		state.channels = append(state.channels, cp)
	}

	it, err := reader.Messages(mcap.UsingIndex(true), mcap.AfterNanos(0), mcap.BeforeNanos(^uint64(0)))
	if err != nil {
		return nil, fmt.Errorf("create message iterator: %w", err)
	}
	var msg *mcap.Message
	for {
		_, _, msg, err = it.NextInto(msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read message: %w", err)
		}
		dataCopy := make([]byte, len(msg.Data))
		copy(dataCopy, msg.Data)
		state.messages = append(state.messages, &bridgeMsg{
			channelID: msg.ChannelID,
			logTime:   msg.LogTime,
			data:      dataCopy,
		})
	}

	return state, nil
}

// --- WebSocket server ---

var wsUpgrader = websocket.Upgrader{
	CheckOrigin:  func(_ *http.Request) bool { return true },
	Subprotocols: []string{wsFoxgloveSubprotocol},
}

// ServeBridge starts a Foxglove WebSocket bridge server at addr for a
// pre-loaded BridgeState. Foxglove Studio connects to ws://addr.
// The server runs until ctx is done.
func ServeBridge(ctx context.Context, state *BridgeState, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, upgradeErr := wsUpgrader.Upgrade(w, r, nil)
		if upgradeErr != nil {
			return
		}
		serveWSClient(conn, state)
	})

	srv := &http.Server{Addr: addr, Handler: mux}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		return srv.Shutdown(context.Background()) //nolint:contextcheck
	case err := <-errCh:
		return err
	}
}

// Bridge decrypts the encrypted MCAP at mcapPath and starts a Foxglove
// WebSocket bridge server listening at addr (e.g. "localhost:8765").
// Foxglove Studio connects to ws://addr. The server runs until ctx is done.
// For progress reporting during the load phase, use LoadBridgeState + ServeBridge.
func Bridge(ctx context.Context, mcapPath, privKeyPath, addr string) error {
	state, err := loadBridgeState(mcapPath, privKeyPath)
	if err != nil {
		return err
	}
	return ServeBridge(ctx, state, addr)
}

// serveWSClient handles one Foxglove Studio connection: sends serverInfo and
// advertise, then streams subscribed messages when the client subscribes.
func serveWSClient(conn *websocket.Conn, state *bridgeState) {
	defer conn.Close()

	// Gorilla websocket allows one concurrent writer. We guard with a mutex so
	// the streaming goroutine and the control loop can both write safely.
	var mu sync.Mutex
	sendText := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		return conn.WriteMessage(websocket.TextMessage, b)
	}
	sendBinary := func(b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		return conn.WriteMessage(websocket.BinaryMessage, b)
	}

	if err := sendText(wsServerInfo{
		Op:                 "serverInfo",
		Name:               "mcap-encrypt bridge",
		Capabilities:       []string{},
		SupportedEncodings: []string{},
	}); err != nil {
		return
	}

	if err := sendText(wsAdvertise{
		Op:       "advertise",
		Channels: buildWSChannels(state),
	}); err != nil {
		return
	}

	// subscriptions maps subscriptionID → channelID.
	subscriptions := map[uint32]uint16{}
	streaming := false

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var op struct {
			Op string `json:"op"`
		}
		if err := json.Unmarshal(raw, &op); err != nil {
			continue
		}

		switch op.Op {
		case "subscribe":
			var sub wsClientSubscribe
			if err := json.Unmarshal(raw, &sub); err != nil {
				continue
			}
			for _, s := range sub.Subscriptions {
				subscriptions[s.ID] = uint16(s.ChannelID)
			}
			// Start one streaming goroutine per client; ignore subsequent subscribes.
			if !streaming && len(subscriptions) > 0 {
				streaming = true
				snapSubs := make(map[uint32]uint16, len(subscriptions))
				for k, v := range subscriptions {
					snapSubs[k] = v
				}
				go streamWSMessages(state, snapSubs, sendBinary)
			}
		}
	}
}

// buildWSChannels converts MCAP schemas and channels to ws-protocol channel descriptors.
func buildWSChannels(state *bridgeState) []wsChannel {
	out := make([]wsChannel, 0, len(state.channels))
	for _, c := range state.channels {
		s := state.schemaByID[c.SchemaID]
		var schemaName, schemaEnc, schema64 string
		if s != nil {
			schemaName = s.Name
			schemaEnc = s.Encoding
			schema64 = base64.StdEncoding.EncodeToString(s.Data)
		}
		out = append(out, wsChannel{
			ID:             uint32(c.ID),
			Topic:          c.Topic,
			Encoding:       c.MessageEncoding,
			SchemaName:     schemaName,
			Schema:         schema64,
			SchemaEncoding: schemaEnc,
		})
	}
	return out
}

// streamWSMessages sends all messages for subscribed channels in log-time order.
// Each message is framed as a ws-protocol binary MESSAGE_DATA record:
//
//	byte[0]    = 0x01 (MESSAGE_DATA opcode)
//	bytes[1-4] = subscriptionId (uint32 LE)
//	bytes[5-12]= logTime (uint64 LE)
//	bytes[13+] = message payload
func streamWSMessages(state *bridgeState, subscriptions map[uint32]uint16, send func([]byte) error) {
	// Reverse map: channelID → subscriptionID
	chanToSub := make(map[uint16]uint32, len(subscriptions))
	for subID, chanID := range subscriptions {
		chanToSub[chanID] = subID
	}

	for _, msg := range state.messages {
		subID, ok := chanToSub[msg.channelID]
		if !ok {
			continue
		}
		frame := make([]byte, 13+len(msg.data))
		frame[0] = wsBinaryOpMessageData
		binary.LittleEndian.PutUint32(frame[1:5], subID)
		binary.LittleEndian.PutUint64(frame[5:13], msg.logTime)
		copy(frame[13:], msg.data)
		if err := send(frame); err != nil {
			return
		}
	}
}
