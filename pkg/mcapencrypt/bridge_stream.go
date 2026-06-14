package mcapencrypt

import (
	"container/list"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rsa"
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

// defaultStreamingChunkCacheSize is the number of decrypted chunks the
// streaming bridge keeps in its LRU. Tunable later; held constant for the
// first cut so the bridge has a predictable RAM ceiling regardless of file
// size. Each cached entry is a decompressed chunk (typically a few MiB).
const defaultStreamingChunkCacheSize = 8

// chunkIndexEntry is the per-chunk metadata extracted during the initial
// summary scan. The ciphertext is not held in memory — only what we need to
// (a) decide whether a chunk overlaps a requested time range and (b) read
// and decrypt the chunk's bytes on demand.
type chunkIndexEntry struct {
	chunkIdx         uint64 // index in encryption sequence; bound into AEAD AAD
	recordDataOffset int64  // file offset of the EncryptedChunk record's data payload
	recordDataLen    int64  // length of that data payload
	messageStartTime uint64
	messageEndTime   uint64
}

// streamingBridgeState is the on-demand-decrypt counterpart to bridgeState.
// At load time it reads schemas, channels, and the encrypted chunk index from
// the file, decrypts no chunks, and verifies the manifest HMAC. At serve
// time, each subscription scans the chunk index for overlap with the
// requested time range and decrypts only those chunks, cached LRU.
type streamingBridgeState struct {
	file       *os.File
	schemas    []*mcap.Schema
	channels   []*mcap.Channel
	schemaByID map[uint16]*mcap.Schema

	symKey  []byte
	fileID  []byte
	chunks  []chunkIndexEntry
	cacheMu sync.Mutex
	// cache stores decompressed chunk bytes (inner record stream) keyed by
	// chunkIdx. The LRU is enforced by recency in the linked list.
	cache       map[uint64]*list.Element
	cacheList   *list.List
	cacheCap    int
	decryptOnce sync.Map // tracks chunks currently being decrypted to dedupe work

	// decryptCount is incremented each time decryptChunkOnDemand performs an
	// AEAD open (cache miss + decompress). Tests inspect it via
	// DecryptCount to verify the streaming bridge only touches the chunks
	// the time range demands.
	decryptCount uint64
	countMu      sync.Mutex
}

// StreamingBridgeState is the exported alias for streamingBridgeState.
type StreamingBridgeState = streamingBridgeState

// DecryptCount returns the number of chunk decryptions performed so far.
// Test hook; not part of the public bridge contract.
func (s *streamingBridgeState) DecryptCount() uint64 {
	s.countMu.Lock()
	defer s.countMu.Unlock()
	return s.decryptCount
}

// Close releases the underlying file handle and clears cached plaintext.
func (s *streamingBridgeState) Close() error {
	s.cacheMu.Lock()
	for k := range s.cache {
		delete(s.cache, k)
	}
	s.cacheList.Init()
	s.cacheMu.Unlock()
	clear(s.symKey)
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// LoadStreamingBridgeState opens an encrypted MCAP, parses the summary to
// build a chunk index, and prepares for on-demand decryption. It does NOT
// decrypt any chunks; callers see no plaintext until they request a time
// range. The file handle is held open until Close is called.
func LoadStreamingBridgeState(mcapPath, privKeyPath string) (*StreamingBridgeState, error) {
	privKey, err := LoadPrivateKeyAny(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}
	var unwrap func(kekAlg string, wrappedKey []byte) ([]byte, error)
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		unwrap = func(kekAlg string, wrappedKey []byte) ([]byte, error) {
			if kekAlg != "rsa-oaep-sha256" {
				return nil, fmt.Errorf("private key is RSA but slot uses %q", kekAlg)
			}
			return UnwrapSymmetricKey(wrappedKey, k)
		}
	case *ecdh.PrivateKey:
		unwrap = func(kekAlg string, wrappedKey []byte) ([]byte, error) {
			if kekAlg != "x25519-hkdf-xchacha20poly1305" {
				return nil, fmt.Errorf("private key is X25519 but slot uses %q", kekAlg)
			}
			return UnwrapSymmetricKeyX25519(wrappedKey, k)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privKey)
	}

	f, err := os.Open(mcapPath)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	state, err := scanEncryptedFile(f, unwrap)
	if err != nil {
		f.Close()
		return nil, err
	}
	state.file = f
	state.cache = make(map[uint64]*list.Element)
	state.cacheList = list.New()
	state.cacheCap = defaultStreamingChunkCacheSize
	return state, nil
}

// scanEncryptedFile walks an encrypted MCAP once, capturing schemas,
// channels, wrapped-key attachments (to unwrap symKey + fileID), and the
// offset+metadata of every EncryptedChunk record. It also verifies the
// manifest HMAC if present, so streaming clients get the same anti-strip
// guarantees as batch decrypt.
func scanEncryptedFile(f *os.File, unwrap func(kekAlg string, wrappedKey []byte) ([]byte, error)) (*streamingBridgeState, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek input: %w", err)
	}
	if err := ReadMagic(f); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}

	state := &streamingBridgeState{
		schemaByID: make(map[uint16]*mcap.Schema),
	}
	var (
		symKey           []byte
		fileID           []byte
		chunkIdx         uint64
		wkaCount         int
		manifestRequired bool
		manifestPayload  []byte
	)
	pos := int64(8) // bytes already consumed by ReadMagic

scan:
	for {
		// pos is the byte offset of the next record's opcode.
		opcode, data, err := ReadRecord(f)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		// recordDataOffset is the offset of `data` within the file
		// (immediately after the 9-byte record header).
		recordDataOffset := pos + 9
		recordDataLen := int64(len(data))
		pos = recordDataOffset + recordDataLen

		switch opcode {
		case opcodeSchema:
			s, parseErr := mcap.ParseSchema(data)
			if parseErr != nil {
				return nil, fmt.Errorf("parse schema: %w", parseErr)
			}
			cp := &mcap.Schema{
				ID:       s.ID,
				Name:     s.Name,
				Encoding: s.Encoding,
				Data:     make([]byte, len(s.Data)),
			}
			copy(cp.Data, s.Data)
			state.schemas = append(state.schemas, cp)
			state.schemaByID[s.ID] = cp

		case opcodeChannel:
			c, parseErr := mcap.ParseChannel(data)
			if parseErr != nil {
				return nil, fmt.Errorf("parse channel: %w", parseErr)
			}
			cp := &mcap.Channel{
				ID:              c.ID,
				SchemaID:        c.SchemaID,
				Topic:           c.Topic,
				MessageEncoding: c.MessageEncoding,
				Metadata:        c.Metadata,
			}
			state.channels = append(state.channels, cp)

		case opcodeAttach:
			name, mediaType, attData, parseErr := parseAttachmentRecord(data)
			if parseErr != nil {
				return nil, fmt.Errorf("parse attachment: %w", parseErr)
			}
			if name == ManifestAttachmentName && mediaType == ManifestAttachmentMediaType {
				manifestPayload = make([]byte, len(attData))
				copy(manifestPayload, attData)
				continue
			}
			if name != AttachmentName || mediaType != AttachmentMediaType {
				continue // non-key, non-manifest attachments are not served by the streaming bridge
			}
			wkaCount++
			wkd, decErr := DecodeWrappedKeyData(attData)
			if decErr != nil {
				continue
			}
			if wkd.Version >= wrappedKeyVersion {
				manifestRequired = true
			}
			if symKey != nil {
				continue
			}
			candidate, unwrapErr := unwrap(wkd.KEKAlg, wkd.WrappedKey)
			if unwrapErr != nil {
				continue
			}
			if len(candidate) != 32 {
				continue
			}
			symKey = candidate
			fileID = wkd.FileID

		case OpcodeEncryptedChunk:
			if symKey == nil {
				if wkaCount == 0 {
					return nil, fmt.Errorf("encountered encrypted chunk before wrapped key attachment")
				}
				return nil, fmt.Errorf("private key does not match any of the %d recipient key(s) in this file", wkaCount)
			}
			// Decode header fields only; ciphertext stays on disk.
			ec, decErr := DecodeEncryptedChunk(data)
			if decErr != nil {
				return nil, fmt.Errorf("decode encrypted chunk: %w", decErr)
			}
			state.chunks = append(state.chunks, chunkIndexEntry{
				chunkIdx:         chunkIdx,
				recordDataOffset: recordDataOffset,
				recordDataLen:    recordDataLen,
				messageStartTime: ec.MessageStartTime,
				messageEndTime:   ec.MessageEndTime,
			})
			chunkIdx++

		case opcodeFooter:
			break scan
		}
	}

	if symKey == nil {
		if wkaCount == 0 {
			return nil, fmt.Errorf("input is not an encrypted MCAP file (no wrapped key attachment present); only files produced by 'mcap-encrypt encrypt' can be decrypted")
		}
		return nil, fmt.Errorf("private key does not match any of the %d recipient key(s) in this file", wkaCount)
	}

	if manifestRequired && manifestPayload == nil {
		return nil, fmt.Errorf("manifest attachment missing: file may have been tampered with (strip attack)")
	}
	if manifestPayload != nil {
		if len(manifestPayload) < manifestPayloadSize {
			return nil, fmt.Errorf("manifest payload too short (%d bytes, need %d)", len(manifestPayload), manifestPayloadSize)
		}
		storedCount := binary.LittleEndian.Uint64(manifestPayload[:8])
		storedHMAC := manifestPayload[8 : 8+32]
		expectedHMAC := ComputeManifestHMAC(symKey, storedCount, fileID)
		if !hmac.Equal(storedHMAC, expectedHMAC) {
			return nil, fmt.Errorf("manifest HMAC verification failed: file may be corrupted or tampered")
		}
		if storedCount != chunkIdx {
			if storedCount < chunkIdx {
				return nil, fmt.Errorf("manifest chunk count mismatch: declared %d chunk(s), found %d (file may have been padded with extra chunks)", storedCount, chunkIdx)
			}
			return nil, fmt.Errorf("manifest chunk count mismatch: declared %d chunk(s), found %d (file appears truncated)", storedCount, chunkIdx)
		}
	}

	state.symKey = symKey
	state.fileID = fileID
	return state, nil
}

// decryptedChunk is the unit cached in the LRU: the decompressed concatenated
// MCAP records (Schema, Channel, Message …) that the chunk contained.
type decryptedChunk struct {
	chunkIdx uint64
	records  []byte
}

// getDecryptedChunk returns the decompressed inner-record bytes for the given
// chunk, decrypting if necessary. Concurrent callers for the same chunk
// dedupe via a sync.Once-like sync.Map entry, so a hot chunk is decrypted
// exactly once even under contention.
func (s *streamingBridgeState) getDecryptedChunk(entry chunkIndexEntry) ([]byte, error) {
	// Fast path: cache hit.
	s.cacheMu.Lock()
	if el, ok := s.cache[entry.chunkIdx]; ok {
		s.cacheList.MoveToFront(el)
		dc := el.Value.(*decryptedChunk)
		out := dc.records
		s.cacheMu.Unlock()
		return out, nil
	}
	s.cacheMu.Unlock()

	// Dedupe parallel decrypts of the same chunk.
	onceAny, _ := s.decryptOnce.LoadOrStore(entry.chunkIdx, &sync.Once{})
	once := onceAny.(*sync.Once)
	var (
		decErr error
		result []byte
	)
	once.Do(func() {
		result, decErr = s.decryptChunkFromDisk(entry)
		if decErr == nil {
			s.cachePut(entry.chunkIdx, result)
		}
	})
	s.decryptOnce.Delete(entry.chunkIdx)
	if decErr != nil {
		return nil, decErr
	}
	if result != nil {
		return result, nil
	}
	// Another goroutine ran the Once: re-check the cache.
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if el, ok := s.cache[entry.chunkIdx]; ok {
		s.cacheList.MoveToFront(el)
		return el.Value.(*decryptedChunk).records, nil
	}
	return nil, fmt.Errorf("chunk %d: decrypt completed concurrently but cache miss", entry.chunkIdx)
}

func (s *streamingBridgeState) cachePut(chunkIdx uint64, records []byte) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if el, ok := s.cache[chunkIdx]; ok {
		s.cacheList.MoveToFront(el)
		el.Value.(*decryptedChunk).records = records
		return
	}
	el := s.cacheList.PushFront(&decryptedChunk{chunkIdx: chunkIdx, records: records})
	s.cache[chunkIdx] = el
	for s.cacheList.Len() > s.cacheCap {
		back := s.cacheList.Back()
		if back == nil {
			break
		}
		dc := back.Value.(*decryptedChunk)
		s.cacheList.Remove(back)
		delete(s.cache, dc.chunkIdx)
	}
}

func (s *streamingBridgeState) decryptChunkFromDisk(entry chunkIndexEntry) ([]byte, error) {
	// Read the record's data payload from disk. Concurrent ReadAt calls on
	// the same *os.File are safe and do not advance a shared offset.
	buf := make([]byte, entry.recordDataLen)
	if _, err := s.file.ReadAt(buf, entry.recordDataOffset); err != nil {
		return nil, fmt.Errorf("read chunk %d at offset %d: %w", entry.chunkIdx, entry.recordDataOffset, err)
	}
	ec, decErr := DecodeEncryptedChunk(buf)
	if decErr != nil {
		return nil, fmt.Errorf("decode chunk %d: %w", entry.chunkIdx, decErr)
	}
	plaintext, decErr := decryptSingleChunk(ec, s.symKey, s.fileID, entry.chunkIdx)
	if decErr != nil {
		return nil, decErr
	}
	s.countMu.Lock()
	s.decryptCount++
	s.countMu.Unlock()
	if ec.UncompressedSize == 0 {
		return nil, nil
	}
	decompressed, err := decompressChunkData(plaintext, ec.Compression)
	if err != nil {
		return nil, fmt.Errorf("decompress chunk %d: %w", entry.chunkIdx, err)
	}
	if ec.UncompressedSize != 0 && uint64(len(decompressed)) != ec.UncompressedSize {
		return nil, fmt.Errorf("chunk %d: uncompressed size mismatch: got %d, want %d", entry.chunkIdx, len(decompressed), ec.UncompressedSize)
	}
	return decompressed, nil
}

// ServeStreamingBridge starts a Foxglove WebSocket bridge that decrypts
// chunks on demand. Unlike ServeBridge, RAM usage is bounded by the LRU
// chunk cache rather than the file size.
func ServeStreamingBridge(ctx context.Context, state *StreamingBridgeState, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, upgradeErr := wsUpgrader.Upgrade(w, r, nil)
		if upgradeErr != nil {
			return
		}
		serveWSStreamingClient(conn, state)
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

// StreamingBridge is the on-demand-decrypt counterpart to Bridge. It opens
// the encrypted MCAP, scans its summary, and serves a Foxglove WebSocket
// bridge until ctx is done. Chunks are decrypted as Studio requests them.
func StreamingBridge(ctx context.Context, mcapPath, privKeyPath, addr string) error {
	state, err := LoadStreamingBridgeState(mcapPath, privKeyPath)
	if err != nil {
		return err
	}
	defer state.Close()
	return ServeStreamingBridge(ctx, state, addr)
}

// serveWSStreamingClient mirrors serveWSClient but is wired to the
// on-demand decrypt path.
func serveWSStreamingClient(conn *websocket.Conn, state *streamingBridgeState) {
	defer conn.Close()

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
		Name:               "mcap-encrypt bridge (streaming)",
		Capabilities:       []string{},
		SupportedEncodings: []string{},
	}); err != nil {
		return
	}

	if err := sendText(wsAdvertise{
		Op:       "advertise",
		Channels: buildStreamingWSChannels(state),
	}); err != nil {
		return
	}

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
			if !streaming && len(subscriptions) > 0 {
				streaming = true
				snapSubs := make(map[uint32]uint16, len(subscriptions))
				for k, v := range subscriptions {
					snapSubs[k] = v
				}
				go streamWSStreamingMessages(state, snapSubs, sendBinary)
			}
		}
	}
}

func buildStreamingWSChannels(state *streamingBridgeState) []wsChannel {
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

// streamWSStreamingMessages iterates the full time range, decrypting only
// chunks that contain subscribed-channel messages. Foxglove Studio receives
// the same ws-protocol MESSAGE_DATA framing as the batch bridge — only the
// path that produced the bytes is different.
func streamWSStreamingMessages(state *streamingBridgeState, subscriptions map[uint32]uint16, send func([]byte) error) {
	chanToSub := make(map[uint16]uint32, len(subscriptions))
	for subID, chanID := range subscriptions {
		chanToSub[chanID] = subID
	}
	err := state.iterateMessages(0, ^uint64(0), func(msg *mcap.Message) error {
		subID, ok := chanToSub[msg.ChannelID]
		if !ok {
			return nil
		}
		frame := make([]byte, 13+len(msg.Data))
		frame[0] = wsBinaryOpMessageData
		binary.LittleEndian.PutUint32(frame[1:5], subID)
		binary.LittleEndian.PutUint64(frame[5:13], msg.LogTime)
		copy(frame[13:], msg.Data)
		return send(frame)
	})
	_ = err // client may have disconnected; nothing to do
}

// iterateMessages yields decoded mcap.Message values for chunks whose
// [start, end] times overlap [fromNanos, toNanos]. Chunks fully outside the
// range are skipped without any disk I/O or decrypt work. Messages within a
// matching chunk that fall outside the range are skipped at parse time.
func (s *streamingBridgeState) iterateMessages(fromNanos, toNanos uint64, yield func(*mcap.Message) error) error {
	for i := range s.chunks {
		entry := s.chunks[i]
		if entry.messageEndTime < fromNanos || entry.messageStartTime > toNanos {
			continue
		}
		records, err := s.getDecryptedChunk(entry)
		if err != nil {
			return err
		}
		if records == nil {
			continue
		}
		// Walk the inner record stream and emit Message records whose log
		// time falls within the window. This mirrors writeChunkMessages but
		// hands each message to the yield callback instead of an mcap.Writer.
		o := 0
		for o < len(records) {
			if o+9 > len(records) {
				return fmt.Errorf("chunk %d: truncated inner record header at offset %d", entry.chunkIdx, o)
			}
			innerOpcode := records[o]
			length := binary.LittleEndian.Uint64(records[o+1 : o+9])
			o += 9
			if length > uint64(len(records)-o) {
				return fmt.Errorf("chunk %d: truncated inner record data at offset %d", entry.chunkIdx, o)
			}
			end := o + int(length)
			if innerOpcode == 0x05 {
				msg, parseErr := mcap.ParseMessage(records[o:end])
				if parseErr != nil {
					return fmt.Errorf("chunk %d: parse message: %w", entry.chunkIdx, parseErr)
				}
				if msg.LogTime >= fromNanos && msg.LogTime <= toNanos {
					if yieldErr := yield(msg); yieldErr != nil {
						return yieldErr
					}
				}
			}
			o = end
		}
	}
	return nil
}
