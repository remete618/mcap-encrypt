# Foxglove Studio integration

`mcap-encrypt bridge` decrypts an encrypted MCAP file, loads all messages into memory, then serves them over the [Foxglove WebSocket protocol](https://github.com/foxglove/ws-protocol). Foxglove Studio connects to it exactly as it connects to a live ROS 2 robot running `foxglove-bridge`: same protocol, same UI, same workflow. No persistent decrypted file remains on disk.

---

## Quick setup

**Step 1: start the bridge**

```bash
mcap-encrypt bridge --key analyst.priv.pem recording.mcap
```

Output:
```
loading: recording.mcap
  /  decrypting  2.1s
done  2.1s
listening: ws://localhost:8765
Open Foxglove Studio → Add connection → Foxglove WebSocket → ws://localhost:8765
Press Ctrl-C to stop.
```

**Step 2: connect Foxglove Studio**

1. Open [Foxglove Studio](https://foxglove.dev/studio) (desktop or `studio.foxglove.dev`).
2. Click **Open data source**.
3. Select **Foxglove WebSocket**.
4. Enter `ws://localhost:8765`.
5. Click **Open**.

All topics, schemas, and messages appear immediately. Camera feeds, lidar point clouds, plots, and diagnostics render exactly as they do with a live ROS 2 source. You can scrub the timeline, jump to timestamps, and use all Foxglove panels.

---

## How it compares to foxglove-bridge

| | `foxglove-bridge` (ROS 2 live) | `mcap-encrypt bridge` (encrypted file) |
|---|---|---|
| Data source | Live ROS 2 node graph | Encrypted MCAP file |
| Protocol | Foxglove WebSocket v1 | Foxglove WebSocket v1 |
| Connect in Studio | `ws://localhost:8765` | `ws://localhost:8765` |
| Key required | No | Yes (your private key) |
| Decrypted file on disk | n/a | Never |
| Multiple clients | Yes | Yes (each gets its own stream) |

The Studio UI is identical. Switch between a live robot and an encrypted log by changing the WebSocket URL.

---

## Custom address

```bash
# Specific port
mcap-encrypt bridge --key analyst.priv.pem --addr localhost:9090 recording.mcap

# All interfaces (use with a TLS reverse proxy in production)
mcap-encrypt bridge --key analyst.priv.pem --addr 0.0.0.0:8765 recording.mcap
```

By default the bridge listens only on `localhost`. The decrypted stream is unencrypted over the WebSocket connection. If you expose the bridge on a non-localhost address, put a TLS-terminating reverse proxy (nginx, Caddy) in front.

---

## How it works

On startup the bridge decrypts the entire file into memory and loads all schemas, channels, and messages. When Foxglove Studio connects and subscribes to topics, the bridge streams binary `MESSAGE_DATA` frames in log-time order. Multiple Studio instances can connect simultaneously; each gets an independent stream. Press Ctrl-C to stop.

The private key never leaves your machine. The decrypted content exists only in RAM.

---

## Using the bridge from Go

```go
import (
    "context"
    "github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// Load once, serve many connections.
state, err := mcapencrypt.LoadBridgeState("recording.mcap", "analyst.priv.pem")
if err != nil { log.Fatal(err) }

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Blocks until ctx is cancelled or the server fails.
if err := mcapencrypt.ServeBridge(ctx, state, "localhost:8765"); err != nil {
    log.Fatal(err)
}
```

`LoadBridgeState` decrypts the file into memory. `ServeBridge` starts the WebSocket server. Separating the two lets you show a progress indicator during load before announcing the server address.

---

## Multi-recipient with Foxglove

The format supports adding Foxglove as a recipient at encrypt time. Once Foxglove publishes a stable public key, this becomes a single extra `--key` flag:

```bash
mcap-encrypt encrypt \
  --key your.pub.pem \
  --key foxglove.pub.pem \
  recording.mcap encrypted.mcap
# You decrypt locally with your.priv.pem.
# Foxglove decrypts on ingest with its own key.
# Ciphertext is identical for both recipients.
```

The library supports this today. The integration requires Foxglove to publish a public key and wire up `iterateMessages()` from the npm package on their ingest side.
