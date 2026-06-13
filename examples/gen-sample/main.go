// gen-sample writes examples/sample.mcap. Run from the repo root:
//
//	go run ./examples/gen-sample
//
// The generated file is a tiny chunked MCAP with two channels (a JSON
// "sensor" stream and a JSON "cmd" stream) and 100 messages total. It is
// large enough to exercise multi-chunk encryption, small enough to commit
// to source control. Regenerate it whenever the desired sample contents
// change; the file is otherwise stable across runs.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/foxglove/mcap/go/mcap"
)

func main() {
	const outputPath = "examples/sample.mcap"
	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		os.Exit(1)
	}
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{
		Chunked:     true,
		ChunkSize:   1024,
		Compression: mcap.CompressionZSTD,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "writer:", err)
		os.Exit(1)
	}

	must := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	must(w.WriteHeader(&mcap.Header{Profile: "sample"}))
	must(w.WriteSchema(&mcap.Schema{
		ID: 1, Name: "Sensor", Encoding: "jsonschema",
		Data: []byte(`{"type":"object","properties":{"x":{"type":"number"},"y":{"type":"number"}}}`),
	}))
	must(w.WriteSchema(&mcap.Schema{
		ID: 2, Name: "Cmd", Encoding: "jsonschema",
		Data: []byte(`{"type":"object","properties":{"v":{"type":"number"}}}`),
	}))
	must(w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/sensor", MessageEncoding: "json"}))
	must(w.WriteChannel(&mcap.Channel{ID: 2, SchemaID: 2, Topic: "/cmd", MessageEncoding: "json"}))

	// Use a fixed epoch so the file bytes are deterministic across runs.
	base := uint64(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	for i := 0; i < 50; i++ {
		ts := base + uint64(i)*1_000_000
		must(w.WriteMessage(&mcap.Message{
			ChannelID: 1, Sequence: uint32(i), LogTime: ts, PublishTime: ts,
			Data: []byte(fmt.Sprintf(`{"x":%d,"y":%d}`, i, i*2)),
		}))
		must(w.WriteMessage(&mcap.Message{
			ChannelID: 2, Sequence: uint32(i), LogTime: ts + 500_000, PublishTime: ts + 500_000,
			Data: []byte(fmt.Sprintf(`{"v":%d}`, i+100)),
		}))
	}
	must(w.Close())

	info, _ := os.Stat(outputPath)
	fmt.Printf("wrote %s (%d bytes, 100 messages, 2 channels)\n", outputPath, info.Size())
}
