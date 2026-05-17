package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

var version = "dev"

const usage = `mcap-encrypt: encrypt and decrypt MCAP files with XChaCha20-Poly1305 + RSA-OAEP-SHA-256

Usage:
  mcap-encrypt keygen  --out <basename>
  mcap-encrypt encrypt --key <pub.pem> [--key <pub2.pem>...] [--force] <input.mcap> <output.mcap>
  mcap-encrypt decrypt --key <priv.pem> [--force] <input.mcap> <output.mcap>
  mcap-encrypt bridge  --key <priv.pem> [--addr <host:port>] <encrypted.mcap>

Commands:
  keygen   Generate an RSA-4096 key pair.
           Writes <basename>.pub.pem and <basename>.priv.pem.

  encrypt  Encrypt an MCAP file. Each chunk is encrypted with XChaCha20-Poly1305.
           Repeat --key to encrypt for multiple recipients; any private key decrypts.
           Supports RSA-4096 and X25519 public keys (single-pass, streaming).

  decrypt  Decrypt an encrypted MCAP file using the private key.
           Supports RSA and X25519 private keys.
           Outputs a standard, fully-indexed MCAP file.

  bridge   Start a Foxglove WebSocket bridge for an encrypted MCAP file.
           Decrypts in memory and serves over the Foxglove ws-protocol.
           Open Foxglove Studio and connect to ws://<addr> (default localhost:8765).
           Press Ctrl-C to stop.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("mcap-encrypt", version)
	case "keygen":
		runKeygen(os.Args[2:])
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	case "bridge":
		runBridge(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

// stringList is a repeatable flag value (--key a --key b → ["a", "b"]).
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ", ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func checkMCAPMagic(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	buf := make([]byte, 8)
	if _, err := io.ReadFull(f, buf); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(buf) != "\x89MCAP0\r\n" {
		return fmt.Errorf("not an MCAP file (invalid magic bytes)")
	}
	return nil
}

// startSpinner prints an animated progress line to stderr. Close the returned
// channel to stop the spinner and clear the line.
func startSpinner(label string) chan struct{} {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		frames := []byte{'-', '\\', '|', '/'}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		start := time.Now()
		i := 0
		for {
			select {
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r  %c  %s  %.1fs",
					frames[i%len(frames)], label, time.Since(start).Seconds())
				i++
			case <-done:
				fmt.Fprint(os.Stderr, "\r\033[K") // clear the progress line
				return
			}
		}
	}()
	// Return a channel that, when closed, stops the spinner and waits for cleanup.
	stop := make(chan struct{})
	go func() {
		<-stop
		close(done)
		wg.Wait()
	}()
	return stop
}

func formatThroughput(path string, elapsed time.Duration) string {
	info, err := os.Stat(path)
	if err != nil || elapsed.Seconds() < 0.01 {
		return ""
	}
	mbps := float64(info.Size()) / elapsed.Seconds() / 1024 / 1024
	return fmt.Sprintf("  (%.1f MB/s)", mbps)
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "mcap-key", "output basename for key files")
	_ = fs.Parse(args)

	if err := mcapencrypt.GenerateKeyPair(*out); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s.priv.pem (keep secret) and %s.pub.pem\n", *out, *out)
}

func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var keys stringList
	fs.Var(&keys, "key", "path to RSA-4096 or X25519 public key (.pub.pem); repeat for multiple recipients")
	force := fs.Bool("force", false, "overwrite output file if it exists")
	_ = fs.Parse(args)

	if len(keys) == 0 {
		fatal(fmt.Errorf("--key is required"))
	}
	if fs.NArg() != 2 {
		fatal(fmt.Errorf("usage: encrypt --key <pub.pem> <input.mcap> <output.mcap>"))
	}
	input, output := fs.Arg(0), fs.Arg(1)

	if err := checkMCAPMagic(input); err != nil {
		fatal(fmt.Errorf("input is not a valid MCAP file: %w", err))
	}
	if !*force {
		if _, statErr := os.Stat(output); statErr == nil {
			fatal(fmt.Errorf("output file %q already exists (use --force to overwrite)", output))
		}
	}

	recipientNote := ""
	if len(keys) > 1 {
		recipientNote = fmt.Sprintf(" (%d recipients)", len(keys))
	}
	fmt.Printf("encrypting%s: %s\n", recipientNote, input)

	stop := startSpinner("encrypting")
	start := time.Now()
	err := mcapencrypt.EncryptMulti(input, output, []string(keys))
	close(stop)
	elapsed := time.Since(start)

	if err != nil {
		os.Remove(output)
		fatal(err)
	}
	fmt.Printf("done  %.2fs%s\n", elapsed.Seconds(), formatThroughput(output, elapsed))
}

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	key := fs.String("key", "", "path to RSA-4096 or X25519 private key (.priv.pem)")
	force := fs.Bool("force", false, "overwrite output file if it exists")
	_ = fs.Parse(args)

	if *key == "" {
		fatal(fmt.Errorf("--key is required"))
	}
	if fs.NArg() != 2 {
		fatal(fmt.Errorf("usage: decrypt --key <priv.pem> <input.mcap> <output.mcap>"))
	}
	input, output := fs.Arg(0), fs.Arg(1)

	if !*force {
		if _, statErr := os.Stat(output); statErr == nil {
			fatal(fmt.Errorf("output file %q already exists (use --force to overwrite)", output))
		}
	}
	fmt.Printf("decrypting: %s\n", input)

	stop := startSpinner("decrypting")
	start := time.Now()
	err := mcapencrypt.Decrypt(input, output, *key)
	close(stop)
	elapsed := time.Since(start)

	if err != nil {
		os.Remove(output)
		fatal(err)
	}
	fmt.Printf("done  %.2fs%s\n", elapsed.Seconds(), formatThroughput(output, elapsed))
}

func runBridge(args []string) {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	key := fs.String("key", "", "path to RSA-4096 or X25519 private key (.priv.pem)")
	addr := fs.String("addr", "localhost:8765", "WebSocket listen address (host:port)")
	_ = fs.Parse(args)

	if *key == "" {
		fatal(fmt.Errorf("--key is required"))
	}
	if fs.NArg() != 1 {
		fatal(fmt.Errorf("usage: bridge --key <priv.pem> [--addr <host:port>] <encrypted.mcap>"))
	}
	mcapPath := fs.Arg(0)

	fmt.Printf("loading: %s\n", mcapPath)
	stop := startSpinner("decrypting")
	start := time.Now()

	state, err := mcapencrypt.LoadBridgeState(mcapPath, *key)
	close(stop)
	if err != nil {
		fatal(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("done  %.2fs\n", elapsed.Seconds())
	fmt.Printf("listening: ws://%s\n", *addr)
	fmt.Println("Open Foxglove Studio → Add connection → Foxglove WebSocket → ws://" + *addr)
	fmt.Println("Press Ctrl-C to stop.")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nshutting down...")
		cancel()
	}()

	if err := mcapencrypt.ServeBridge(ctx, state, *addr); err != nil {
		if ctx.Err() == nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
