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
	"sync/atomic"
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
  mcap-encrypt rotate  --old-key <priv.pem> --new-key <pub.pem> [--new-key <pub2.pem>...] [--force] <input.mcap> <output.mcap>
  mcap-encrypt bridge  --key <priv.pem> [--addr <host:port>] <encrypted.mcap>

Commands:
  keygen   Generate an RSA-4096 key pair.
           Writes <basename>.pub.pem and <basename>.priv.pem.

  encrypt  Encrypt an MCAP file. Each chunk is encrypted with XChaCha20-Poly1305.
           Repeat --key to encrypt for multiple recipients; any private key decrypts.
           Supports RSA-4096 and X25519 public keys (single-pass, streaming).
           Press Ctrl-Z to pause, fg to resume.

  decrypt  Decrypt an encrypted MCAP file using the private key.
           Supports RSA and X25519 private keys.
           Outputs a standard, fully-indexed MCAP file.
           Press Ctrl-Z to pause, fg to resume.

  rotate   Re-wrap the symmetric key for a new set of recipients without decrypting
           any chunk data. O(file size) I/O with zero message decryption.
           --old-key: the private key that can currently decrypt the file.
           --new-key: one or more public keys for the new recipient set (repeatable).
           Press Ctrl-Z to pause, fg to resume.

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
	case "rotate":
		runRotate(os.Args[2:])
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

// formatSize formats bytes as a human-readable string (B / KB / MB / GB).
func formatSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// formatETA formats a duration as a compact ETA string.
// Returns "" when the duration is zero, negative, or implausibly large.
func formatETA(d time.Duration) string {
	if d <= 0 || d > 24*time.Hour {
		return ""
	}
	if d < time.Second {
		return "ETA <1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("ETA %ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("ETA %dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("ETA %dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

const barWidth = 22

// renderBar returns the progress line string. total <= 0 means no progress info.
func renderBar(label string, frame byte, elapsed time.Duration, done, total int64, rateMBps float64) string {
	if total <= 0 {
		return fmt.Sprintf("\r\033[K  %c  %s  %.1fs", frame, label, elapsed.Seconds())
	}

	pct := float64(done) / float64(total) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}

	filled := int(pct / 100 * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("=", filled)
	if filled < barWidth {
		bar += ">"
		bar += strings.Repeat(" ", barWidth-filled-1)
	}

	rateStr := "-- MB/s"
	if rateMBps >= 0.01 {
		rateStr = fmt.Sprintf("%.1f MB/s", rateMBps)
	}

	etaStr := ""
	if rateMBps >= 0.01 && pct < 99.5 {
		remMB := float64(total-done) / (1 << 20)
		eta := time.Duration(remMB / rateMBps * float64(time.Second))
		if s := formatETA(eta); s != "" {
			etaStr = "  " + s
		}
	}

	return fmt.Sprintf("\r\033[K  %c  %s  [%s]  %3.0f%%  %s / %s  %s%s",
		frame, label, bar, pct,
		formatSize(done), formatSize(total),
		rateStr, etaStr)
}

// startProgress prints an animated progress bar to stderr.
// bytesTotal <= 0 shows a simple spinner with elapsed time.
// bytesWritten is read atomically each tick.
// Close the returned channel to stop and clear the line.
func startProgress(label string, bytesTotal int64, bytesWritten *atomic.Int64) chan struct{} {
	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		frames := []byte{'-', '\\', '|', '/'}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		start := time.Now()
		i := 0

		var lastSampleBytes int64
		lastSampleTime := start
		var rateMBps float64

		// SIGTSTP (Ctrl-Z): pause the spinner cleanly, suspend the process,
		// then resume the spinner when the shell runs fg.
		sigPause := make(chan os.Signal, 1)
		notifyPause(sigPause)
		defer resetPause(sigPause)

		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(start)
				frame := frames[i%len(frames)]
				i++

				n := int64(0)
				if bytesWritten != nil {
					n = bytesWritten.Load()
				}

				// Update EMA throughput every 500 ms.
				if dt := time.Since(lastSampleTime); dt >= 500*time.Millisecond && dt > 0 {
					inst := float64(n-lastSampleBytes) / dt.Seconds() / (1 << 20)
					if inst >= 0 {
						if rateMBps == 0 {
							rateMBps = inst
						} else {
							// Exponential moving average, alpha = 0.35.
							rateMBps = 0.35*inst + 0.65*rateMBps
						}
					}
					lastSampleBytes = n
					lastSampleTime = time.Now()
				}

				fmt.Fprint(os.Stderr, renderBar(label, frame, elapsed, n, bytesTotal, rateMBps))

			case <-sigPause:
				// Clear the progress line and print a pause notice.
				fmt.Fprint(os.Stderr, "\r\033[K  paused  (run 'fg' to resume)\n")
				// Stop catching SIGTSTP, then send SIGSTOP so the OS suspends us.
				// The process blocks here until the shell sends SIGCONT (fg).
				resetPause(sigPause)
				suspendSelf()
				// Resumed: re-register and redraw immediately.
				notifyPause(sigPause)
				lastSampleTime = time.Now() // reset rate window to avoid spike
				lastSampleBytes = func() int64 {
					if bytesWritten != nil {
						return bytesWritten.Load()
					}
					return 0
				}()

			case <-quit:
				fmt.Fprint(os.Stderr, "\r\033[K")
				return
			}
		}
	}()

	stop := make(chan struct{})
	go func() {
		<-stop
		close(quit)
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
	if *force {
		os.Remove(output) // ignore error; library will catch any real FS issue
	} else if _, statErr := os.Stat(output); statErr == nil {
		fatal(fmt.Errorf("output file %q already exists (use --force to overwrite)", output))
	}

	recipientNote := ""
	if len(keys) > 1 {
		recipientNote = fmt.Sprintf(" (%d recipients)", len(keys))
	}
	fmt.Printf("encrypting%s: %s\n", recipientNote, input)

	inputSize := fileSize(input)
	var progressBytes atomic.Int64
	stop := startProgress("encrypting", inputSize, &progressBytes)
	start := time.Now()
	err := mcapencrypt.EncryptMulti(input, output, []string(keys), func(n int64) {
		progressBytes.Store(n)
	})
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

	if *force {
		os.Remove(output) // ignore error; library will catch any real FS issue
	} else if _, statErr := os.Stat(output); statErr == nil {
		fatal(fmt.Errorf("output file %q already exists (use --force to overwrite)", output))
	}
	fmt.Printf("decrypting: %s\n", input)

	inputSize := fileSize(input)
	var progressBytes atomic.Int64
	stop := startProgress("decrypting", inputSize, &progressBytes)
	start := time.Now()
	err := mcapencrypt.Decrypt(input, output, *key, func(n int64) {
		progressBytes.Store(n)
	})
	close(stop)
	elapsed := time.Since(start)

	if err != nil {
		os.Remove(output)
		fatal(err)
	}
	fmt.Printf("done  %.2fs%s\n", elapsed.Seconds(), formatThroughput(output, elapsed))
}

func runRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	oldKey := fs.String("old-key", "", "path to the current private key (.priv.pem) that can decrypt the file")
	var newKeys stringList
	fs.Var(&newKeys, "new-key", "path to a new recipient public key (.pub.pem); repeat for multiple recipients")
	force := fs.Bool("force", false, "overwrite output file if it exists")
	_ = fs.Parse(args)

	if *oldKey == "" {
		fatal(fmt.Errorf("--old-key is required"))
	}
	if len(newKeys) == 0 {
		fatal(fmt.Errorf("--new-key is required (at least one)"))
	}
	if fs.NArg() != 2 {
		fatal(fmt.Errorf("usage: rotate --old-key <priv.pem> --new-key <pub.pem> <input.mcap> <output.mcap>"))
	}
	input, output := fs.Arg(0), fs.Arg(1)

	oldPrivPEM, err := os.ReadFile(*oldKey)
	if err != nil {
		fatal(fmt.Errorf("read old private key: %w", err))
	}

	newPubPEMs := make([]string, len(newKeys))
	for i, path := range newKeys {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			fatal(fmt.Errorf("read new public key %d (%s): %w", i+1, path, readErr))
		}
		newPubPEMs[i] = string(data)
	}

	if *force {
		os.Remove(output)
	} else if _, statErr := os.Stat(output); statErr == nil {
		fatal(fmt.Errorf("output file %q already exists (use --force to overwrite)", output))
	}

	recipientNote := ""
	if len(newKeys) > 1 {
		recipientNote = fmt.Sprintf(" (%d new recipients)", len(newKeys))
	}
	fmt.Printf("rotating keys%s: %s\n", recipientNote, input)

	start := time.Now()
	err = mcapencrypt.RotateKeyFile(input, output, string(oldPrivPEM), newPubPEMs)
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
	stop := startProgress("decrypting", 0, nil)
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

// fileSize returns the size in bytes of the file at path, or 0 on error.
func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	return info.Size()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
