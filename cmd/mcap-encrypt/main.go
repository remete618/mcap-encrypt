package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

const usage = `mcap-encrypt — encrypt and decrypt MCAP files using XChaCha20Poly1305 + RSA-2048

Usage:
  mcap-encrypt keygen  --out <basename>
  mcap-encrypt encrypt --key <pub.pem>  <input.mcap> <output.mcap>
  mcap-encrypt decrypt --key <priv.pem> <input.mcap> <output.mcap>

Commands:
  keygen   Generate an RSA-2048 key pair.
           Writes <basename>.pub.pem and <basename>.priv.pem.

  encrypt  Encrypt an MCAP file. Each chunk is encrypted with XChaCha20Poly1305.
           The symmetric key is wrapped with the RSA public key and stored as
           an attachment named "mcap_encryption_key".
           Schemas and channels remain plaintext (structure visible, data hidden).

  decrypt  Decrypt an encrypted MCAP file using the RSA private key.
           Outputs a standard, fully-indexed MCAP file.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		runKeygen(os.Args[2:])
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
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
	key := fs.String("key", "", "path to RSA public key (.pub.pem)")
	_ = fs.Parse(args)

	if *key == "" {
		fatal(fmt.Errorf("--key is required"))
	}
	if fs.NArg() != 2 {
		fatal(fmt.Errorf("usage: encrypt --key <pub.pem> <input.mcap> <output.mcap>"))
	}
	input, output := fs.Arg(0), fs.Arg(1)

	fmt.Printf("encrypting %s → %s\n", input, output)
	if err := mcapencrypt.Encrypt(input, output, *key); err != nil {
		fatal(err)
	}
	fmt.Println("done")
}

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	key := fs.String("key", "", "path to RSA private key (.priv.pem)")
	_ = fs.Parse(args)

	if *key == "" {
		fatal(fmt.Errorf("--key is required"))
	}
	if fs.NArg() != 2 {
		fatal(fmt.Errorf("usage: decrypt --key <priv.pem> <input.mcap> <output.mcap>"))
	}
	input, output := fs.Arg(0), fs.Arg(1)

	fmt.Printf("decrypting %s → %s\n", input, output)
	if err := mcapencrypt.Decrypt(input, output, *key); err != nil {
		fatal(err)
	}
	fmt.Println("done")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
