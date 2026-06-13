package mcapencrypt

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt/kms"
)

// DecryptWithKMS reads an encrypted MCAP from r and writes a standard,
// indexed MCAP to w, using a KMS-backed Decrypter to unwrap the symmetric
// key. The private RSA key never crosses the KMS boundary; only the
// 32-byte symmetric key is returned to this process.
//
// This is the third decrypt entry point alongside Decrypt (file/path-based,
// local private key) and DecryptWithOptions (reader-based, local private
// key). Behaviour is otherwise identical: wrapped-key attachments may use
// either KEK algorithm at parse time, but the KMS decrypter will reject any
// non-RSA-OAEP-SHA-256 slot — RSA is currently the only algorithm any major
// KMS exposes for asymmetric decrypt.
func DecryptWithKMS(ctx context.Context, r io.Reader, w io.Writer, kmsDec kms.Decrypter, opts DecryptOptions) error {
	if kmsDec == nil {
		return fmt.Errorf("nil KMS decrypter")
	}
	unwrap := func(kekAlg string, wrappedKey []byte) ([]byte, error) {
		return kmsDec.Decrypt(ctx, kekAlg, wrappedKey)
	}
	return streamDecrypt(r, w, unwrap, opts.WarnFunc)
}

// DecryptFileWithKMS is the file-path analogue of DecryptWithKMS. It writes
// atomically to a temp file in the output directory and renames into place,
// matching Decrypt's behaviour on the on-disk private-key path.
// inputPath and outputPath must differ.
func DecryptFileWithKMS(ctx context.Context, inputPath, outputPath string, kmsDec kms.Decrypter, progress ...func(int64)) (retErr error) {
	absIn, err := filepath.Abs(inputPath)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	absOut, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if absIn == absOut {
		return fmt.Errorf("inputPath and outputPath must differ")
	}
	if _, statErr := os.Stat(absOut); statErr == nil {
		return fmt.Errorf("output file already exists: %q (delete it first)", outputPath)
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(outputPath), ".mcap-encrypt-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	tmpPath := tmpFile.Name()
	var tmpClosed bool
	defer func() {
		if !tmpClosed {
			if err := tmpFile.Close(); err != nil && retErr == nil {
				retErr = fmt.Errorf("close temp output: %w", err)
			}
		}
		if retErr != nil {
			os.Remove(tmpPath)
		}
	}()

	var src io.Reader = inFile
	if len(progress) > 0 && progress[0] != nil {
		src = &progressReader{r: inFile, progress: progress[0]}
	}
	if err := DecryptWithKMS(ctx, src, tmpFile, kmsDec, DecryptOptions{}); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("flush temp output: %w", err)
	}
	tmpClosed = true
	return os.Rename(tmpPath, outputPath)
}
