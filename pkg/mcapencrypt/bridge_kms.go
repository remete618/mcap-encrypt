package mcapencrypt

import (
	"context"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt/kms"
)

// LoadBridgeStateWithKMS is the KMS-backed analogue of LoadBridgeState: it
// decrypts the input MCAP via the supplied Decrypter (private key stays in
// the KMS) and loads the result into a BridgeState for ServeBridge.
//
// The intermediate decrypted file is written to a temporary location and
// removed after loading, matching LoadBridgeState. Files larger than
// MaxBridgeFileSize are rejected for the same reason.
func LoadBridgeStateWithKMS(ctx context.Context, mcapPath string, kmsDec kms.Decrypter) (*BridgeState, error) {
	return loadBridgeStateFn(mcapPath, func(in, out string) error {
		return DecryptFileWithKMS(ctx, in, out, kmsDec)
	})
}
