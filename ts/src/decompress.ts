import { decompress as zstdDecompress } from "fzstd";

export function decompressChunkData(data: Uint8Array, compression: string): Uint8Array {
  switch (compression) {
    case "":
    case "none":
      return data;
    case "zstd":
      return zstdDecompress(data);
    default:
      throw new Error(
        `unsupported compression: "${compression}". ` +
        `If this file uses LZ4, re-encrypt with the Go CLI (which normalizes LZ4 to zstd automatically).`,
      );
  }
}
