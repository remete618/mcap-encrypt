const TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c;
  }
  return t;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const b of data) crc = (crc >>> 8) ^ TABLE[(crc ^ b) & 0xff]!;
  return (crc ^ 0xffffffff) >>> 0;
}
