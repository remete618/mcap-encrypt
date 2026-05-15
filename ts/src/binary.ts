export class BinaryReader {
  readonly data: Uint8Array;
  private view: DataView;
  offset: number;

  constructor(data: Uint8Array) {
    this.data = data;
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.offset = 0;
  }

  private require(n: number): void {
    if (this.offset + n > this.data.length) {
      throw new Error(
        `unexpected end of data: need ${n} bytes at offset ${this.offset}, have ${this.data.length - this.offset}`,
      );
    }
  }

  readUint8(): number {
    this.require(1);
    return this.view.getUint8(this.offset++);
  }

  readUint16(): number {
    this.require(2);
    const v = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return v;
  }

  readUint32(): number {
    this.require(4);
    const v = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return v;
  }

  readUint64(): bigint {
    this.require(8);
    const v = this.view.getBigUint64(this.offset, true);
    this.offset += 8;
    return v;
  }

  readBytes(n: number): Uint8Array {
    this.require(n);
    const result = this.data.subarray(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }

  readString(): string {
    const len = this.readUint32();
    return new TextDecoder().decode(this.readBytes(len));
  }

  readPrefixedBytes(): Uint8Array {
    const len = this.readUint32();
    return this.readBytes(len);
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }
}

export class BinaryWriter {
  private parts: Uint8Array[] = [];
  private _length = 0;

  writeUint8(v: number): void {
    const b = new Uint8Array(1);
    b[0] = v;
    this.push(b);
  }

  writeUint16(v: number): void {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    this.push(b);
  }

  writeUint32(v: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v, true);
    this.push(b);
  }

  writeUint64(v: bigint): void {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, v, true);
    this.push(b);
  }

  writeBytes(data: Uint8Array): void {
    this.push(data);
  }

  writeString(s: string): void {
    const encoded = new TextEncoder().encode(s);
    this.writeUint32(encoded.length);
    this.push(encoded);
  }

  writePrefixedBytes(data: Uint8Array): void {
    this.writeUint32(data.length);
    this.push(data);
  }

  private push(data: Uint8Array): void {
    this.parts.push(data);
    this._length += data.length;
  }

  get length(): number {
    return this._length;
  }

  toUint8Array(): Uint8Array {
    const out = new Uint8Array(this._length);
    let offset = 0;
    for (const part of this.parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }
}
