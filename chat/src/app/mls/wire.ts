export class Buf {
  private b: Uint8Array;
  private o = 0;

  constructor(v?: Uint8Array) {
    this.b = v ?? new Uint8Array(0);
  }

  get left(): number {
    return this.b.length - this.o;
  }

  get done(): boolean {
    return this.o >= this.b.length;
  }

  take(n: number): Uint8Array {
    if (n > this.left) throw new Error("short");
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }

  u8(): number {
    return this.take(1)[0];
  }

  u16(): number {
    const v = this.take(2);
    return (v[0] << 8) | v[1];
  }

  u32(): number {
    const v = this.take(4);
    return ((v[0] << 24) >>> 0) + (v[1] << 16) + (v[2] << 8) + v[3];
  }

  u64(): number {
    const hi = this.u32();
    const lo = this.u32();
    return hi * 4294967296 + lo;
  }

  vlen(): number {
    const first = this.u8();
    const prefix = first >> 6;
    if (prefix === 3) throw new Error("bad vector length");
    const width = 1 << prefix;
    let v = first & 63;
    for (let i = 1; i < width; i++) v = v * 256 + this.u8();
    return v;
  }

  slice(start: number, end: number): Uint8Array {
    return this.b.subarray(start, end);
  }

  reset(pos: number): void {
    this.o = pos;
  }

  get pos(): number {
    return this.o;
  }

  vec(): Uint8Array {
    return this.take(this.vlen());
  }

  rest(): Uint8Array {
    return this.take(this.left);
  }

  since(start: number): Uint8Array {
    return this.take(this.o - start);
  }

  none(): boolean {
    return this.u8() === 0;
  }
}

export class Writer {
  private parts: Uint8Array[] = [];

  u8(v: number): this {
    this.parts.push(new Uint8Array([v & 255]));
    return this;
  }

  u16(v: number): this {
    this.parts.push(new Uint8Array([(v >> 8) & 255, v & 255]));
    return this;
  }

  u32(v: number): this {
    const n = v >>> 0;
    this.parts.push(new Uint8Array([(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]));
    return this;
  }

  u64(v: number): this {
    this.u32(Math.floor(v / 4294967296));
    this.u32(v >>> 0);
    return this;
  }

  vlen(n: number): this {
    if (n < 64) this.parts.push(new Uint8Array([n]));
    else if (n < 16384) this.parts.push(new Uint8Array([0x40 | ((n >> 8) & 63), n & 255]));
    else if (n < 1073741824) {
      this.parts.push(new Uint8Array([0x80 | ((n >>> 24) & 63), (n >>> 16) & 255, (n >>> 8) & 255, n & 255]));
    } else {
      throw new Error("vector too long");
    }
    return this;
  }

  vec(v: Uint8Array): this {
    this.vlen(v.length);
    this.parts.push(v);
    return this;
  }

  raw(v: Uint8Array): this {
    this.parts.push(v);
    return this;
  }

  none(present: boolean): this {
    return this.u8(present ? 1 : 0);
  }

  out(): Uint8Array {
    let n = 0;
    for (const p of this.parts) n += p.length;
    const v = new Uint8Array(n);
    let o = 0;
    for (const p of this.parts) {
      v.set(p, o);
      o += p.length;
    }
    return v;
  }
}