const crypto = require('crypto');

function to32(val) { return val | 0; }
function u32(val) { return val >>> 0; }
function ushr(val, n) { return u32(val) >>> n; }

class VMState {
  constructor() {
    this.getters = {};
    this.keyArr = [];
    this.seed = 0;
    this.pos = null;
    this.bytecode = [];
    this.bcLength = 0;
    this.loop = 0;
    this.decompiled = '';
    this.bytePos = 0;
    this.maxIter = 8001;
    this.strArr = [];
    for (let i = 0; i < 287; i++) this.strArr.push(String.fromCharCode(i));
    this.ops = {};
  }

  addGetter(value, N, T) {
    if (T === 87 || T === 160 || T === 21) {
      const container = { v: value };
      return { create: () => container.v, concat: (K) => { container.v = K; } };
    } else {
      return { create: (X) => null, concat: () => value };
    }
  }

  setKey(idx, val) {
    if (idx === 87 || idx === 160 || idx === 21) {
      if (this.getters[idx]) {
        const g = this.getters[idx];
        if (g.concat) g.concat(val);
      } else {
        this.getters[idx] = this.addGetter(val, 0, idx);
      }
    } else {
      this.getters[idx] = this.addGetter(val, 49, idx);
    }
    if (idx === 21) {
      const [seedVal] = this.read(false, 32);
      this.seed = seedVal;
      this.pos = null;
    }
  }

  getKey(idx) {
    const L = this.getters[idx];
    if (L === undefined) return [null, [{}, 30, idx]];
    if (idx === 87 || idx === 160 || idx === 21) return [L.create(), null];
    L.create(idx * 4 * idx + idx * -57 + -22);
    return [L.concat(), null];
  }

  encr(keys, pos, seed) {
    let key = to32(keys[3]);
    let keys2 = to32(keys[2]);
    for (let idx = 0; idx < 14; idx++) {
      pos = to32(ushr(pos, 8) | u32(pos) << 24);
      pos = to32(pos + seed);
      key = to32(ushr(key, 8) | u32(key) << 24);
      key = to32(key + keys2);
      key ^= to32(idx + 930);
      pos ^= to32(keys2 + 930);
      keys2 = to32(u32(keys2) << 3 | ushr(keys2, 29));
      keys2 ^= key;
      seed = to32(u32(seed) << 3 | ushr(seed, 29));
      seed ^= pos;
    }
    return [
      (seed >> 24) & 255, (seed >> 16) & 255, (seed >> 8) & 255, seed & 255,
      (pos >> 24) & 255, (pos >> 16) & 255, (pos >> 8) & 255, pos & 255,
    ];
  }

  read(enc, bits) {
    const [bbpos, err] = this.getKey(87);
    if (err) return [0, err];
    let bpos = bbpos;
    if (bpos >= this.bcLength) return [0, [{}, 31]];
    let X = to32(bpos);
    let P = to32(bits);
    let K = 0;
    const origBpos = bpos;
    while (P > 0) {
      const c = X % 8;
      const uArr = X >> 3;
      if (uArr >= this.bytecode.length) {
        this.setKey(87, to32(origBpos + bits));
        return [0, [{}, 31]];
      }
      let bg = 8 - c;
      let p = this.bytecode[uArr];
      if (bg >= P) bg = P;
      if (enc) {
        const E = X;
        if (this.pos !== (E >> 6)) {
          this.pos = E >> 6;
          const [eVal, err2] = this.getKey(21);
          if (err2) {
            this.setKey(87, to32(origBpos + bits));
            return [0, err2];
          }
          this.keyArr = this.encr([0, 0, eVal[1], eVal[2]], this.pos, this.seed);
        }
        if (this.keyArr.length) p ^= this.keyArr[uArr & 7];
      }
      K |= ((p >> (8 - c - bg)) & ((1 << bg) - 1)) << (P - bg);
      P -= bg;
      X += bg;
    }
    this.setKey(87, to32(origBpos + bits));
    return [to32(K), null];
  }

  getByte() {
    const [b0, err] = this.read(true, 8);
    if (err) return [0, err];
    let b = to32(b0);
    if (b & 128) {
      b ^= 128;
      const [idx, err2] = this.read(true, 2);
      if (err2) return [0, err2];
      b = to32(b << 2) + to32(idx);
    }
    return [b, null];
  }

  getByte2() {
    const [b0, err] = this.read(true, 8);
    if (err) return [0, err];
    let b = b0;
    if (b & 128) {
      const [idx, err2] = this.read(true, 8);
      if (err2) return [0, err2];
      b = to32((b & 127) | (idx << 7));
    }
    return [to32(b), null];
  }

  initKey(idx, val) { this.setKey(idx, val); }

  getBytecode(enc) {
    const b64 = enc.substring(3);
    const buf = Buffer.from(b64, 'base64');
    return Array.from(buf);
  }

  setup() {
    const s = this;
    s.initKey(87, 0);
    s.initKey(57, 144);
    s.initKey(443, 0);
    s.initKey(195, []);
    s.initKey(7, 'rnd(4)');
    s.initKey(75, 0);
    s.initKey(338, {});
    s.initKey(364, []);
    s.initKey(15, 'window');
    s.initKey(6, 32);
    s.initKey(192, 'rnd(4)');
    s.initKey(136, []);
    s.initKey(444, [160, 0, 0]);
    s.initKey(21, [0, 0, 0]);
    s.initKey(477, [2048]);
    s.initKey(160, 0);
    s.initKey(360, []);
    s.initKey(239, []);
    s.initKey(122, 'rnd(4)');
    s.initKey(460, [0, 0, 0]);
  }

  decompile(enc) {
    this.bytecode = this.getBytecode(enc);
    this.bcLength = to32(this.bytecode.length) << 3;
    this.setup();
    while (this.maxIter > 0) {
      this.maxIter -= 1;
      const [bp, err] = this.getKey(87);
      if (err) continue;
      this.bytePos = bp;
      if (this.bytePos >= this.bcLength) break;
      this.setKey(160, this.bytePos);
      const [opcode, err2] = this.getByte();
      if (err2) continue;
      if (this.ops[opcode]) continue;
    }
    return this.decompiled;
  }
}

function parse(decompiled) {
  let key = 0;
  const arr = [];
  let loop = 0;
  const lines = decompiled.split('\n');
  for (const line of lines) {
    if (line.includes(' = ')) {
      const parts = line.split(' = ');
      if (parts.length === 2 && parts[1].trim().length === 3) {
        const val = parseInt(parts[1].trim(), 10);
        if (!isNaN(val)) key = val;
      }
    }
    if (line.includes('.push(') && line.includes(',')) {
      const start = line.indexOf('(') + 1;
      const end = line.indexOf(')');
      if (start > 0 && end > start) {
        const s = line.substring(start, end);
        for (const part of s.split(',')) {
          const val = parseInt(part.trim(), 10);
          if (!isNaN(val)) arr.push(val);
        }
      }
    }
  }
  return { key, arr: Buffer.from(arr), loop };
}

function rnd(n) { return Array.from(crypto.randomBytes(n)); }
function toArr(v1, v2) {
  const arr = new Array(v2).fill(0);
  for (let i = v2 - 1; i >= 0; i--) arr[v2 - 1 - i] = (u32(v1) >> (i * 8)) & 255;
  return arr;
}

let r460 = [0, 0, 0];

function b64urlEncode(payload) {
  let result = Buffer.from(payload).toString('base64');
  result = result.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return result;
}

function sign(parsed) {
  r460 = [0, 0, 0];
  const r192 = { slice: rnd(4) };
  const r477 = [2048];
  const r360arr = [];
  const r122 = { slice: rnd(4) };
  const r444arr = [160, 0, 0];
  const r443 = parsed.key;
  const r239 = [...parsed.arr];
  for (let i = 0; i < parsed.loop; i++) r360arr.push(95);
  r477[0] -= 114;
  const uArr = toArr(r444arr.length + 2, 2);
  const result = [...rnd(2), ...r444arr];
  result[1] = result[0] ^ 6;
  result[3] = result[1] ^ uArr[0];
  result[4] = result[1] ^ uArr[1];
  return '!' + b64urlEncode(result);
}

function generateBG(bytecodeStr) {
  const vm = new VMState();
  const decompiled = vm.decompile(bytecodeStr);
  const parsed = parse(decompiled);
  return sign(parsed);
}

module.exports = { generateBG };