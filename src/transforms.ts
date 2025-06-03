import type { Block128, Block256 } from "./types";
import { K_PI, K_PI_REV, MULT_TABLE } from "./tables";

export function encryptBlock(data: Block128, keys: Block128[]): void {
  if (data.length !== 16 || keys.length !== 10)
    throw new Error("Invalid input length");
  for (let i = 0; i < 9; i++) {
    tfmLsx(data, keys[i]);
  }
  tfmX(data, keys[9]);
}

export function decryptBlock(data: Block128, keys: Block128[]): void {
  if (data.length !== 16 || keys.length !== 10)
    throw new Error("Invalid input length");
  for (let i = 9; i > 0; i--) {
    tfmX(data, keys[i]);
    tfmRevL(data);
    tfmRevS(data);
  }
  tfmX(data, keys[0]);
}

export function tfmC(data: Block128, number: number): void {
  if (data.length !== 16) throw new Error("Invalid data length");
  data.fill(0);
  data[15] = number;
  tfmL(data);
}

export function tfmF(data: Block256, key: Block128): void {
  if (data.length !== 32 || key.length !== 16)
    throw new Error("Invalid input length");
  const temp = data.subarray(0, 16).slice();
  tfmLsx(data.subarray(0, 16), key);
  tfmXBlock256(data);
  data.set(temp, 16);
}

export function tfmLsx(data: Block128, key: Block128): void {
  tfmX(data, key);
  tfmS(data);
  tfmL(data);
}

export function tfmX(data: Block128, key: Block128): void {
  for (let i = 0; i < 16; i++) {
    data[i] ^= key[i];
  }
}

export function tfmXBlock256(data: Block256): void {
  for (let i = 0; i < 16; i++) {
    data[i] ^= data[i + 16];
  }
}

export function tfmS(data: Block128): void {
  for (let i = 0; i < 16; i++) {
    data[i] = K_PI[data[i]];
  }
}

export function tfmL(data: Block128): void {
  for (let i = 0; i < 16; i++) {
    tfmR(data);
  }
}

export function tfmR(data: Block128): void {
  const temp = trfLinear(data);
  for (let i = 15; i > 0; i--) {
    data[i] = data[i - 1];
  }
  data[0] = temp;
}

export function trfLinear(data: Block128): number {
  let res = 0;
  res ^= MULT_TABLE[3][data[0]];
  res ^= MULT_TABLE[1][data[1]];
  res ^= MULT_TABLE[2][data[2]];
  res ^= MULT_TABLE[0][data[3]];
  res ^= MULT_TABLE[5][data[4]];
  res ^= MULT_TABLE[4][data[5]];
  res ^= data[6];
  res ^= MULT_TABLE[6][data[7]];
  res ^= data[8];
  res ^= MULT_TABLE[4][data[9]];
  res ^= MULT_TABLE[5][data[10]];
  res ^= MULT_TABLE[0][data[11]];
  res ^= MULT_TABLE[2][data[12]];
  res ^= MULT_TABLE[1][data[13]];
  res ^= MULT_TABLE[3][data[14]];
  res ^= data[15];
  return res;
}

export function tfmRevS(data: Block128): void {
  for (let i = 0; i < 16; i++) {
    data[i] = K_PI_REV[data[i]];
  }
}

export function tfmRevR(data: Block128): void {
  const first = data[0];
  for (let i = 0; i < 15; i++) {
    data[i] = data[i + 1];
  }
  data[15] = trfLinear(data);
  data[0] = first;
}

export function tfmRevL(data: Block128): void {
  for (let i = 0; i < 16; i++) {
    tfmRevR(data);
  }
}

export function sumMod2(b1: Uint8Array, b2: Uint8Array): void {
  if (b1.length > b2.length) throw new Error("b1 length exceeds b2");
  for (let i = 0; i < b1.length; i++) {
    b1[i] ^= b2[i];
  }
}

export function additionBlock128_2(data: Uint8Array): Uint8Array {
  return additionBlockS2(data, 16);
}

export function additionBlockS2(data: Uint8Array, s: number): Uint8Array {
  const len = data.length;
  const r = len % s === 0 ? s : len % s;
  const newData = new Uint8Array(len + r);
  newData.set(data);
  newData[len] = 0x80;
  return newData;
}

export function additionRevBlock2(data: Uint8Array): Uint8Array {
  const pos = data.lastIndexOf(0x80);
  const newLen = pos === -1 ? data.length : pos;
  return data.subarray(0, newLen);
}
