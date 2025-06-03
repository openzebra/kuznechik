import { BLOCK_SIZE } from "./constants";

export function validateIv(
  iv: Uint8Array,
  minLength: number = BLOCK_SIZE,
): void {
  if (iv.length < minLength) {
    throw new Error(
      `Initialization vector length must be at least ${minLength} bytes`,
    );
  }
}

export function updateIv(iv: Uint8Array, data: Uint8Array, s: number = BLOCK_SIZE): void {
  validateIv(iv);
  if (data.length < s) {
    throw new Error(`Data length must be at least ${s} bytes`);
  }
  const shiftLength = iv.length - s;
  for (let i = 0; i < shiftLength; i++) {
    iv[i] = iv[i + s];
  }
  for (let i = 0; i < s; i++) {
    iv[shiftLength + i] = data[i];
  }
}
