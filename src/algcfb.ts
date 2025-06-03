import type { Block128 } from './types';
import { KeyStore } from './keystore';
import { encryptBlock, sumMod2, additionBlockS2, additionRevBlock2 } from './transforms';

const BLOCK_SIZE = 16;
const DEFAULT_S = 16;

export class AlgCfb {
  private keyStore: KeyStore;
  private iv: Uint8Array;
  private s: number;

  constructor(keyStore: KeyStore) {
    this.keyStore = keyStore;
    this.iv = new Uint8Array(0);
    this.s = DEFAULT_S;
  }

  public setIv(iv: Uint8Array): void {
    if (iv.length < BLOCK_SIZE) {
      throw new Error(`Initialization vector length must be at least ${BLOCK_SIZE} bytes`);
    }
    this.iv = iv.slice();
  }

  public setS(s: number): void {
    if (s <= 0 || s > BLOCK_SIZE) {
      throw new Error(`Parameter s must be between 1 and ${BLOCK_SIZE}`);
    }
    this.s = s;
  }

  public encrypt(data: Uint8Array): Uint8Array {
    this.validateIv();
    const paddedData = additionBlockS2(data, this.s);
    const blockCount = paddedData.length / this.s;

    for (let i = 0; i < blockCount; i++) {
      const block = paddedData.subarray(i * this.s, (i + 1) * this.s);
      const encryptedIv = this.getEncryptedIv();
      sumMod2(block, encryptedIv.subarray(0, this.s));
      this.updateIv(block);
    }

    return paddedData;
  }

  public decrypt(data: Uint8Array): Uint8Array {
    this.validateIv();
    const blockCount = data.length / this.s;
    const decryptedData = data.slice();

    for (let i = 0; i < blockCount; i++) {
      const block = decryptedData.subarray(i * this.s, (i + 1) * this.s);
      const encryptedIv = this.getEncryptedIv();
      this.updateIv(block);
      sumMod2(block, encryptedIv.subarray(0, this.s));
    }

    return additionRevBlock2(decryptedData);
  }

  private getEncryptedIv(): Block128 {
    const ivBlock = this.iv.subarray(0, BLOCK_SIZE);
    const encryptedIv = ivBlock.slice();
    encryptBlock(encryptedIv, this.keyStore.keys);
    return encryptedIv;
  }

  private updateIv(data: Uint8Array): void {
    const ivLength = this.iv.length;
    if (ivLength < BLOCK_SIZE) {
      throw new Error(`Initialization vector length must be at least ${BLOCK_SIZE} bytes`);
    }
    if (data.length < this.s) {
      throw new Error(`Data length must be at least s bytes: ${this.s}`);
    }

    const shiftLength = ivLength - this.s;
    for (let i = 0; i < shiftLength; i++) {
      this.iv[i] = this.iv[i + this.s];
    }
    for (let i = 0; i < this.s; i++) {
      this.iv[shiftLength + i] = data[i];
    }
  }

  private validateIv(): void {
    if (this.iv.length < BLOCK_SIZE) {
      throw new Error(`Initialization vector not set or length less than ${BLOCK_SIZE} bytes`);
    }
  }
}
