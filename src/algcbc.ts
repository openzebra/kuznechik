import type { Block128 } from "./types";
import { KeyStore } from "./keystore";
import {
  encryptBlock,
  decryptBlock,
  sumMod2,
  additionBlock128_2,
  additionRevBlock2,
} from "./transforms";
import { BLOCK_SIZE } from "./constants";
import { updateIv, validateIv } from "./utils";

export class AlgCbc {
  private keyStore: KeyStore;
  private iv: Uint8Array;

  constructor(keyStore: KeyStore) {
    this.keyStore = keyStore;
    this.iv = new Uint8Array(0);
  }

  public setIv(iv: Uint8Array): void {
    if (iv.length < BLOCK_SIZE) {
      throw new Error(
        `Initialization vector length must be at least ${BLOCK_SIZE} bytes`,
      );
    }
    this.iv = iv.slice();
  }

  public encrypt(data: Uint8Array): Uint8Array {
    this.validateIv();
    const paddedData = additionBlock128_2(data);
    const blockCount = paddedData.length / BLOCK_SIZE;

    for (let i = 0; i < blockCount; i++) {
      const block = paddedData.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
      sumMod2(block, this.iv.subarray(0, BLOCK_SIZE));
      encryptBlock(block, this.keyStore.keys);
      this.updateIv(block);
    }

    return paddedData;
  }

  public decrypt(data: Uint8Array): Uint8Array {
    this.validateIv();
    const blockCount = data.length / BLOCK_SIZE;
    const decryptedData = data.slice();

    for (let i = 0; i < blockCount; i++) {
      const block = decryptedData.subarray(
        i * BLOCK_SIZE,
        (i + 1) * BLOCK_SIZE,
      );
      const encryptedBlock = block.slice();
      decryptBlock(block, this.keyStore.keys);
      sumMod2(block, this.iv.subarray(0, BLOCK_SIZE));
      this.updateIv(encryptedBlock);
    }

    return additionRevBlock2(decryptedData);
  }

  private updateIv(block: Block128): void {
    updateIv(this.iv, block, BLOCK_SIZE);
  }

  private validateIv(): void {
    validateIv(this.iv, BLOCK_SIZE);
  }
}
