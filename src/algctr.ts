import type { Block128 } from "./types";
import { KeyStore } from "./keystore";
import { BLOCK_SIZE } from "./constants";
import { encryptBlock, sumMod2 } from "./transforms";

export class AlgCtr {
  private kuz: KeyStore;
  private gamma: Uint8Array;

  constructor(kuz: KeyStore) {
    this.kuz = kuz;
    this.gamma = new Uint8Array(0);
  }

  public setGamma(gamma: Uint8Array): void {
    this.gamma = gamma.slice();
  }

  public encrypt(data: Uint8Array): Uint8Array {
    const encryptedData = data.slice();
    const blockCount = Math.floor(data.length / BLOCK_SIZE);

    for (let i = 0; i < blockCount; i++) {
      const block = this.getEncryptedCounter();
      sumMod2(
        encryptedData.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE),
        block,
      );
      this.incrementCounter();
    }

    const remainder = data.length % BLOCK_SIZE;
    if (remainder > 0) {
      const block = this.getEncryptedCounter();
      sumMod2(
        encryptedData.subarray(blockCount * BLOCK_SIZE),
        block.subarray(0, remainder),
      );
      this.incrementCounter();
    }

    return encryptedData;
  }

  public decrypt(data: Uint8Array): Uint8Array {
    return this.encrypt(data); // CTR mode is symmetric
  }

  private getEncryptedCounter(): Block128 {
    if (this.gamma.length < BLOCK_SIZE) {
      throw new Error(`Gamma must be at least ${BLOCK_SIZE} bytes`);
    }
    const counterBlock = this.gamma.subarray(0, BLOCK_SIZE).slice() as Block128;
    encryptBlock(counterBlock, this.kuz.keys);
    return counterBlock;
  }

  private incrementCounter(): void {
    for (let i = this.gamma.length - 1; i >= 0; i--) {
      this.gamma[i] = (this.gamma[i] + 1) & 0xff;
      if (this.gamma[i] !== 0) {
        break;
      }
    }
  }
}
