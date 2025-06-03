import type { Block128 } from "./types";
import { KeyStore } from "./keystore";
import { encryptBlock, sumMod2 } from "./transforms";
import { BLOCK_SIZE, MIN_GAMMA_SIZE } from "./constants";

export class AlgOfb {
  private kuz: KeyStore;
  private gamma: Uint8Array;

  constructor(kuz: KeyStore) {
    this.kuz = kuz;
    this.gamma = new Uint8Array(0);
  }

  public setGamma(gamma: Uint8Array): void {
    if (gamma.length < MIN_GAMMA_SIZE) {
      throw new Error(`Gamma must be at least ${MIN_GAMMA_SIZE} bytes`);
    }
    this.gamma = gamma.slice();
  }

  public encrypt(data: Uint8Array): Uint8Array {
    const encryptedData = data.slice();
    const blockCount = Math.floor(data.length / BLOCK_SIZE);

    for (let i = 0; i < blockCount; i++) {
      const block = this.getEncryptedGamma();
      sumMod2(
        encryptedData.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE),
        block,
      );
      this.updateGamma();
    }

    const remainder = data.length % BLOCK_SIZE;
    if (remainder > 0) {
      const block = this.getEncryptedGamma();
      sumMod2(
        encryptedData.subarray(blockCount * BLOCK_SIZE),
        block.subarray(0, remainder),
      );
      this.updateGamma();
    }

    return encryptedData;
  }

  public decrypt(data: Uint8Array): Uint8Array {
    return this.encrypt(data); // OFB mode is symmetric
  }

  private getEncryptedGamma(): Block128 {
    if (this.gamma.length < BLOCK_SIZE) {
      throw new Error(`Gamma must be at least ${BLOCK_SIZE} bytes`);
    }
    const gammaBlock = this.gamma.subarray(0, BLOCK_SIZE); // Убрали .slice()
    encryptBlock(gammaBlock, this.kuz.keys);
    return gammaBlock;
  }

  private updateGamma(): void {
    const len = this.gamma.length;
    if (len < MIN_GAMMA_SIZE) {
      throw new Error(`Gamma length must be at least ${MIN_GAMMA_SIZE} bytes`);
    }

    const temp = this.gamma.subarray(0, BLOCK_SIZE).slice();
    for (let i = BLOCK_SIZE; i < len; i++) {
      const swap = this.gamma[i];
      this.gamma[i] = this.gamma[i - BLOCK_SIZE];
      this.gamma[i - BLOCK_SIZE] = swap;
    }
    this.gamma.set(temp, len - BLOCK_SIZE);
  }
}
