import type { Block128 } from "./types";
import { KeyStore } from "./keystore";
import {
  encryptBlock,
  decryptBlock,
  additionBlock128_2,
  additionRevBlock2,
} from "./transforms";

export class AlgEcb {
  private kuz: KeyStore;

  constructor(kuz: KeyStore) {
    this.kuz = kuz;
  }

  public encrypt(data: Uint8Array): Uint8Array {
    let paddedData = additionBlock128_2(data);
    const blockSize = 16;
    const countBlocks = paddedData.length / blockSize;

    for (let i = 0; i < countBlocks; i++) {
      const block = paddedData.subarray(
        i * blockSize,
        (i + 1) * blockSize,
      ) as Block128;
      encryptBlock(block, this.kuz.keys);
    }
    return paddedData;
  }

  public decrypt(data: Uint8Array): Uint8Array {
    const blockSize = 16;
    const countBlocks = data.length / blockSize;
    let decryptedData = data.slice();

    for (let i = 0; i < countBlocks; i++) {
      const block = decryptedData.subarray(
        i * blockSize,
        (i + 1) * blockSize,
      ) as Block128;
      decryptBlock(block, this.kuz.keys);
    }

    return additionRevBlock2(decryptedData);
  }
}
