import type { Block128, Block256 } from "./types";
import { tfmC, tfmF } from "./transforms";
import { INNER_LOOP_ITERATIONS, KEY_SIZE, MASTER_KEY_SIZE, NUM_KEYS, OUTER_LOOP_ITERATIONS } from "./constants";

type HashFunction = (passwordBytes: Uint8Array) => Promise<Block256>;

export class KeyStore {
  public keys: Block128[];
  #masterKey: Block256;
  #hashFunction?: HashFunction;

  constructor() {
    this.#masterKey = new Uint8Array(MASTER_KEY_SIZE);
    this.keys = Array.from(
      { length: NUM_KEYS },
      () => new Uint8Array(KEY_SIZE),
    );
  }

  public setHashFunction(hashFunction: HashFunction): void {
    this.#hashFunction = hashFunction;
  }

  public async setPassword(password: Uint8Array): Promise<void> {
    if (this.#hashFunction) {
      this.#masterKey = await this.#hashFunction(password);
    }
    this.expandKey();
  }

  public setMasterKey(masterKey: Block256): void {
    if (masterKey.length !== MASTER_KEY_SIZE)
      throw new Error("Invalid master key length");
    this.#masterKey = masterKey.slice();
    this.expandKey();
  }

  private expandKey(): void {
    const c = new Uint8Array(KEY_SIZE);
    let constC = this.#masterKey.slice();

    this.keys[0].set(this.#masterKey.subarray(0, KEY_SIZE));
    this.keys[1].set(this.#masterKey.subarray(KEY_SIZE, MASTER_KEY_SIZE));

    let k = 2;
    for (let j = 0; j < OUTER_LOOP_ITERATIONS; j++) {
      for (let i = 1; i <= INNER_LOOP_ITERATIONS; i++) {
        tfmC(c, j * INNER_LOOP_ITERATIONS + i);
        tfmF(constC, c);
      }
      this.keys[k].set(constC.subarray(0, KEY_SIZE));
      k++;
      this.keys[k].set(constC.subarray(KEY_SIZE, MASTER_KEY_SIZE));
      k++;
    }
  }
}
