import type { Block128 } from './types';
import { KeyStore } from './keystore';
import { encryptBlock, sumMod2 } from './transforms';

const BLOCK_SIZE = 16;

export class AlgMac {
    private kuz: KeyStore;
    private s: number;
    private k1: Block128;
    private k2: Block128;

    constructor(kuz: KeyStore) {
        this.kuz = kuz;
        this.s = 8;
        this.k1 = new Uint8Array(BLOCK_SIZE);
        this.k2 = new Uint8Array(BLOCK_SIZE);
        this.makeK();
    }

    public encrypt(data: Uint8Array): Uint8Array {
        let mutableData = data.slice();
        const isAdded = additionBlock128_3(mutableData, BLOCK_SIZE);
        const countBlocks = mutableData.length / BLOCK_SIZE;

        let result = mutableData.subarray(0, BLOCK_SIZE).slice() as Block128;
        encryptBlock(result, this.kuz.keys);

        for (let i = 1; i < countBlocks - 1; i++) {
            const block = mutableData.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
            sumMod2(result, block);
            encryptBlock(result, this.kuz.keys);
        }

        const key = isAdded ? this.k2 : this.k1;
        const lastBlock = mutableData.subarray((countBlocks - 1) * BLOCK_SIZE);
        sumMod2(result, lastBlock);
        sumMod2(result, key);
        encryptBlock(result, this.kuz.keys);

        return result.subarray(0, this.s);
    }

    public decrypt(_data: Uint8Array): Uint8Array {
        throw new Error("AlgMac has no decrypt function");
    }

    private makeK(): void {
        this.k1 = new Uint8Array(BLOCK_SIZE);
        encryptBlock(this.k1, this.kuz.keys);
        mkK(this.k1);

        this.k2 = this.k1.slice();
        mkK(this.k2);
    }
}

function mkK(k: Block128): void {
    if (shiftLeft(k) === 1) {
        k[BLOCK_SIZE - 1] ^= 0x87;
    }
}

function shiftLeft(m: Uint8Array): number {
    const len = m.length;
    let h = 0;
    for (let i = len - 1; i >= 0; i--) {
        const temp = (m[i] >> 7) & 1;
        m[i] = (m[i] << 1) | h;
        h = temp;
    }
    return h;
}

function additionBlock128_3(data: Uint8Array, s: number): boolean {
    const r = data.length % s;
    if (r > 0) {
        const exData = new Uint8Array(s - r);
        exData[0] = 0x80;
        for (let i = 1; i < s - r; i++) {
            exData[i] = 0x00;
        }
        const newData = new Uint8Array(data.length + (s - r));
        newData.set(data);
        newData.set(exData, data.length);
        data = newData;
        return true;
    }
    return false;
}
