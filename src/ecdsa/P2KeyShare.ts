import * as secp from "@noble/secp256k1";
import * as paillier from 'paillier-bigint';
import * as utils from "../utils";
import {
    b64ToBigint,
    bigintTob64,
    bigintToHex,
    hexToBigint,
    hexToPoint, paillierPublickeyFromStr,
    paillierPublickeyToStr,
    pointToHex
} from "../utils";


export interface IP2KeyShare {
    x2: string;
    public_key: string;
    c_key_x1: string;
    paillier_public_key: string;
}

export class P2KeyShare {
    static requiredFields = ['x2', 'public_key', 'c_key_x1', 'paillier_public_key'];

    x2: bigint;
    publicKey: secp.Point;
    cKeyX1: bigint;
    paillierPublicKey: paillier.PublicKey;

    constructor(
        x2: bigint,
        publicKey: secp.Point,
        cKeyX1: bigint,
        paillierPublicKey: paillier.PublicKey,
    ) {
        this.x2 = x2;
        this.publicKey = publicKey;
        this.cKeyX1 = cKeyX1;
        this.paillierPublicKey = paillierPublicKey;
    }

    toObj(): IP2KeyShare {
        return {
            x2: bigintToHex(this.x2),
            public_key: pointToHex(this.publicKey),
            c_key_x1: bigintTob64(this.cKeyX1),
            paillier_public_key: paillierPublickeyToStr(this.paillierPublicKey)
        };
    }

    toStr() {
        return JSON.stringify(this.toObj());
    }

    static fromObj(obj: IP2KeyShare) {
        if (!utils.checkOwnKeys(P2KeyShare.requiredFields, obj)) {
            throw new Error('Object invalid');
        }
        const x2 = hexToBigint(obj.x2);
        const publicKey = hexToPoint(obj.public_key);
        const cKeyX1 = b64ToBigint(obj.c_key_x1);
        const paillierPublicKey = paillierPublickeyFromStr(obj.paillier_public_key);
        return new P2KeyShare(x2, publicKey, cKeyX1, paillierPublicKey);
    }

    static fromStr(objString: string) {
        const obj = JSON.parse(objString);
        return P2KeyShare.fromObj(obj);
    }
}
