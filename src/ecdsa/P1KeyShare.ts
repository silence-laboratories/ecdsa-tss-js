import * as secp from "@noble/secp256k1";
import * as paillier from "paillier-bigint";
import * as utils from "../utils";
import {
	bigintToHex,
	hexToBigint,
	hexToPoint,
	paillierPrivateKeyFromObj,
	paillierPrivateKeyToObj,
	paillierPublickeyFromStr,
	paillierPublickeyToStr,
	pointToHex,
} from "../utils";

export interface IPaillierPrivateKey {
	p: string;
	q: string;
}

export interface IP1KeyShare {
	x1: string;
	public_key: string;
	paillier_private_key: IPaillierPrivateKey;
	paillier_public_key: string;
}

export class P1KeyShare {
	static requiredFields = [
		"x1",
		"public_key",
		"paillier_private_key",
		"paillier_public_key",
	];

	x1: bigint;
	publicKey: secp.Point;
	paillierPrivateKey: paillier.PrivateKey;
	paillierPublicKey: paillier.PublicKey;

	constructor(
		x1: bigint,
		publicKey: secp.Point,
		paillierPrivateKey: paillier.PrivateKey,
		paillierPublicKey: paillier.PublicKey,
	) {
		this.x1 = x1;
		this.publicKey = publicKey;
		this.paillierPrivateKey = paillierPrivateKey;
		this.paillierPublicKey = paillierPublicKey;
	}

	toObj(): IP1KeyShare {
		return {
			x1: bigintToHex(this.x1),
			public_key: pointToHex(this.publicKey),
			paillier_private_key: paillierPrivateKeyToObj(this.paillierPrivateKey),
			paillier_public_key: paillierPublickeyToStr(this.paillierPublicKey),
		};
	}

	toStr() {
		return JSON.stringify(this.toObj());
	}

	static fromObj(obj: IP1KeyShare) {
		if (!utils.checkOwnKeys(P1KeyShare.requiredFields, obj)) {
			throw new Error("Object invalid");
		}
		const x1 = hexToBigint(obj.x1);
		const publicKey = hexToPoint(obj.public_key);
		const paillierPrivateKey = paillierPrivateKeyFromObj(
			obj.paillier_private_key,
		);
		const paillierPublicKey = paillierPublickeyFromStr(obj.paillier_public_key);
		return new P1KeyShare(x1, publicKey, paillierPrivateKey, paillierPublicKey);
	}

	static fromStr(objString: string) {
		const obj = JSON.parse(objString);
		return P1KeyShare.fromObj(obj);
	}
}
