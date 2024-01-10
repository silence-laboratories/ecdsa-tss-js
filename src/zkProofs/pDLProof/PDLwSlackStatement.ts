import * as paillier from "paillier-bigint";
import * as secp from "@noble/secp256k1";
import * as utils from "../../utils";

export class PDLwSlackStatement {
	static requiredFields = ["ciphertext", "ek", "Q", "G", "h1", "h2", "N_tilde"];

	ciphertext: bigint;
	ek: paillier.PublicKey;
	Q: secp.Point;
	G: secp.Point;
	h1: bigint;
	h2: bigint;
	nTilde: bigint;

	constructor(
		ciphertext: bigint,
		ek: paillier.PublicKey,
		Q: secp.Point,
		G: secp.Point,
		h1: bigint,
		h2: bigint,
		nTilde: bigint,
	) {
		this.ciphertext = ciphertext;
		this.ek = ek;
		this.Q = Q;
		this.G = G;
		this.h1 = h1;
		this.h2 = h2;
		this.nTilde = nTilde;
	}

	toObj(): IPDLwSlackStatement {
		return {
			ciphertext: utils.bigintTob64(this.ciphertext),
			ek: utils.bigintTob64(this.ek.n),
			Q: utils.pointTob64(this.Q),
			G: utils.pointTob64(this.G),
			h1: utils.bigintTob64(this.h1),
			h2: utils.bigintTob64(this.h2),
			N_tilde: utils.bigintTob64(this.nTilde),
		};
	}

	to_str() {
		return JSON.stringify(this.toObj());
	}

	static fromObj(message: IPDLwSlackStatement) {
		if (!utils.checkOwnKeys(PDLwSlackStatement.requiredFields, message)) {
			throw new Error("PDLwSlackStatement invalid");
		}
		const ciphertext = utils.b64ToBigint(message.ciphertext);
		const n = utils.b64ToBigint(message.ek);
		const ek = new paillier.PublicKey(n, n + BigInt(1));
		const Q = utils.b64ToPoint(message.Q);
		const G = utils.b64ToPoint(message.G);
		const h1 = utils.b64ToBigint(message.h1);
		const h2 = utils.b64ToBigint(message.h2);
		const nTilde = utils.b64ToBigint(message.N_tilde);
		return new PDLwSlackStatement(ciphertext, ek, Q, G, h1, h2, nTilde);
	}

	static fromString(messageString: string) {
		const message = JSON.parse(messageString);
		return PDLwSlackStatement.fromObj(message);
	}
}

export interface IPDLwSlackStatement {
	ciphertext: string;
	ek: string;
	Q: string;
	G: string;
	h1: string;
	h2: string;
	N_tilde: string;
}
