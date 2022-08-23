import {KeyGenMessage1} from "./KeyGenMessage1";
import {KeyGenMessage2} from "./KeyGenMessage2";
import {KeyGenMessage3} from "./KeyGenMessage3";
import {verifyCommitment} from "../../zkProofs/hashCommitment"
import PDLProof from "../../zkProofs/pDLProof/PDLProof";
import DLogProof from "../../zkProofs/DLogProof";
import * as utils from "../../utils";
import * as secp from "@noble/secp256k1";
import {IP2KeyShare, P2KeyShare} from "../P2KeyShare";
import {KeyGenFailed} from "./KeyGenFailed";
import { PARTY_ID_1, PARTY_ID_2 } from "../common";


export interface IP2KeyGenResult {
	msg_to_send: string | null,
	p2_key_share: IP2KeyShare | null
}

enum P2KeyGenState {
    COMPLETE = 0,
    FAILED = -1,
    PROCESS_KEY_GEN_MSG_1 = 1,
    PROCESS_KEY_GEN_MSG_3 = 2
}

export class P2KeyGen {
	static G = secp.Point.BASE;
	static q = secp.CURVE.n;

    sessionId: string;
	x2: bigint;
	eph2: bigint | any;
	commitment1: string | any;
	commitment2: string | any;
	expectedPublicKey?: string;
    _state: P2KeyGenState;

    constructor(sessionId: string, x2?: Uint8Array, expectedPublicKey?: string) {
        this.sessionId = sessionId;
		this.expectedPublicKey = expectedPublicKey;
		if (x2) {
			if (x2.length !== 32) {
				throw new KeyGenFailed('Invalid length of x1');
			}
			this.x2 = utils.modPositive(utils.Uint8ArraytoBigint(x2), P2KeyGen.q);
		}
		else {
			this.x2 = utils.randomCurveScalar();
		}
		this._state = P2KeyGenState.PROCESS_KEY_GEN_MSG_1;
    }

	static getInstanceForKeyRefresh(sessionId: string, p2KeyShareObj: IP2KeyShare) {
		const p2KeyShare = P2KeyShare.fromObj(p2KeyShareObj);
		const expectedPublicKey = utils.pointToHex(p2KeyShare.publicKey);
		const x2Uint8Array = utils.bigintToUint8Array(p2KeyShare.x2);
		return new P2KeyGen(sessionId, x2Uint8Array, expectedPublicKey);
	}

    isActive(): boolean {
		const cond1 = this._state !== P2KeyGenState.FAILED;
		const cond2 = this._state !== P2KeyGenState.COMPLETE;
        return cond1 && cond2;
    }

	async _processKeyGenMessage1(keyGenMessage1: KeyGenMessage1): Promise<KeyGenMessage2> {
		if (this._state !== P2KeyGenState.PROCESS_KEY_GEN_MSG_1) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid state');
		}
		if (this.sessionId !== keyGenMessage1.sessionId) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid sessionId');
		}
		this.commitment1 = keyGenMessage1.commitment1;
		this.commitment2 = keyGenMessage1.commitment2;
		const q2 = P2KeyGen.G.multiply(this.x2);
		const dLogProof1 = await DLogProof.prove(this.x2, q2, this.sessionId, PARTY_ID_2);

		this.eph2 = utils.randomCurveScalar();
		const e2 = P2KeyGen.G.multiply(this.eph2);
		const dLogProof2 = await DLogProof.prove(this.eph2, e2, this.sessionId, PARTY_ID_2);

		const keyGenMessage2 = new KeyGenMessage2(
			this.sessionId,
			q2,
			dLogProof1,
			e2,
			dLogProof2
		);
		this._state = P2KeyGenState.PROCESS_KEY_GEN_MSG_3;
		return keyGenMessage2;
	}

	async _processKeyGenMessage3(keyGenMessage3: KeyGenMessage3): Promise<P2KeyShare> {
		if (this._state !== P2KeyGenState.PROCESS_KEY_GEN_MSG_3) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid state');
		}
		if (this.sessionId !== keyGenMessage3.sessionId) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid sessionId');
		}
		const q1 = keyGenMessage3.q1;
		const dLogProof1 = keyGenMessage3.dLogProof1;
		const cond1 = await dLogProof1.verify(q1, this.sessionId, PARTY_ID_1);
		if (!cond1) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid dLogProof1');
		}
		const blindFactor1 = keyGenMessage3.blindFactor1;
		const cond2 = await verifyCommitment(
			this.commitment1, q1, dLogProof1, blindFactor1, this.sessionId, PARTY_ID_1
		);
		if (!cond2) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid Commitment1');
		}

		const publicKey = q1.multiply(this.x2);
		if (this.expectedPublicKey !== undefined) {
			if (this.expectedPublicKey !== utils.pointToHex(publicKey)) {
				this._state = P2KeyGenState.FAILED;
				throw new KeyGenFailed('Invalid publicKey');
			}
		}

		const e1 = keyGenMessage3.e1;
		const dLogProof2 = keyGenMessage3.dLogProof2;
		const cond3 = await dLogProof2.verify(e1, this.sessionId, PARTY_ID_1);
		if (!cond3) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid dLogProof2');
		}
		const blindFactor2 = keyGenMessage3.blindFactor2;
		const cond4 = await verifyCommitment(
			this.commitment2, e1, dLogProof2, blindFactor2, this.sessionId, PARTY_ID_1
		);
		if (!cond4) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid Commitment2');
		}
		// rotate private share x2 using rotateValue2
		const ephPoint = e1.multiply(this.eph2);
		const rotateValue1 = ephPoint.x;
		const rotateValue2 = utils.bigintModInv(rotateValue1, P2KeyGen.q);
		// rotate q1 using rotateValue1 to calculate PDLProof correctly, since x1 has been rotated
		const q1Rotated = q1.multiply(rotateValue1);
		this.x2 = utils.modPositive(this.x2 * rotateValue2, P2KeyGen.q);

		const paillierPublicKey = keyGenMessage3.paillierPublicKey;
		const cond5 = paillierPublicKey.bitLength === 2048;
		if (!cond5) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('PaillierPublicKey.bitLength !== 2048');
		}
		const nIKeyCorrectProof = keyGenMessage3.nIKeyCorrectProof;
		const cond6 = await nIKeyCorrectProof.verify(paillierPublicKey, this.sessionId, PARTY_ID_1);
		if (!cond6) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid nIKeyCorrectProof');
		}
		const cKeyX1 = keyGenMessage3.cKey;
		const pDSwSlackStatement = keyGenMessage3.pDSwSlackStatement;
		const pDLwSlackProof = keyGenMessage3.pDLwSlackProof;
		const compositeDLogProof = keyGenMessage3.compositeDLogProof;
		const cond7 = await PDLProof.verify(
			compositeDLogProof,
			pDSwSlackStatement,
			pDLwSlackProof,
			paillierPublicKey,
			cKeyX1,
			q1Rotated,
			this.sessionId,
			PARTY_ID_1
		)
		if (!cond7) {
			this._state = P2KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid PDLProof');
		}
		const p2KeyShare = new P2KeyShare(this.x2, publicKey, cKeyX1, paillierPublicKey);
		this._state = P2KeyGenState.COMPLETE;
		return p2KeyShare;
	}

	async processMessage(messageString: string): Promise<IP2KeyGenResult> {
		if (!this.isActive()) {
			throw new KeyGenFailed('KeyGen was already Completed or Failed');
		}

        const messageObj = JSON.parse(messageString);
        const messageSessionId = messageObj.session_id;
        if (this.sessionId !== messageSessionId)
            throw new Error('Invalid sessionId');

		try {
			if (this._state === P2KeyGenState.PROCESS_KEY_GEN_MSG_1) {
				const keyGenMessage1 = KeyGenMessage1.fromStr(messageString);
				const keyGenMessage2 = await this._processKeyGenMessage1(keyGenMessage1);
				return {
					msg_to_send: keyGenMessage2.toStr(),
					p2_key_share: null
				}
			}
			if (this._state === P2KeyGenState.PROCESS_KEY_GEN_MSG_3) {
				const keyGenMessage3 = KeyGenMessage3.fromStr(messageString);
				const p2KeyShare = await this._processKeyGenMessage3(keyGenMessage3);
				return {
					msg_to_send: null,
					p2_key_share: p2KeyShare.toObj()
				}
			}
		}
		catch (e) {
			this._state = P2KeyGenState.FAILED;
			throw e;
		}

		this._state = P2KeyGenState.FAILED;
		throw new KeyGenFailed('');
	}

}
