import * as secp from "@noble/secp256k1";
import * as utils from "../../utils";
import DLogProof from "../../zkProofs/DLogProof";
import {verifyCommitment} from "../../zkProofs/hashCommitment"
import {IP2KeyShare, P2KeyShare} from "../P2KeyShare";
import {SignMessage1} from "./SignMessage1";
import {SignMessage2} from "./SignMessage2";
import {SignMessage3} from "./SignMessage3";
import {SignMessage4} from "./SignMessage4";
import {SignMessage5} from "./SignMessage5";
import {SignatureFailed} from "./SignatureFailed";
import { PARTY_ID_1, PARTY_ID_2 } from "../common";


const G = secp.Point.BASE;
const q = secp.CURVE.n;

export interface IP2SignatureResult {
	msg_to_send: string | null,
	signature: string | null
}

enum Party2SignatureState {
    COMPLETE = 0,
    FAILED = -1,
    PROCESS_SIGN_MSG_1 = 1,
    PROCESS_SIGN_MSG_3 = 2,
    PROCESS_SIGN_MSG_5 = 3,
}

export class P2Signature {
    sessionId: string;
	messageHash: Uint8Array;
	p2KeyShare: P2KeyShare;
    k2: bigint | any;
	commitment: string = "";
    _state: Party2SignatureState;

    constructor(
		sessionId: string,
		messageHash: Uint8Array,
		p2KeyShareObj: IP2KeyShare,
    ) {
        this.sessionId = sessionId;
        this.messageHash = messageHash;
        this.p2KeyShare = P2KeyShare.fromObj(p2KeyShareObj);
        this._state = Party2SignatureState.PROCESS_SIGN_MSG_1;
    }

	isActive(): boolean {
		const cond1 = this._state !== Party2SignatureState.FAILED;
		const cond2 = this._state !== Party2SignatureState.COMPLETE;
		return cond1 && cond2;
	}

	async _processSignMessage1(signMessage1: SignMessage1): Promise<SignMessage2> {
		if (this._state !== Party2SignatureState.PROCESS_SIGN_MSG_1) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid state');
		}
		if (this.sessionId !== signMessage1.sessionId) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid sessionId');
		}
		this.commitment = signMessage1.commitment;
		this.k2 = utils.randomCurveScalar();
		const r2 = G.multiply(this.k2);
		const dLogProof = await DLogProof.prove(this.k2, r2, this.sessionId, PARTY_ID_2);
		const signMessage2 = new SignMessage2(this.sessionId, r2, dLogProof)
		this._state = Party2SignatureState.PROCESS_SIGN_MSG_3;
		return signMessage2;
	}

	async _processSignMessage3(signMessage3: SignMessage3): Promise<SignMessage4> {
		if (this._state !== Party2SignatureState.PROCESS_SIGN_MSG_3) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid state');
		}
		if (this.sessionId !== signMessage3.sessionId) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid sessionId');
		}
		const r1 = signMessage3.r1;
		const dLogProof = signMessage3.dLogProof;
		const con1 = await dLogProof.verify(r1, this.sessionId, PARTY_ID_1);
		if (!con1) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid dLogProof');
		}
		const blindFactor = signMessage3.blindFactor;
		const cond2 = await verifyCommitment(
			this.commitment, r1, dLogProof, blindFactor, this.sessionId, PARTY_ID_1
		);
		if (!cond2) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid Commitment');
		}
		const paillierPublicKey = this.p2KeyShare.paillierPublicKey;
		const cKeyX1 = this.p2KeyShare.cKeyX1;
		const rUpper = r1.multiply(this.k2);
		const r = utils.modPositive(rUpper.x, q);
		const m = utils.Uint8ArraytoBigint(this.messageHash);
		const ro = utils.randBelow(q ** 2n);
		const k2Inv = utils.bigintModInv(this.k2, q);
		const c1 = paillierPublicKey.encrypt(
			ro * q + utils.modPositive(k2Inv * m,  q)
		);
		const v = k2Inv * r * this.p2KeyShare.x2;
		const c2 = paillierPublicKey.multiply(cKeyX1, v);
		const c3 = paillierPublicKey.addition(c1, c2);
		const signMessage4 = new SignMessage4(this.sessionId, c3)
		this._state = Party2SignatureState.PROCESS_SIGN_MSG_5;
		return signMessage4;
	}

	async _processSignMessage5(signMessage5: SignMessage5): Promise<string> {
		if (this._state !== Party2SignatureState.PROCESS_SIGN_MSG_5) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid state');
		}
		if (this.sessionId !== signMessage5.sessionId) {
			this._state = Party2SignatureState.FAILED;
			throw new SignatureFailed('Invalid sessionId');
		}
		const signature = signMessage5.signature;
		try {
			const signatureIsCorrect = await utils.verifySignature(
				this.messageHash,
				this.p2KeyShare.publicKey,
				signature
			);
			if (!signatureIsCorrect) {
				throw new SignatureFailed('Invalid signature');
			}
		} catch (e) {
			this._state = Party2SignatureState.FAILED;
			throw e;
		}
		this._state = Party2SignatureState.COMPLETE;
		return signature;
	}

	async processMessage(messageString: string): Promise<IP2SignatureResult> {
		if (!this.isActive()) {
			throw new SignatureFailed('Signature was already Completed or Failed');
		}

		const messageObj = JSON.parse(messageString);
		const messageSessionId = messageObj.session_id;
		if (this.sessionId !== messageSessionId)
			throw new Error('Invalid sessionId');

		try {
			if (this._state === Party2SignatureState.PROCESS_SIGN_MSG_1) {
				const signMessage1 = SignMessage1.fromStr(messageString);
				const signMessage2 = await this._processSignMessage1(signMessage1);
				return {
					msg_to_send: signMessage2.toStr(),
					signature: null
				}
			}
			if (this._state === Party2SignatureState.PROCESS_SIGN_MSG_3) {
				const signMessage3 = SignMessage3.fromStr(messageString);
				const signMessage4 = await this._processSignMessage3(signMessage3);
				return {
					msg_to_send: signMessage4.toStr(),
					signature: null
				}
			}
			if (this._state === Party2SignatureState.PROCESS_SIGN_MSG_5) {
				const signMessage5 = SignMessage5.fromStr(messageString);
				const signature = await this._processSignMessage5(signMessage5);
				return {
					msg_to_send: null,
					signature
				}
			}
		} catch (e) {
			this._state = Party2SignatureState.FAILED;
			throw e;
		}

		this._state = Party2SignatureState.FAILED;
		throw new SignatureFailed('');
	}

}
