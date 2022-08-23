import * as secp from "@noble/secp256k1";
import * as utils from "../../utils";
import DLogProof from "../../zkProofs/DLogProof";
import {createCommitment} from "../../zkProofs/hashCommitment"
import {IP1KeyShare, P1KeyShare} from "../P1KeyShare";
import {SignMessage1} from "./SignMessage1";
import {SignMessage2} from "./SignMessage2";
import {SignMessage3} from "./SignMessage3";
import {SignMessage4} from "./SignMessage4";
import {SignMessage5} from "./SignMessage5";
import {SignatureFailed} from "./SignatureFailed";
import { PARTY_ID_1, PARTY_ID_2 } from "../common";


const G = secp.Point.BASE;
const q = secp.CURVE.n;

export interface IP1SignatureResult {
	msg_to_send: string,
	signature: string | null
}

enum Party1SignatureState {
    COMPLETE = 0,
    FAILED = -1,
    GET_SIGN_MSG_1 = 1,
    PROCESS_SIGN_MSG_2 = 2,
    PROCESS_SIGN_MSG_4 = 3,
}

export class P1Signature {
    sessionId: string;
	messageHash: Uint8Array;
	p1KeyShare: P1KeyShare;
    k1: bigint | any;
	r1: secp.Point | any;
	dLogProof: DLogProof | any;
	blindFactor: bigint | any;
	r: bigint | any;
    _state: Party1SignatureState;

    constructor(
		sessionId: string,
		messageHash: Uint8Array,
		p1KeyShareObj: IP1KeyShare,
    ) {
        this.sessionId = sessionId;
        this.messageHash = messageHash;
        this.p1KeyShare = P1KeyShare.fromObj(p1KeyShareObj);
        this._state = Party1SignatureState.GET_SIGN_MSG_1;
    }

	isActive(): boolean {
		const cond1 = this._state !== Party1SignatureState.FAILED;
		const cond2 = this._state !== Party1SignatureState.COMPLETE;
		return cond1 && cond2;
	}

    async _getSignMessage1(): Promise<SignMessage1> {
        if (this._state !== Party1SignatureState.GET_SIGN_MSG_1) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed('Invalid state');
		}
		this.k1 = utils.randomCurveScalar();
		this.r1 = G.multiply(this.k1);
		this.dLogProof = await DLogProof.prove(this.k1, this.r1, this.sessionId, PARTY_ID_1);
		this.blindFactor = await utils.randomNum(32);
		const commitment = await createCommitment(
			this.r1, this.dLogProof, this.blindFactor, this.sessionId, PARTY_ID_1
		);
		const signMessage1 = new SignMessage1(this.sessionId, commitment);
		this._state = Party1SignatureState.PROCESS_SIGN_MSG_2;
		return signMessage1;
    }

	async _processSignMessage2(signMessage2: SignMessage2): Promise<SignMessage3> {
		if (this._state !== Party1SignatureState.PROCESS_SIGN_MSG_2) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed('Invalid state');
		}
		if (this.sessionId !== signMessage2.sessionId) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed('Invalid sessionId');
		}
		const r2 = signMessage2.r2;
		const dLogProof = signMessage2.dLogProof;
		const cond1 = await dLogProof.verify(r2, this.sessionId, PARTY_ID_2);
		if (!cond1) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed('Invalid dLogProof');
		}
		const rUpper = r2.multiply(this.k1);
		this.r = utils.modPositive(rUpper.x, q);
		const signMessage3 = new SignMessage3(this.sessionId, this.r1, this.dLogProof, this.blindFactor);
		this._state = Party1SignatureState.PROCESS_SIGN_MSG_4;
		return signMessage3;
	}

	async _processSignMessage4(signMessage4: SignMessage4):
		Promise<{ signMessage5: SignMessage5, signature: string }> {
		if (this._state !== Party1SignatureState.PROCESS_SIGN_MSG_4) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed('Invalid state');
		}
		if (this.sessionId !== signMessage4.sessionId) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed('Invalid sessionId');
		}
		const c3 = signMessage4.c3;
		const s1 = this.p1KeyShare.paillierPrivateKey.decrypt(c3);
		const s2 = utils.modPositive(utils.bigintModInv(this.k1, q) * s1, q);
		const s = s2 < q - s2 ? s2 : q - s2;
		const signature = utils.signatureToHex(this.r, s);
		try {
			const signatureIsCorrect = await utils.verifySignature(
				this.messageHash,
				this.p1KeyShare.publicKey,
				signature
			);
			if (!signatureIsCorrect) {
				throw new SignatureFailed('Invalid signature');
			}
		} catch (e) {
			this._state = Party1SignatureState.FAILED;
			throw e;
		}
		const signMessage5 = new SignMessage5(this.sessionId, signature);
		this._state = Party1SignatureState.COMPLETE;
		return { signMessage5, signature };
	}

	async processMessage(messageString: string | null): Promise<IP1SignatureResult> {
		if (!this.isActive()) {
			throw new SignatureFailed('Signature was already Completed or Failed');
		}

		if (messageString == null) {
			const signMessage1 = await this._getSignMessage1();
			return {
				msg_to_send: signMessage1.toStr(),
				signature: null
			}
		}

		const messageObj = JSON.parse(messageString);
		const messageSessionId = messageObj.session_id;
		if (this.sessionId !== messageSessionId)
			throw new Error('Invalid sessionId');

		try {
			if (this._state === Party1SignatureState.PROCESS_SIGN_MSG_2) {
				const signMessage2 = SignMessage2.fromStr(messageString);
				const signMessage3 = await this._processSignMessage2(signMessage2);
				return {
					msg_to_send: signMessage3.toStr(),
					signature: null
				}
			}
			if (this._state === Party1SignatureState.PROCESS_SIGN_MSG_4) {
				const signMessage4 = SignMessage4.fromStr(messageString);
				const {signMessage5, signature} = await this._processSignMessage4(signMessage4);
				return {
					msg_to_send: signMessage5.toStr(),
					signature
				}
			}
		} catch (e) {
			this._state = Party1SignatureState.FAILED;
			throw e;
		}

		this._state = Party1SignatureState.FAILED;
		throw new SignatureFailed('');
	}

}
