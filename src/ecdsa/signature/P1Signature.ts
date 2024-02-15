// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

import * as secp from "@noble/secp256k1";
import * as utils from "../../utils";
import DLogProof from "../../zkProofs/DLogProof";
import { createCommitment } from "../../zkProofs/hashCommitment";
import { IP1KeyShare, P1KeyShare } from "../P1KeyShare";
import { SignMessage1 } from "./SignMessage1";
import { SignMessage2 } from "./SignMessage2";
import { SignMessage3 } from "./SignMessage3";
import { SignMessage4 } from "./SignMessage4";
import { SignMessage5 } from "./SignMessage5";
import { SignatureFailed } from "./SignatureFailed";
import { PARTY_ID_1, PARTY_ID_2 } from "../common";
import {
	b64ToBigint,
	b64ToPoint,
	b64ToUint8Array,
	bigintTob64,
	pointTob64,
	Uint8ArrayTob64,
} from "../../utils";

const G = secp.Point.BASE;
const q = secp.CURVE.n;

export interface IP1SignatureResult {
	msg_to_send: string;
	signature: string | null;
	recid?: number;
}

enum Party1SignatureState {
	COMPLETE = 0,
	FAILED = -1,
	GET_SIGN_MSG_1 = 1,
	PROCESS_SIGN_MSG_2 = 2,
	PROCESS_SIGN_MSG_4 = 3,
}

export class P1Signature {
	static requiredFields = [
		"sessionId",
		"messageHash",
		"p1KeyShare",
		"k1",
		"r1",
		"dLogProof",
		"blindFactor",
		"r",
		"recid",
		"state",
	];
	sessionId: string;
	messageHash: Uint8Array;
	p1KeyShare: P1KeyShare;
	k1: bigint | null;
	r1: secp.Point | null;
	dLogProof: DLogProof | null;
	blindFactor: bigint | null;
	r: bigint | null;
	recid: number | null;
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
		this.recid = null;
		this.k1 = null;
		this.r1 = null;
		this.dLogProof = null;
		this.blindFactor = null;
		this.r = null;
	}

	toObj(): IP1Signature {
		const d: IP1Signature = {
			sessionId: this.sessionId,
			messageHash: Uint8ArrayTob64(this.messageHash),
			p1KeyShare: this.p1KeyShare.toObj(),
			k1: null,
			r1: null,
			dLogProof: null,
			blindFactor: null,
			r: null,
			recid: this.recid,
			state: this._state,
		};
		if (this.k1 != null && this.k1 !== undefined) {
			// @ts-ignore
			d.k1 = bigintTob64(this.k1);
		}
		if (this.r1 != null && this.r1 !== undefined) {
			// @ts-ignore
			d.r1 = pointTob64(this.r1);
		}
		if (this.dLogProof != null && this.dLogProof !== undefined) {
			// @ts-ignore
			d.dLogProof = this.dLogProof.toObj();
		}
		if (this.blindFactor !== null && this.blindFactor !== undefined) {
			// @ts-ignore
			d.blindFactor = bigintTob64(this.blindFactor);
		}
		if (this.r !== null && this.r !== undefined) {
			// @ts-ignore
			d.r = bigintTob64(this.r);
		}
		return d;
	}

	static fromObj(obj: IP1Signature) {
		if (!utils.checkOwnKeys(P1Signature.requiredFields, obj)) {
			throw new Error("Invalid obj");
		}
		const sessionId = obj.sessionId;
		const messageHash = b64ToUint8Array(obj.messageHash);
		const signObj = new P1Signature(sessionId, messageHash, obj.p1KeyShare);
		signObj._state = obj.state;
		if (obj.k1) signObj.k1 = b64ToBigint(obj.k1);
		if (obj.r1) signObj.r1 = b64ToPoint(obj.r1);
		if (obj.dLogProof) signObj.dLogProof = DLogProof.fromObj(obj.dLogProof);
		if (obj.blindFactor) signObj.blindFactor = b64ToBigint(obj.blindFactor);
		if (obj.r) signObj.r = b64ToBigint(obj.r);
		if (obj.recid !== null) signObj.recid = obj.recid;
		return signObj;
	}

	isActive(): boolean {
		const cond1 = this._state !== Party1SignatureState.FAILED;
		const cond2 = this._state !== Party1SignatureState.COMPLETE;
		return cond1 && cond2;
	}

	async _getSignMessage1(): Promise<SignMessage1> {
		if (this._state !== Party1SignatureState.GET_SIGN_MSG_1) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed("Invalid state");
		}
		this.k1 = utils.randomCurveScalar();
		this.r1 = G.multiply(this.k1);
		this.dLogProof = await DLogProof.prove(
			this.k1,
			this.r1,
			this.sessionId,
			PARTY_ID_1,
		);
		this.blindFactor = await utils.randomNum(32);
		const commitment = await createCommitment(
			this.r1,
			this.dLogProof,
			this.blindFactor,
			this.sessionId,
			PARTY_ID_1,
		);
		const signMessage1 = new SignMessage1(this.sessionId, commitment);
		this._state = Party1SignatureState.PROCESS_SIGN_MSG_2;
		return signMessage1;
	}

	async _processSignMessage2(
		signMessage2: SignMessage2,
	): Promise<SignMessage3> {
		if (this._state !== Party1SignatureState.PROCESS_SIGN_MSG_2) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed("Invalid state");
		}
		if (this.sessionId !== signMessage2.sessionId) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed("Invalid sessionId");
		}
		const r2 = signMessage2.r2;
		const dLogProof = signMessage2.dLogProof;
		const cond1 = await dLogProof.verify(r2, this.sessionId, PARTY_ID_2);
		if (!cond1) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed("Invalid dLogProof");
		}
		const rUpper = r2.multiply(this.k1 as bigint);
		this.r = utils.modPositive(rUpper.x, q);
		const yBytes = utils.bigintToUint8Array(rUpper.y);
		this.recid = yBytes[yBytes.length - 1] % 2 === 0 ? 0 : 1;

		const signMessage3 = new SignMessage3(
			this.sessionId,
			this.r1 as secp.Point,
			this.dLogProof as DLogProof,
			this.blindFactor as bigint,
		);

		this._state = Party1SignatureState.PROCESS_SIGN_MSG_4;
		return signMessage3;
	}

	async _processSignMessage4(
		signMessage4: SignMessage4,
	): Promise<{ signMessage5: SignMessage5; signature: string; recid: number }> {
		if (this._state !== Party1SignatureState.PROCESS_SIGN_MSG_4) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed("Invalid state");
		}
		if (this.sessionId !== signMessage4.sessionId) {
			this._state = Party1SignatureState.FAILED;
			throw new SignatureFailed("Invalid sessionId");
		}
		const c3 = signMessage4.c3;
		const s1 = this.p1KeyShare.paillierPrivateKey.decrypt(c3);
		const s2 = utils.modPositive(
			utils.bigintModInv(this.k1 as bigint, q) * s1,
			q,
		);
		// const s = s2 < q - s2 ? s2 : q - s2;
		const sPrime = q - s2;
		let s;
		if (this.recid === null) {
			throw new Error("recid is null");
		}

		if (s2 < sPrime) {
			s = s2;
		} else {
			s = sPrime;
			// We know recid will not be null
			this.recid = this.recid === 0 ? 1 : 0;
		}

		const signature = utils.signatureToHex(this.r as bigint, s);
		try {
			const signatureIsCorrect = await utils.verifySignature(
				this.messageHash,
				this.p1KeyShare.publicKey,
				signature,
			);
			if (!signatureIsCorrect) {
				throw new SignatureFailed("Invalid signature");
			}
		} catch (e) {
			this._state = Party1SignatureState.FAILED;
			throw e;
		}
		const signMessage5 = new SignMessage5(this.sessionId, signature);
		this._state = Party1SignatureState.COMPLETE;

		if (this.recid === null) {
			throw new Error("recid is null");
		}

		return { signMessage5, signature, recid: this.recid };
	}

	async processMessage(
		messageString: string | null,
	): Promise<IP1SignatureResult> {
		if (!this.isActive()) {
			throw new SignatureFailed("Signature was already Completed or Failed");
		}

		if (messageString == null) {
			const signMessage1 = await this._getSignMessage1();
			return {
				msg_to_send: signMessage1.toStr(),
				signature: null,
			};
		}

		const messageObj = JSON.parse(messageString);
		const messageSessionId = messageObj.session_id;
		if (this.sessionId !== messageSessionId)
			throw new Error("Invalid sessionId");

		try {
			if (this._state === Party1SignatureState.PROCESS_SIGN_MSG_2) {
				const signMessage2 = SignMessage2.fromStr(messageString);
				const signMessage3 = await this._processSignMessage2(signMessage2);
				return {
					msg_to_send: signMessage3.toStr(),
					signature: null,
				};
			}
			if (this._state === Party1SignatureState.PROCESS_SIGN_MSG_4) {
				const signMessage4 = SignMessage4.fromStr(messageString);
				const { signMessage5, signature, recid } =
					await this._processSignMessage4(signMessage4);
				return {
					msg_to_send: signMessage5.toStr(),
					signature,
					recid,
				};
			}
		} catch (e) {
			this._state = Party1SignatureState.FAILED;
			throw e;
		}

		this._state = Party1SignatureState.FAILED;
		throw new SignatureFailed("");
	}
}

export interface IP1Signature {
	readonly sessionId: string;
	readonly messageHash: string;
	readonly p1KeyShare: IP1KeyShare;
	readonly k1: string | null;
	readonly r1: string | null;
	readonly dLogProof: { t: string; s: string } | null;
	readonly blindFactor: string | null;
	readonly r: string | null;
	readonly recid: number | null;
	readonly state: Party1SignatureState;
}
