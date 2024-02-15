// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

import * as secp from "@noble/secp256k1";
import * as utils from "../../utils";
import DLogProof, { IDLogProof } from "../../zkProofs/DLogProof";
import { b64ToBigint, bigintTob64 } from "../../utils";

export class SignMessage3 {
	static phase = "sign_message_3";
	static requiredFields = [
		"phase",
		"session_id",
		"r1",
		"dlog_proof",
		"blind_factor",
	];

	sessionId: string;
	r1: secp.Point;
	dLogProof: DLogProof;
	blindFactor: bigint;

	constructor(
		sessionId: string,
		r1: secp.Point,
		dLogProof: DLogProof,
		blindFactor: bigint,
	) {
		this.sessionId = sessionId;
		this.r1 = r1;
		this.dLogProof = dLogProof;
		this.blindFactor = blindFactor;
	}

	toObj() {
		return {
			phase: SignMessage3.phase,
			session_id: this.sessionId,
			r1: utils.pointToHex(this.r1),
			dlog_proof: this.dLogProof.toObj(),
			blind_factor: bigintTob64(this.blindFactor),
		};
	}

	toStr() {
		return JSON.stringify(this.toObj());
	}

	static fromObj(message: ISignMessage3) {
		if (!utils.checkOwnKeys(SignMessage3.requiredFields, message)) {
			throw new Error("Message invalid");
		}
		if (message.phase !== SignMessage3.phase) {
			throw new Error("Phase invalid");
		}
		const sessionId = message.session_id;
		const r1 = utils.hexToPoint(message.r1);
		const dLogProof = DLogProof.fromObj(message.dlog_proof);
		const blindFactor = b64ToBigint(message.blind_factor);
		return new SignMessage3(sessionId, r1, dLogProof, blindFactor);
	}

	static fromStr(messageString: string) {
		const message = JSON.parse(messageString);
		return SignMessage3.fromObj(message);
	}
}

export interface ISignMessage3 {
	phase: string;
	session_id: string;
	r1: string;
	dlog_proof: IDLogProof;
	blind_factor: string;
}
