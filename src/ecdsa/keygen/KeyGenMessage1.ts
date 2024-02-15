// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

import * as utils from "../../utils";

export class KeyGenMessage1 {
	static phase = "key_gen_message_1";
	static requiredFields = [
		"phase",
		"session_id",
		"commitment_1",
		"commitment_2",
	];

	sessionId: string;
	commitment1: string;
	commitment2: string;

	constructor(sessionId: string, commitment1: string, commitment2: string) {
		this.sessionId = sessionId;
		this.commitment1 = commitment1;
		this.commitment2 = commitment2;
	}

	toObj(): IKeyGenMessage1 {
		return {
			phase: KeyGenMessage1.phase,
			session_id: this.sessionId,
			commitment_1: this.commitment1,
			commitment_2: this.commitment2,
		};
	}

	toStr() {
		return JSON.stringify(this.toObj());
	}

	static fromObj(message: IKeyGenMessage1) {
		if (!utils.checkOwnKeys(KeyGenMessage1.requiredFields, message)) {
			throw new Error("Message invalid");
		}
		if (message.phase !== KeyGenMessage1.phase) {
			throw new Error("Phase invalid");
		}
		const sessionId = message.session_id;
		const commitment1 = message.commitment_1;
		const commitment2 = message.commitment_2;
		return new KeyGenMessage1(sessionId, commitment1, commitment2);
	}

	static fromStr(messageString: string) {
		const message = JSON.parse(messageString);
		return KeyGenMessage1.fromObj(message);
	}
}

export interface IKeyGenMessage1 {
	phase: string;
	session_id: string;
	commitment_1: string;
	commitment_2: string;
}
