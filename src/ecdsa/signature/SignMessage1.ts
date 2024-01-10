import * as utils from "../../utils";

export class SignMessage1 {
	static phase = "sign_message_1";
	static requiredFields = ["phase", "session_id", "commitment"];

	sessionId: string;
	commitment: string;

	constructor(sessionId: string, commitment: string) {
		this.sessionId = sessionId;
		this.commitment = commitment;
	}

	toObj() {
		return {
			phase: SignMessage1.phase,
			session_id: this.sessionId,
			commitment: this.commitment,
		};
	}

	toStr() {
		return JSON.stringify(this.toObj());
	}

	static fromObj(message: ISignMessage1) {
		if (!utils.checkOwnKeys(SignMessage1.requiredFields, message)) {
			throw new Error("Message invalid");
		}
		if (message.phase !== SignMessage1.phase) {
			throw new Error("Phase invalid");
		}
		const sessionId = message.session_id;
		const commitment = message.commitment;
		return new SignMessage1(sessionId, commitment);
	}

	static fromStr(messageString: string) {
		const message = JSON.parse(messageString);
		return SignMessage1.fromObj(message);
	}
}

export interface ISignMessage1 {
	phase: string;
	session_id: string;
	commitment: string;
}
