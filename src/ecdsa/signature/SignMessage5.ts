import * as utils from "../../utils";


export class SignMessage5 {
    static phase = "sign_message_5";
    static requiredFields = ['phase', 'session_id', 'signature'];

    sessionId: string;
    signature: string;

    constructor(sessionId: string, signature: string) {
        this.sessionId = sessionId;
        this.signature = signature;
    }

    toObj() {
        return {
            phase: SignMessage5.phase,
            session_id: this.sessionId,
            signature: this.signature,
        };
    }

    toStr() {
        return JSON.stringify(this.toObj());
    }

    static fromObj(message: any) {
        if (!utils.checkOwnKeys(SignMessage5.requiredFields, message)) {
            throw new Error('Message invalid');
        }
        if (message.phase !== SignMessage5.phase) {
            throw new Error('Phase invalid');
        }
        const sessionId = message.session_id;
        const signature = message.signature;
        return new SignMessage5(sessionId, signature);
    }

    static fromStr(messageString: string) {
        const message = JSON.parse(messageString);
        return SignMessage5.fromObj(message);
    }

}
