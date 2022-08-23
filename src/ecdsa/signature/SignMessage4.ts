import * as utils from "../../utils";


export class SignMessage4 {
    static phase = "sign_message_4";
    static requiredFields = ['phase', 'session_id', 'c3'];

    sessionId: string;
    c3: bigint;

    constructor(sessionId: string, c3: bigint) {
        this.sessionId = sessionId;
        this.c3 = c3;
    }

    toObj() {
        return {
            phase: SignMessage4.phase,
            session_id: this.sessionId,
            c3: utils.paillierEncryptedNumberToStr(this.c3),
        };
    }

    toStr() {
        return JSON.stringify(this.toObj());
    }

    static fromObj(message: any) {
        if (!utils.checkOwnKeys(SignMessage4.requiredFields, message)) {
            throw new Error('Message invalid');
        }
        if (message.phase !== SignMessage4.phase) {
            throw new Error('Phase invalid');
        }
        const sessionId = message.session_id;
        const c3 = utils.paillierEncryptedNumberFromStr(message.c3);
        return new SignMessage4(sessionId, c3);
    }

    static fromStr(messageString: string) {
        const message = JSON.parse(messageString);
        return SignMessage4.fromObj(message);
    }

}
