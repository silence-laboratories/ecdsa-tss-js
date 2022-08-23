import * as secp from "@noble/secp256k1";
import * as utils from "../../utils";
import DLogProof from "../../zkProofs/DLogProof";


export class SignMessage2 {
    static phase = "sign_message_2";
    static requiredFields = ['phase', 'session_id', 'r2', 'dlog_proof'];

    sessionId: string;
    r2: secp.Point;
    dLogProof: DLogProof;

    constructor(sessionId: string, r2: secp.Point, dLogProof: DLogProof) {
        this.sessionId = sessionId;
        this.r2 = r2;
        this.dLogProof = dLogProof;
    }

    toObj() {
        return {
            phase: SignMessage2.phase,
            session_id: this.sessionId,
            r2: utils.pointToHex(this.r2),
            dlog_proof: this.dLogProof.toObj()
        };
    }

    toStr() {
        return JSON.stringify(this.toObj());
    }

    static fromObj(message: any) {
        if (!utils.checkOwnKeys(SignMessage2.requiredFields, message)) {
            throw new Error('Message invalid');
        }
        if (message.phase !== SignMessage2.phase) {
            throw new Error('Phase invalid');
        }
        const sessionId = message.session_id;
        const r2 = utils.hexToPoint(message.r2);
        const dLogProof = DLogProof.fromObj(message.dlog_proof);
        return new SignMessage2(sessionId, r2, dLogProof);
    }

    static fromStr(messageString: string) {
        const message = JSON.parse(messageString);
        return SignMessage2.fromObj(message);
    }

}
