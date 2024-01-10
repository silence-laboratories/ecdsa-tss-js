import * as utils from "../../utils";
import * as secp from "@noble/secp256k1";
import DLogProof, { IDLogProof } from "../../zkProofs/DLogProof";
import { b64ToPoint, pointTob64 } from "../../utils";

export class KeyGenMessage2 {
  static phase = "key_gen_message_2";
  static requiredFields = [
    "phase",
    "session_id",
    "q2",
    "dlog_proof_1",
    "e2",
    "dlog_proof_2",
  ];

  sessionId: string;
  q2: secp.Point;
  dLogProof1: DLogProof;
  e2: secp.Point;
  dLogProof2: DLogProof;

  constructor(
    sessionId: string,
    q2: secp.Point,
    dLogProof1: DLogProof,
    e2: secp.Point,
    dLogProof2: DLogProof
  ) {
    this.sessionId = sessionId;
    this.q2 = q2;
    this.dLogProof1 = dLogProof1;
    this.e2 = e2;
    this.dLogProof2 = dLogProof2;
  }

  toObj(): IKeyGenMessage2 {
    return {
      phase: KeyGenMessage2.phase,
      session_id: this.sessionId,
      q2: pointTob64(this.q2),
      dlog_proof_1: this.dLogProof1.toObj(),
      e2: pointTob64(this.e2),
      dlog_proof_2: this.dLogProof2.toObj(),
    };
  }

  toStr() {
    return JSON.stringify(this.toObj());
  }

  static fromObj(message: IKeyGenMessage2) {
    if (!utils.checkOwnKeys(KeyGenMessage2.requiredFields, message)) {
      throw new Error("Message invalid");
    }
    if (message.phase !== KeyGenMessage2.phase) {
      throw new Error("Phase invalid");
    }
    const sessionId = message.session_id;
    const q2 = b64ToPoint(message.q2);
    const dLogProof1 = DLogProof.fromObj(message.dlog_proof_1);
    const e2 = b64ToPoint(message.e2);
    const dLogProof2 = DLogProof.fromObj(message.dlog_proof_2);
    return new KeyGenMessage2(sessionId, q2, dLogProof1, e2, dLogProof2);
  }

  static fromStr(messageString: string) {
    const message = JSON.parse(messageString);
    console.log("Parsed: ", message);
    return KeyGenMessage2.fromObj(message);
  }
}

export interface IKeyGenMessage2 {
  phase: string;
  session_id: string;
  q2: string;
  dlog_proof_1: IDLogProof;
  e2: string;
  dlog_proof_2: IDLogProof;
}
