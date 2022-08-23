import * as utils from '../../utils';
import * as secp from "@noble/secp256k1";
import DLogProof from '../../zkProofs/DLogProof';
import {
  b64ToBigint,
  b64ToPoint,
  bigintTob64,
  paillierEncryptedNumberToStr,
  paillierPublickeyToStr,
  pointTob64,
  paillierEncryptedNumberFromStr,
  paillierPublickeyFromStr,
} from '../../utils';
import { PDLwSlackProof } from '../../zkProofs/pDLProof/PDLwSlackProof';
import { CompositeDLogProof } from '../../zkProofs/wiDLogProof/CompositeDLogProof';
import * as paillier from 'paillier-bigint';
import NICorrectKeyProof from '../../zkProofs/NICorrectKeyProof';
import { PDLwSlackStatement } from '../../zkProofs/pDLProof/PDLwSlackStatement';


export class KeyGenMessage3 {
  static phase = 'key_gen_message_3';
  static requiredFields = [
    'phase',
    'session_id',
    'q1',
    'dlog_proof_1',
    'blind_factor_1',
    'c_key',
    'paillier_public_key',
    'ni_key_correct_proof',
    'pdl_w_slack_statement',
    'pdl_w_slack_proof',
    'composite_dlog_proof',
    'e1',
    'dlog_proof_2',
    'blind_factor_2',
  ];

  sessionId: string;
  q1: secp.Point;
  dLogProof1: DLogProof;
  blindFactor1: bigint;
  cKey: bigint;
  paillierPublicKey: paillier.PublicKey;
  nIKeyCorrectProof: NICorrectKeyProof;
  pDSwSlackStatement: PDLwSlackStatement;
  pDLwSlackProof: PDLwSlackProof;
  compositeDLogProof: CompositeDLogProof;
  e1: secp.Point;
  dLogProof2: DLogProof;
  blindFactor2: bigint;

  constructor(
    sessionId: string,
    q1: secp.Point,
    dLogProof1: DLogProof,
    blindFactor1: bigint,
    cKey: bigint,
    paillierPublicKey: paillier.PublicKey,
    nIKeyCorrectProof: NICorrectKeyProof,
    pDSwSlackStatement: PDLwSlackStatement,
    pDLwSlackProof: PDLwSlackProof,
    compositeDLogProof: CompositeDLogProof,
    e1: secp.Point,
    dLogProof2: DLogProof,
    blindFactor2: bigint
  ) {
    this.sessionId = sessionId;
    this.q1 = q1;
    this.dLogProof1 = dLogProof1;
    this.blindFactor1 = blindFactor1;
    this.cKey = cKey;
    this.paillierPublicKey = paillierPublicKey;
    this.nIKeyCorrectProof = nIKeyCorrectProof;
    this.pDSwSlackStatement = pDSwSlackStatement;
    this.pDLwSlackProof = pDLwSlackProof;
    this.compositeDLogProof = compositeDLogProof;
    this.e1 = e1;
    this.dLogProof2 = dLogProof2;
    this.blindFactor2 = blindFactor2;
  }

  toJson() {
    return {
      phase: KeyGenMessage3.phase,
      session_id: this.sessionId,
      q1: pointTob64(this.q1),
      dlog_proof_1: this.dLogProof1.toObj(),
      blind_factor_1: bigintTob64(this.blindFactor1),
      c_key: paillierEncryptedNumberToStr(this.cKey),
      paillier_public_key: paillierPublickeyToStr(this.paillierPublicKey),
      ni_key_correct_proof: this.nIKeyCorrectProof.toObj(),
      pdl_w_slack_statement: this.pDSwSlackStatement.toObj(),
      pdl_w_slack_proof: this.pDLwSlackProof.toObj(),
      composite_dlog_proof: this.compositeDLogProof.toObj(),
      e1: pointTob64(this.e1),
      dlog_proof_2: this.dLogProof2.toObj(),
      blind_factor_2: bigintTob64(this.blindFactor2),
    };
  }

  toStr() {
    return JSON.stringify(this.toJson());
  }

  static fromObj(message: any) {
    if (!utils.checkOwnKeys(KeyGenMessage3.requiredFields, message)) {
      throw new Error('Message invalid');
    }
    if (message.phase !== KeyGenMessage3.phase) {
      throw new Error('Phase invalid');
    }
    const sessionId = message.session_id;
    const q1 = b64ToPoint(message.q1);
    const dLogProof1 = DLogProof.fromObj(message.dlog_proof_1);
    const blindFactor1 = b64ToBigint(message.blind_factor_1);
    const cKey = paillierEncryptedNumberFromStr(message.c_key);
    const paillierPublicKey = paillierPublickeyFromStr(message.paillier_public_key);
    const nIKeyCorrectProof = NICorrectKeyProof.fromObj(message.ni_key_correct_proof);
    const pDSwSlackStatement = PDLwSlackStatement.fromObj(message.pdl_w_slack_statement);
    const pDLwSlackProof = PDLwSlackProof.fromObj(message.pdl_w_slack_proof);
    const compositeDLogProof = CompositeDLogProof.fromObj(message.composite_dlog_proof);
    const e1 = b64ToPoint(message.e1);
    const dLogProof2 = DLogProof.fromObj(message.dlog_proof_2);
    const blindFactor2 = b64ToBigint(message.blind_factor_2);
    return new KeyGenMessage3(
      sessionId,
      q1,
      dLogProof1,
      blindFactor1,
      cKey,
      paillierPublicKey,
      nIKeyCorrectProof,
      pDSwSlackStatement,
      pDLwSlackProof,
      compositeDLogProof,
      e1,
      dLogProof2,
      blindFactor2,
    );
  }

  static fromStr(messageString: string) {
    const message = JSON.parse(messageString);
    return KeyGenMessage3.fromObj(message);
  }
}
