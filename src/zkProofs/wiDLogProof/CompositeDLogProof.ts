import * as utils from "../../utils";
import { DLogStatement } from "./DLogStatement";

export class CompositeDLogProof {
  static K = BigInt(128);
  static K_PRIME = BigInt(128);
  static SAMPLE_S = BigInt(256);
  static requiredFields = ["x", "y"];

  x: bigint;
  y: bigint;

  constructor(x: bigint, y: bigint) {
    this.x = x;
    this.y = y;
  }

  static async prove(
    dLogStatement: DLogStatement,
    secret: bigint,
    sid: string,
    pid: string
  ) {
    const bits =
      CompositeDLogProof.K +
      CompositeDLogProof.K_PRIME +
      CompositeDLogProof.SAMPLE_S;
    const R = BigInt(2) ** bits;

    // // Generating random number less than R = 2**bits in cryptogrphically secure manner
    // let bytes_needed = Number(bits)/8;                                  // Calculating number of bytes needed
    // let bytes = new Uint8Array(bytes_needed)                            // Initialising bytes_needed bytes
    // let r = BigInt(0)
    // while (r>= R || r<1) {                                              // specifying limits, though checking for >= R is redundant
    //     r = utils.Uint8ArraytoBigint(crypto.getRandomValues(bytes))     // Generate bytes_needed random bytes and convert it to bigint
    // }

    const r = utils.randBelow(R);
    const x = utils.bigintModPow(dLogStatement.g, r, dLogStatement.N);
    const data = [
      utils.bigintToUint8Array(x),
      utils.bigintToUint8Array(dLogStatement.g),
      utils.bigintToUint8Array(dLogStatement.N),
      utils.bigintToUint8Array(dLogStatement.ni),
      utils.hexToUint8Array(sid),
      utils.stringToUint8Array(pid),
    ];
    const concatData = utils.concatUint8Arrays(data);
    const h = await utils.sha256(concatData);
    const e = utils.Uint8ArraytoBigint(new Uint8Array(h));
    const y = r + e * secret;
    return new CompositeDLogProof(x, y);
  }

  async verify(dLogStatement: DLogStatement, sid: string, pid: string) {
    if (!(dLogStatement.N > BigInt(2) ** CompositeDLogProof.K)) return false;

    if (utils.bigintGcd(dLogStatement.g, dLogStatement.N) !== BigInt(1))
      return false;

    if (utils.bigintGcd(dLogStatement.ni, dLogStatement.N) !== BigInt(1))
      return false;

    const data = [
      utils.bigintToUint8Array(this.x),
      utils.bigintToUint8Array(dLogStatement.g),
      utils.bigintToUint8Array(dLogStatement.N),
      utils.bigintToUint8Array(dLogStatement.ni),
      utils.hexToUint8Array(sid),
      utils.stringToUint8Array(pid),
    ];
    const concatData = utils.concatUint8Arrays(data);

    const h = await utils.sha256(concatData);
    const e = utils.Uint8ArraytoBigint(new Uint8Array(h));

    const niE = utils.bigintModPow(dLogStatement.ni, e, dLogStatement.N);
    const gY = utils.bigintModPow(dLogStatement.g, this.y, dLogStatement.N);
    const gYNiE = utils.modPositive(gY * niE, dLogStatement.N);

    return this.x === gYNiE;
  }

  toObj(): ICompositeDLogProof {
    return {
      x: utils.bigintTob64(this.x),
      y: utils.bigintTob64(this.y),
    };
  }

  to_str() {
    return JSON.stringify(this.toObj());
  }

  static fromObj(message: ICompositeDLogProof) {
    if (!utils.checkOwnKeys(CompositeDLogProof.requiredFields, message)) {
      throw new Error("CompositeDLogProof object invalid");
    }
    const x = utils.b64ToBigint(message.x);
    const y = utils.b64ToBigint(message.y);
    return new CompositeDLogProof(x, y);
  }

  static fromString(messageString: string) {
    const message = JSON.parse(messageString);
    return CompositeDLogProof.fromObj(message);
  }
}

export interface ICompositeDLogProof {
  x: string;
  y: string;
}
