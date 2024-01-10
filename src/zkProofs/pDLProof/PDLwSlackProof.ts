import * as secp from "@noble/secp256k1";
import * as utils from "../../utils";
import { PDLwSlackWitness } from "./PDLwSlackWitness";
import { PDLwSlackStatement } from "./PDLwSlackStatement";

export class PDLwSlackProof {
  static requiredFields = ["z", "u1", "u2", "u3", "s1", "s2", "s3"];
  static q = secp.CURVE.n;

  z: bigint;
  u1: secp.Point;
  u2: bigint;
  u3: bigint;
  s1: bigint;
  s2: bigint;
  s3: bigint;

  constructor(
    z: bigint,
    u1: secp.Point,
    u2: bigint,
    u3: bigint,
    s1: bigint,
    s2: bigint,
    s3: bigint
  ) {
    this.z = z;
    this.u1 = u1;
    this.u2 = u2;
    this.u3 = u3;
    this.s1 = s1;
    this.s2 = s2;
    this.s3 = s3;
  }

  toObj(): IPDLwSlackProof {
    return {
      z: utils.bigintTob64(this.z),
      u1: utils.pointTob64(this.u1),
      u2: utils.bigintTob64(this.u2),
      u3: utils.bigintTob64(this.u3),
      s1: utils.bigintTob64(this.s1),
      s2: utils.bigintTob64(this.s2),
      s3: utils.bigintTob64(this.s3),
    };
  }

  to_str() {
    return JSON.stringify(this.toObj());
  }

  static fromObj(message: IPDLwSlackProof) {
    if (!utils.checkOwnKeys(PDLwSlackProof.requiredFields, message)) {
      throw new Error("PDLwSlackProof object invalid");
    }
    const z = utils.b64ToBigint(message.z);
    const u1 = utils.b64ToPoint(message.u1);
    const u2 = utils.b64ToBigint(message.u2);
    const u3 = utils.b64ToBigint(message.u3);
    const s1 = utils.b64ToBigint(message.s1);
    const s2 = utils.b64ToBigint(message.s2);
    const s3 = utils.b64ToBigint(message.s3);
    return new PDLwSlackProof(z, u1, u2, u3, s1, s2, s3);
  }

  static async prove(
    witness: PDLwSlackWitness,
    statement: PDLwSlackStatement,
    sid: string,
    pid: string
  ) {
    const q3 = PDLwSlackProof.q ** BigInt(3);
    const qNTilde = PDLwSlackProof.q * statement.nTilde;
    const q3NTilde = q3 * statement.nTilde;

    const alpha: bigint = utils.randBelow(q3);
    const beta: bigint = utils.randBelow(statement.ek.n);
    const rho: bigint = utils.randBelow(qNTilde);
    const gamma: bigint = utils.randBelow(q3NTilde);

    const z = commitment_unknown_order(
      statement.h1,
      statement.h2,
      statement.nTilde,
      witness.x,
      rho
    );

    const u1 = statement.G.multiply(utils.modPositive(alpha, PDLwSlackProof.q));

    const u2 = commitment_unknown_order(
      statement.ek.n + BigInt(1),
      beta,
      statement.ek._n2,
      alpha,
      statement.ek.n
    );

    const u3 = commitment_unknown_order(
      statement.h1,
      statement.h2,
      statement.nTilde,
      alpha,
      gamma
    );

    const data = [];
    data.push(utils.pointToBytes(statement.G));
    data.push(utils.pointToBytes(statement.Q));
    data.push(utils.bigintToUint8Array(statement.ciphertext));
    data.push(utils.bigintToUint8Array(z));
    data.push(utils.pointToBytes(u1));
    data.push(utils.bigintToUint8Array(u2));
    data.push(utils.bigintToUint8Array(u3));
    data.push(utils.hexToUint8Array(sid));
    data.push(utils.stringToUint8Array(pid));

    const concatData = utils.concatUint8Arrays(data);

    const h = await utils.sha256(concatData);

    const e = utils.Uint8ArraytoBigint(new Uint8Array(h));

    const s1 = e * witness.x + alpha;
    const s2 = commitment_unknown_order(
      witness.r,
      beta,
      statement.ek.n,
      e,
      BigInt(1)
    );
    const s3 = e * rho + gamma;

    return new PDLwSlackProof(z, u1, u2, u3, s1, s2, s3);
  }

  async verify(statement: PDLwSlackStatement, sid: string, pid: string) {
    const data = [];
    data.push(utils.pointToBytes(statement.G));
    data.push(utils.pointToBytes(statement.Q));
    data.push(utils.bigintToUint8Array(statement.ciphertext));
    data.push(utils.bigintToUint8Array(this.z));
    data.push(utils.pointToBytes(this.u1));
    data.push(utils.bigintToUint8Array(this.u2));
    data.push(utils.bigintToUint8Array(this.u3));
    data.push(utils.hexToUint8Array(sid));
    data.push(utils.stringToUint8Array(pid));

    const concatData = utils.concatUint8Arrays(data);

    const h = await utils.sha256(concatData);
    const e = utils.Uint8ArraytoBigint(new Uint8Array(h));

    const gS1 = statement.G.multiply(
      utils.modPositive(this.s1, PDLwSlackProof.q)
    );
    const eFeNeg = PDLwSlackProof.q - e;
    const yMinusE = statement.Q.multiply(eFeNeg);
    const u1Test = gS1.add(yMinusE);

    const u2TestTmp = commitment_unknown_order(
      statement.ek.n + BigInt(1),
      this.s2,
      statement.ek._n2,
      this.s1,
      statement.ek.n
    );
    const u2Test = commitment_unknown_order(
      u2TestTmp,
      statement.ciphertext,
      statement.ek._n2,
      BigInt(1),
      -e
    );

    const u3TestTmp = commitment_unknown_order(
      statement.h1,
      statement.h2,
      statement.nTilde,
      this.s1,
      this.s3
    );
    const u3Test = commitment_unknown_order(
      u3TestTmp,
      this.z,
      statement.nTilde,
      BigInt(1),
      -e
    );
    return this.u1.equals(u1Test) && this.u2 === u2Test && this.u3 === u3Test;
  }
}

function commitment_unknown_order(
  h1: bigint,
  h2: bigint,
  nTilde: bigint,
  x: bigint,
  r: bigint
): bigint {
  const h1X = utils.bigintModPow(h1, x, nTilde);
  let h2R: bigint;
  if (r < 0) {
    const h2Inv = utils.bigintModInv(h2, nTilde);
    h2R = utils.bigintModPow(h2Inv, -r, nTilde);
  } else {
    h2R = utils.bigintModPow(h2, r, nTilde);
  }
  return utils.modPositive(h1X * h2R, nTilde);
}
export interface IPDLwSlackProof {
  z: string;
  u1: string;
  u2: string;
  u3: string;
  s1: string;
  s2: string;
  s3: string;
}
