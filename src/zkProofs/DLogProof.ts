import * as secp from "@noble/secp256k1";
import * as utils from '../utils';

export default class DLogProof {
  static G = secp.Point.BASE;
  static q = secp.CURVE.n;
  static requiredFields = ['t', 's'];

  t: secp.Point;
  s: bigint;

  constructor(t: secp.Point, s: bigint) {
    this.t = t;
    this.s = s;
  }

  static async _hashList(lst: Uint8Array): Promise<bigint> {
    const h = await utils.sha256(lst);
    return utils.Uint8ArraytoBigint(new Uint8Array(h));
  }

  static async _hashPoints(points: secp.Point[], sid: string, pid: string) {
    const xList: Uint8Array[] = [];
    points.forEach((point) => {
      xList.push(utils.bigintToUint8Array(point.x));
    });
    xList.push(utils.stringToUint8Array(sid));
    xList.push(utils.stringToUint8Array(pid));
    const xListConcat = utils.concatUint8Arrays(xList);
    return await this._hashList(xListConcat);
  }

  static async prove(x: bigint, y: secp.Point, sid: string, pid: string) {
    const r = await utils.randomNum(32);
    const t = this.G.multiply(r);
    const c = await this._hashPoints([this.G, y, t], sid, pid);
    const s = (r + c * x) % this.q;
    return new DLogProof(t, s);
  }

  async verify(y: secp.Point, sid: string, pid: string) {
    const c = await DLogProof._hashPoints([DLogProof.G, y, this.t], sid, pid);
    const lhs = DLogProof.G.multiply(this.s);
    const rhs = this.t.add(y.multiply(c));
    return lhs.equals(rhs);
  }

  toObj() {
    return {
      t: utils.pointTob64(this.t),
      s: utils.bigintTob64(this.s),
    };
  }

  toStr() {
    return JSON.stringify(this.toObj());
  }

  static fromObj(message: any) {
    if (!utils.checkOwnKeys(DLogProof.requiredFields, message)) {
      throw new Error('DLogProof object invalid');
    }
    const t = utils.b64ToPoint(message.t);
    const s = utils.b64ToBigint(message.s);
    return new DLogProof(t, s);
  }

  static fromStr(messageString: string) {
    const message = JSON.parse(messageString);
    return DLogProof.fromObj(message);
  }
}
