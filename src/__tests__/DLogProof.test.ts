import DLogProof from "../zkProofs/DLogProof";
import * as utils from '../utils';
import * as secp from "@noble/secp256k1";


async function dLogProofTest() {
  const G = secp.Point.BASE;
  const x = await utils.randomNum(32);
  const y = G.multiply(x);
  const dLogProof = await DLogProof.prove(x, y, "", "");
  const dLogProofStr = dLogProof.toStr();
  const dLogProofNew = DLogProof.fromStr(dLogProofStr);
  return await dLogProofNew.verify(y,"", "");
}

test('DLogProof', async () => {
  const data = await dLogProofTest();
  expect(data).toBe(true);
});
