import * as paillier from "paillier-bigint";
import NICorrectKeyProof from "../zkProofs/NICorrectKeyProof";


jest.setTimeout(20000);

export async function nICorrectKeyProofTest() {
  const keyPair = await paillier.generateRandomKeys(2048, true);
  const paillierPrivatekey = keyPair.privateKey;
  const proof = await NICorrectKeyProof.prove(paillierPrivatekey, "", "");
  const proofStr = proof.toStr();
  const proofNew = NICorrectKeyProof.fromStr(proofStr);
  return await proofNew.verify(keyPair.publicKey, "", "");
}

test('nICorrectKeyProof', async () => {
  const data = await nICorrectKeyProofTest();
  expect(data).toBe(true);
});
