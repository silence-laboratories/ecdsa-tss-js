import * as utils from "../utils";
import { sha256, Uint8ArrayToHex } from "../utils";
import DLogProof from "./DLogProof";
import * as secp from "@noble/secp256k1";

export async function createCommitment(
  q: secp.Point,
  dLogProof: DLogProof,
  blindFactor: bigint,
  sid: string,
  pid: string
): Promise<string> {
  const dataList: bigint[] = [q.x, dLogProof.t.x, dLogProof.s, blindFactor];
  const dataToHashList: Uint8Array[] = [];
  dataList.forEach((value) => {
    dataToHashList.push(utils.bigintToUint8Array(value));
  });
  dataToHashList.push(utils.hexToUint8Array(sid));
  dataToHashList.push(utils.stringToUint8Array(pid));
  console.log("Data to hash: ", dataToHashList);
  const dataToHash = utils.concatUint8Arrays(dataToHashList);
  const hash = await sha256(dataToHash);
  console.log("Hash commitment: ", hash);
  return Uint8ArrayToHex(new Uint8Array(hash));
}

export async function verifyCommitment(
  commitment: string,
  q: secp.Point,
  dLogProof: DLogProof,
  blindFactor: bigint,
  sid: string,
  pid: string
): Promise<boolean> {
  const commitmentTest = await createCommitment(
    q,
    dLogProof,
    blindFactor,
    sid,
    pid
  );
  return commitmentTest === commitment;
}
