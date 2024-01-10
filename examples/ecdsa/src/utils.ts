import {
  IP1KeyShare,
  IP2KeyShare,
  P1KeyGen,
  P2KeyGen,
  randBytes,
} from "ecdsa-tss";
import {
  existsSync,
  readFileSync,
  unlink,
  unlinkSync,
  writeFileSync,
} from "fs";

export async function performKeygen(): Promise<
  [IP1KeyShare, IP2KeyShare] | null
> {
  const sessionId =
    "70991882fa4a2597de5f37c93cbac7d377cffbc22318039a9175c0ebae3d0226";
  const x1 = await randBytes(32);
  //   const x1 = Uint8Array.from(
  //     Buffer.from(
  //       "e2b6af68dce5be82e30e55110f1105b1ee4be68f1fa50932cd42e923694e2a60"
  //     )
  //   );
  const x2 = await randBytes(32);

  console.time("keygen");
  const p1 = new P1KeyGen(sessionId, x1);
  await p1.init();
  const p2 = new P2KeyGen(sessionId, x2);

  // Round 1
  const msg1 = await p1.processMessage(null);

  writeMsg("msg1", msg1.msg_to_send);
  console.log("Written msg1");

  //   const msg2 = await p2.processMessage(msg1.msg_to_send);

  //   console.log(JSON.parse(msg2.msg_to_send!));

  // Round 2
  const msg2 = readMsg("msg2");

  console.log("GOT MSG2");
  console.log(JSON.parse(msg2));

  const msg3 = await p1.processMessage(JSON.parse(JSON.stringify(msg2)));

  writeMsg("msg3", msg3.msg_to_send);
  console.log("Written msg3");
  // console.log(JSON.parse(msg3.msg_to_send!));

  const p1KeyShare = msg3.p1_key_share as IP1KeyShare;

  writeMsg("p1share", JSON.stringify(p1KeyShare));
  console.log("P1 keyshare pubkey:", `0x${p1KeyShare.public_key}`);

  // let msg4 = await p2.processMessage(msg3.msg_to_send);

  // const p2KeyShare = msg4.p2_key_share;
  // console.timeEnd("keygen");

  // if (!p1KeyShare || !p2KeyShare) {
  //   return null;
  // }

  return null;
  // return [p1KeyShare, p2KeyShare];
}

export function readMsg(msg: string) {
  while (
    !existsSync(`/Users/sushi/code/learn/silence/legacy-2p/${msg}.json`)
  ) {}

  const data = readFileSync(
    `/Users/sushi/code/learn/silence/legacy-2p/${msg}.json`,
    "utf8"
  );

  unlinkSync(`/Users/sushi/code/learn/silence/legacy-2p/${msg}.json`);

  return data;
}

export function readShare(msg: string) {
  while (
    !existsSync(`/Users/sushi/code/learn/silence/legacy-2p/${msg}.json`)
  ) {}

  const data = readFileSync(
    `/Users/sushi/code/learn/silence/legacy-2p/${msg}.json`,
    "utf8"
  );

  return data;
}

export function writeMsg(msg: string, content: string) {
  writeFileSync(
    `/Users/sushi/code/learn/silence/legacy-2p/${msg}.json`,
    content
  );
}
