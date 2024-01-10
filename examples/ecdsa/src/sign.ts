import {
  IP1KeyShare,
  IP2KeyShare,
  P1Signature,
  P2Signature,
  randBytes,
} from "ecdsa-tss";
import { performKeygen, readMsg, readShare, writeMsg } from "./utils";
import { utils } from "@noble/secp256k1";

async function signature() {
  // const keyshares = await performKeygen();
  // if (keyshares === null) {
  //   throw new Error("Keygen failed");
  // }

  console.time("signature");

  const sessionId =
    "70991882fa4a2597de5f37c93cbac7d377cffbc22318039a9175c0ebae3d0226";

  const messageHash = await utils.sha256(
    Buffer.from("In Silence there is eloquence")
  );
  const keyshare1 = readShare("p1share");
  console.log("keyshare1", keyshare1);
  // const messageHash = await randBytes(32);
  const p1 = new P1Signature(sessionId, messageHash, JSON.parse(keyshare1));
  // const p2 = new P2Signature(sessionId, messageHash, keyshares[1]);

  // Round 1
  const msg1 = await p1.processMessage(null);
  // console.log(JSON.parse(msg1.msg_to_send!));
  // const msg2 = await p2.processMessage(msg1.msg_to_send);
  // console.log(JSON.parse(msg2.msg_to_send!));

  console.log("writing msg1");
  writeMsg("smsg1", msg1.msg_to_send);

  const msg2 = readMsg("smsg2");

  // Round 2
  const msg3 = await p1.processMessage(JSON.parse(JSON.stringify(msg2)));

  console.log("writing msg3");
  writeMsg("smsg3", msg3.msg_to_send);
  // console.log(JSON.parse(msg3.msg_to_send!));
  // const msg4 = await p2.processMessage(msg3.msg_to_send);
  // console.log(JSON.parse(msg4.msg_to_send!));

  // Round 3
  const msg4 = readMsg("smsg4");
  const msg5 = await p1.processMessage(JSON.parse(JSON.stringify(msg4)));
  // console.log(JSON.parse(msg5.msg_to_send!));
  const p1Sign = msg5.signature;
  // const msg6 = await p2.processMessage(msg5.msg_to_send);
  // const p2Sign = msg6.signature;

  writeMsg("smsg5", msg5.msg_to_send);

  console.timeEnd("signature");

  // if (!p1Sign || !p2Sign) {
  //   return null;
  // }

  console.log("p1Sign", `0x${p1Sign}`);
  // console.log("p2Sign", "0x" + p2Sign);
}

signature();
