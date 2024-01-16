import { P1Signature, P2Signature, randBytes } from "ecdsa-tss";
import { performKeygen } from "./utils";

async function signature() {
  const keyshares = await performKeygen();
  if (keyshares === null) {
    throw new Error("Keygen failed");
  }

  const sessionId = "session id for signature";
  const messageHash = await randBytes(32);
  const p1 = new P1Signature(sessionId, messageHash, keyshares[0]);
  const p2 = new P2Signature(sessionId, messageHash, keyshares[1]);

  // Round 1
  const msg1 = await p1.processMessage(null);
  const msg2 = await p2.processMessage(msg1.msg_to_send);

  // Round 2
  const msg3 = await p1.processMessage(msg2.msg_to_send);
  const msg4 = await p2.processMessage(msg3.msg_to_send);

  // Round 3
  const msg5 = await p1.processMessage(msg4.msg_to_send);
  const p1Sign = msg5.signature;
  const msg6 = await p2.processMessage(msg5.msg_to_send);
  const p2Sign = msg6.signature;

  if (!p1Sign || !p2Sign) {
    return null;
  }

  console.log("p1Sign", "0x" + p1Sign);
  console.log("p2Sign", "0x" + p2Sign);
}

signature();
