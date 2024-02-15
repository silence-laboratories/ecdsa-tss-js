// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

import {
  IP1KeyShare,
  IP2KeyShare,
  P1KeyGen,
  P2KeyGen,
  randBytes,
} from "ecdsa-tss";

export async function performKeygen(): Promise<
  [IP1KeyShare, IP2KeyShare] | null
> {
  const sessionId = "some session id";
  const x1 = await randBytes(32);
  const x2 = await randBytes(32);

  const p1 = new P1KeyGen(sessionId, x1);
  await p1.init();
  const p2 = new P2KeyGen(sessionId, x2);

  // Round 1
  const msg1 = await p1.processMessage(null);
  const msg2 = await p2.processMessage(msg1.msg_to_send);

  // Round 2
  const msg3 = await p1.processMessage(msg2.msg_to_send);
  const p1KeyShare = msg3.p1_key_share;

  let msg4 = await p2.processMessage(msg3.msg_to_send);
  const p2KeyShare = msg4.p2_key_share;

  if (!p1KeyShare || !p2KeyShare) {
    return null;
  }

  return [p1KeyShare, p2KeyShare];
}
