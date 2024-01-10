import { arrayify, BytesLike } from "@ethersproject/bytes";
import {
	P1KeyGen,
	P2KeyGen,
	IP1KeyShare,
	IP2KeyShare,
	randBytes,
	P1Signature,
	P2Signature,
} from "ecdsa-tss";

export async function performKeygen(): Promise<
	[IP1KeyShare, IP2KeyShare] | null
> {
	const sessionId = "some session id";
	const x1 = await randBytes(32);
	const x2 = await randBytes(32);

	const p1KeyGen = new P1KeyGen(sessionId, x1);
	await p1KeyGen.init();
	const p2KeyGen = new P2KeyGen(sessionId, x2);

	let p1Store = JSON.stringify(p1KeyGen.toObj());
	let p2Store = JSON.stringify(p2KeyGen.toObj());

	// Round 1
	let p1 = P1KeyGen.fromObj(JSON.parse(p1Store));
	const msg1 = await p1.processMessage(null);
	p1Store = JSON.stringify(p1.toObj());

	let p2 = P2KeyGen.fromObj(JSON.parse(p2Store));
	const msg2 = await p2.processMessage(msg1.msg_to_send);
	p2Store = JSON.stringify(p2.toObj());

	// Round 2
	p1 = P1KeyGen.fromObj(JSON.parse(p1Store));
	const msg3 = await p1.processMessage(msg2.msg_to_send);
	p1Store = JSON.stringify(p1.toObj());
	const p1KeyShare = msg3.p1_key_share;

	p2 = P2KeyGen.fromObj(JSON.parse(p2Store));
	const msg4 = await p2.processMessage(msg3.msg_to_send);
	const p2KeyShare = msg4.p2_key_share;

	if (!p1KeyShare || !p2KeyShare) {
		return null;
	}

	return [p1KeyShare, p2KeyShare];
}

export async function generateSign(
	p1KeyShare: IP1KeyShare,
	p2KeyShare: IP2KeyShare,
	messageHash: BytesLike,
): Promise<[string, number]> {
	const sessionId = "session id for signature";

	const msgHash = arrayify(messageHash);

	const p1Signature = new P1Signature(sessionId, msgHash, p1KeyShare);
	const p2Signature = new P2Signature(sessionId, msgHash, p2KeyShare);

	let p1Store = JSON.stringify(p1Signature.toObj());
	let p2Store = JSON.stringify(p2Signature.toObj());

	let p1 = P1Signature.fromObj(JSON.parse(p1Store));

	// Round 1
	const msg1 = await p1.processMessage(null);
	p1Store = JSON.stringify(p1.toObj());

	let p2 = P2Signature.fromObj(JSON.parse(p2Store));
	const msg2 = await p2.processMessage(msg1.msg_to_send);
	p2Store = JSON.stringify(p2.toObj());

	// Round 2
	p1 = P1Signature.fromObj(JSON.parse(p1Store));
	const msg3 = await p1.processMessage(msg2.msg_to_send);
	p1Store = JSON.stringify(p1.toObj());

	p2 = P2Signature.fromObj(JSON.parse(p2Store));
	const msg4 = await p2.processMessage(msg3.msg_to_send);
	p2Store = JSON.stringify(p2.toObj());

	// Round 3
	p1 = P1Signature.fromObj(JSON.parse(p1Store));
	const msg5 = await p1.processMessage(msg4.msg_to_send);
	p1Store = JSON.stringify(p1.toObj());

	const p1Sign = msg5.signature;

	p2 = P2Signature.fromObj(JSON.parse(p2Store));
	const msg6 = await p2.processMessage(msg5.msg_to_send);
	p2Store = JSON.stringify(p2.toObj());

	const p2Sign = msg6.signature;

	if (!p1Sign || !p2Sign) {
		throw new Error("Signature failed");
	}

	if (msg5.recid === undefined || msg5.recid === null) {
		throw new Error("recid is null");
	}

	return [p1Sign, msg5.recid];
}
