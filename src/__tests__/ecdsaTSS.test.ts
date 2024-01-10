import {
	P1KeyGen,
	P2KeyGen,
	P1Signature,
	P2Signature,
	IP1KeyShare,
	IP2KeyShare,
	randBytes,
} from "../index";

jest.setTimeout(30000);

async function keyGen() {
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

	return { p1KeyShare, p2KeyShare };
}

async function signature(p1KeyShare: IP1KeyShare, p2KeyShare: IP2KeyShare) {
	const sessionId = "session id for signature";
	const messageHash = await randBytes(32);
	const p1Signature = new P1Signature(sessionId, messageHash, p1KeyShare);
	const p2Signature = new P2Signature(sessionId, messageHash, p2KeyShare);

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
		return null;
	}

	return { p1Sign, p2Sign };
}

async function keyRefresh(
	oldP1KeyShare: IP1KeyShare,
	oldP2KeyShare: IP2KeyShare,
) {
	const sessionId = "session id for key generation action";

	const p1KeyGen = P1KeyGen.getInstanceForKeyRefresh(sessionId, oldP1KeyShare);
	await p1KeyGen.init();
	let p1Store = JSON.stringify(p1KeyGen.toObj());

	const p2KeyGen = P2KeyGen.getInstanceForKeyRefresh(sessionId, oldP2KeyShare);
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

	return { p1KeyShare, p2KeyShare };
}

async function keyGenTest() {
	const keyGenResult = await keyGen();
	if (!keyGenResult) return false;
	const { p1KeyShare, p2KeyShare } = keyGenResult;
	return p1KeyShare.public_key === p2KeyShare.public_key;
}

async function signTest() {
	const keyGenResult = await keyGen();
	if (!keyGenResult) return false;
	const { p1KeyShare, p2KeyShare } = keyGenResult;

	const signatureResult = await signature(p1KeyShare, p2KeyShare);
	if (!signatureResult) return false;
	const s1 = signatureResult.p1Sign;
	const s2 = signatureResult.p2Sign;

	return s1 === s2;
}

async function keyRefreshTest() {
	const keyGenResult = await keyGen();
	if (!keyGenResult) return false;
	const p1KeyShare = keyGenResult.p1KeyShare;
	const p2KeyShare = keyGenResult.p2KeyShare;

	const keyRefreshResult = await keyRefresh(p1KeyShare, p2KeyShare);
	if (!keyRefreshResult) return false;
	const p1KeyShareNew = keyRefreshResult.p1KeyShare;
	const p2KeyShareNew = keyRefreshResult.p2KeyShare;

	if (p1KeyShare.public_key !== p1KeyShareNew.public_key) {
		return false;
	}
	if (p2KeyShare.public_key !== p2KeyShareNew.public_key) {
		return false;
	}

	return true;
}

test("KeyGen", async () => {
	const data = await keyGenTest();
	expect(data).toBe(true);
});

test("Signature", async () => {
	const data = await signTest();
	expect(data).toBe(true);
});

test("KeyRefresh", async () => {
	const data = await keyRefreshTest();
	expect(data).toBe(true);
});
