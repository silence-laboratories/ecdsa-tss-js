import { performKeygen } from "./utils";
import { P1KeyGen, P2KeyGen } from "ecdsa-tss";

async function refresh() {
	const keyshares = await performKeygen();

	if (!keyshares) {
		throw new Error("Failed to generate keyshares");
	}

	console.log("P1 keyshare pubkey:", "0x" + keyshares[0].public_key);
	console.log("P2 keyshare pubkey:", "0x" + keyshares[1].public_key);

	const sessionId = "session id for key generation action";

	/// Initialize with old keyshare
	const p1 = P1KeyGen.getInstanceForKeyRefresh(sessionId, keyshares[0]);
	await p1.init();

	/// Initialize with old keyshare
	const p2 = P2KeyGen.getInstanceForKeyRefresh(sessionId, keyshares[1]);

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

	console.log("Successfully refreshed keyshares!");
	console.log(
		"Public key after refresh (should remain the same as before): ",
		"0x" + p1KeyShare.public_key,
	);
}

refresh();
