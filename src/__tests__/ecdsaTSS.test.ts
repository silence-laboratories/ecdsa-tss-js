import {
    P1KeyGen,
    P2KeyGen,
    P1Signature,
    P2Signature,
    IP1KeyShare,
    IP2KeyShare,
    randBytes,
    IP1KeyGenResult, IP2KeyGenResult, IP1SignatureResult, IP2SignatureResult
} from "../index";


jest.setTimeout(30000);

async function keyGen() {
    const sessionId = "some session id";
    const x1 = await randBytes(32);
    const x2 = await randBytes(32);

    const p1KeyGen = new P1KeyGen(sessionId, x1);
    await p1KeyGen.init();

    const p2KeyGen = new P2KeyGen(sessionId, x2);

    let p1KeyShare;
    let p2KeyShare;
    let p1KeyGenCompleted = false;
    let p2KeyGenCompleted = false;
    let messageFromParty1 = null;
    let messageFromParty2 = null;
    // ping-pong
    for (let i = 0; i < 2; i++) {
        if (!p1KeyGenCompleted) {
            const p1KeyGenResult: IP1KeyGenResult = await p1KeyGen.processMessage(messageFromParty2);
            if (p1KeyGenResult.msg_to_send) {
                messageFromParty1 = p1KeyGenResult.msg_to_send;
            }
            if (p1KeyGenResult.p1_key_share) {
                p1KeyShare = p1KeyGenResult.p1_key_share;
                p1KeyGenCompleted = true;
            }
        }
        if (messageFromParty1 && (!p2KeyGenCompleted)) {
            const p2KeyGenResult: IP2KeyGenResult = await p2KeyGen.processMessage(messageFromParty1);
            if (p2KeyGenResult.msg_to_send) {
                messageFromParty2 = p2KeyGenResult.msg_to_send;
            }
            if (p2KeyGenResult.p2_key_share) {
                p2KeyShare = p2KeyGenResult.p2_key_share;
                p2KeyGenCompleted = true;
            }
        }
    }

    if (!(p1KeyShare && p2KeyShare)) {
        return null;
    }
    return {p1KeyShare, p2KeyShare};
}

async function signature(p1KeyShare: IP1KeyShare, p2KeyShare: IP2KeyShare) {
    const sessionId = "session id for signature";
    const messageHash = await randBytes(32);
    const p1Signature = new P1Signature(sessionId, messageHash, p1KeyShare);
    const p2Signature = new P2Signature(sessionId, messageHash, p2KeyShare);

    let s1;
    let s2;
    let p1SignCompleted = false;
    let p2SignCompleted = false;
    let messageFromParty1 = null;
    let messageFromParty2 = null;
    // ping-pong
    for (let i = 0; i < 3; i++) {
        if (!p1SignCompleted) {
            const p1SignResult: IP1SignatureResult = await p1Signature.processMessage(messageFromParty2);
            if (p1SignResult.msg_to_send) {
                messageFromParty1 = p1SignResult.msg_to_send;
            }
            if (p1SignResult.signature) {
                s1 = p1SignResult.signature;
                p1SignCompleted = true;
            }
        }
        if (messageFromParty1 && (!p2SignCompleted)) {
            const p2SignResult: IP2SignatureResult = await p2Signature.processMessage(messageFromParty1);
            if (p2SignResult.msg_to_send) {
                messageFromParty2 = p2SignResult.msg_to_send;
            }
            if (p2SignResult.signature) {
                s2 = p2SignResult.signature;
                p2SignCompleted = true;
            }
        }
    }

    if (!(s1 && s2)) {
        return false;
    }
    return {s1, s2};
}

async function keyRefresh(oldP1KeyShare: IP1KeyShare, oldP2KeyShare: IP2KeyShare) {
    const sessionId = "session id for key generation action";

    const p1KeyGen = P1KeyGen.getInstanceForKeyRefresh(sessionId, oldP1KeyShare);
    await p1KeyGen.init();

    const p2KeyGen = P2KeyGen.getInstanceForKeyRefresh(sessionId, oldP2KeyShare);

    let p1KeyShare;
    let p2KeyShare;
    let p1KeyGenCompleted = false;
    let p2KeyGenCompleted = false;
    let messageFromParty1 = null;
    let messageFromParty2 = null;
    // ping-pong
    for (let i = 0; i < 2; i++) {
        if (!p1KeyGenCompleted) {
            const p1KeyGenResult: IP1KeyGenResult = await p1KeyGen.processMessage(messageFromParty2);
            if (p1KeyGenResult.msg_to_send) {
                messageFromParty1 = p1KeyGenResult.msg_to_send;
            }
            if (p1KeyGenResult.p1_key_share) {
                p1KeyShare = p1KeyGenResult.p1_key_share;
                p1KeyGenCompleted = true;
            }
        }
        if (messageFromParty1 && (!p2KeyGenCompleted)) {
            const p2KeyGenResult: IP2KeyGenResult = await p2KeyGen.processMessage(messageFromParty1);
            if (p2KeyGenResult.msg_to_send) {
                messageFromParty2 = p2KeyGenResult.msg_to_send;
            }
            if (p2KeyGenResult.p2_key_share) {
                p2KeyShare = p2KeyGenResult.p2_key_share;
                p2KeyGenCompleted = true;
            }
        }
    }

    if (!(p1KeyShare && p2KeyShare)) {
        return null;
    }
    return {p1KeyShare, p2KeyShare};
}

async function keyGenTest() {
    const keyGenResult = await keyGen();
    if (!keyGenResult)
        return false;
    const {p1KeyShare, p2KeyShare} = keyGenResult;
    return p1KeyShare.public_key === p2KeyShare.public_key;
}

async function signTest() {
    const keyGenResult = await keyGen();
    if (!keyGenResult)
        return false;
    const {p1KeyShare, p2KeyShare} = keyGenResult;

    const signatureResult = await signature(p1KeyShare, p2KeyShare);
    if (!signatureResult)
        return false;
    const s1 = signatureResult.s1;
    const s2 = signatureResult.s2;

    return s1 === s2;
}

async function keyRefreshTest() {
    const keyGenResult = await keyGen();
    if (!keyGenResult)
        return false;
    const p1KeyShare = keyGenResult.p1KeyShare;
    const p2KeyShare = keyGenResult.p2KeyShare; ;

    const keyRefreshResult =await keyRefresh(p1KeyShare, p2KeyShare);
    if (!keyRefreshResult)
        return false;
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


test('KeyGen', async () => {
    const data = await keyGenTest();
    expect(data).toBe(true);
});

test('Signature', async () => {
    const data = await signTest();
    expect(data).toBe(true);
});

test('KeyRefresh', async () => {
    const data = await keyRefreshTest();
    expect(data).toBe(true);
});
