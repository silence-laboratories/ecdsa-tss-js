# ECDSA secp256k1 TSS(2,2) JS library


## Actions
The library provides the following actions:
-   2-party ECDSA secp256k1: generation and signing
-   Key share refresh

## Benchmarking and Performance

Apple M1, 8GB RAM (node v18.4.0)
```
KeyGen no pre-generated Paillier keys x 0 ops/sec @ 1275ms/op ± 15.34% (min: 712ms, max: 2178ms)
KeyGen with pre-generated Paillier keys x 2 ops/sec @ 399ms/op
Signature x 10 ops/sec @ 98ms/op

RAM: rss=175.1mb heap=46.1mb used=22.6mb ext=0.9mb arr=0.5mb
```

Intel i5-6500, 32GB RAM (Windows 10, node v18.7.0)
```
KeyGen no pre-generated Paillier keys x 0 ops/sec @ 6209ms/op ± 16.78% (min: 3331ms, max: 10618ms)
KeyGen with pre-generated Paillier keys x 0 ops/sec @ 2025ms/op
Signature x 1 ops/sec @ 539ms/op

RAM: rss=68.5mb heap=30.4mb used=17.1mb ext=1.1mb arr=0.7mb
```

## Usage

`ecdsa-tss` can be installed from git repository:

```console
npm install git+https://gitlab.com/com.silencelaboratories/ecdsa-tss-js.git
```

Then either require (Node.js CommonJS):

```javascript
const ecdsaTSS = require('ecdsa-tss')
```

or import (JavaScript ES module):

```javascript
import * as ecdsaTSS from 'ecdsa-tss'
```

An example of KeyGen:

```javascript
import {
    P1KeyGen,
    P2KeyGen,
    IP1KeyShare,
    IP2KeyShare,
    randBytes,
    IP1KeyGenResult, IP2KeyGenResult
} from "ecdsa-tss";


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
```

An example of Sign:

```javascript
import {
    P1Signature,
    P2Signature,
    IP1KeyShare,
    IP2KeyShare,
    randBytes,
    IP1SignatureResult, IP2SignatureResult
} from "ecdsa-tss";


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
```

An example of Key Refresh:
```javascript
import {
    P1KeyGen,
    P2KeyGen,
    IP1KeyShare,
    IP2KeyShare,
    randBytes,
    IP1KeyGenResult, IP2KeyGenResult
} from "ecdsa-tss";


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
```
