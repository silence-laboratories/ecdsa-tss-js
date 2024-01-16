# ECDSA secp256k1 TSS(2,2) JS library

## Actions

The library provides the following actions:

- 2-party ECDSA secp256k1: generation and signing
- Key share refresh

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

## Installation

```bash
npm install @silencelaboratories/ecdsa-tss
```

Then either require (Node.js CommonJS):

```javascript
const ecdsaTSS = require("@silencelaboratories/ecdsa-tss");
```

or import (JavaScript ES module):

```javascript
import * as ecdsaTSS from "@silencelaboratories/ecdsa-tss";
```

An example of KeyGen:

```javascript
import {
  IP1KeyShare,
  IP2KeyShare,
  P1KeyGen,
  P2KeyGen,
  randBytes,
} from "@silencelaboratories/ecdsa-tss";

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
```

An example of Sign:

```javascript
import {
  P1Signature,
  P2Signature,
  IP1KeyShare,
  IP2KeyShare,
  randBytes,
  IP1SignatureResult,
  IP2SignatureResult,
} from "@silencelaboratories/ecdsa-tss";

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
```

An example of Key Refresh:

```javascript
import {
  P1KeyGen,
  P2KeyGen,
  IP1KeyShare,
  IP2KeyShare,
  randBytes,
  IP1KeyGenResult,
  IP2KeyGenResult,
} from "@silencelaboratories/ecdsa-tss";

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
    p1KeyShare.public_key
  );
}
```
