// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

import { performKeygen } from "./utils";

performKeygen()
  .then((keyshares) => {
    if (!keyshares) {
      throw new Error("Failed to generate keyshares");
    }
    console.log("P1 keyshare pubkey:", "0x" + keyshares[0].public_key);
    console.log("P2 keyshare pubkey:", "0x" + keyshares[1].public_key);
  })
  .catch((error) => {
    console.log(error);
  });
