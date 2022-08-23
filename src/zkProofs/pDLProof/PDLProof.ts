import * as secp from "@noble/secp256k1";
import * as paillier from 'paillier-bigint';
import * as utils from '../../utils';
import { CompositeDLogProof } from '../wiDLogProof/CompositeDLogProof';
import { PDLwSlackProof } from './PDLwSlackProof';
import { PDLwSlackStatement } from './PDLwSlackStatement';
import { PDLwSlackWitness } from './PDLwSlackWitness';
import { DLogStatement } from '../wiDLogProof/DLogStatement';
import {KeyPair} from "paillier-bigint";

export default class PDLProof {
  static G = secp.Point.BASE;

  static async prove(
      x1: bigint,
      cKeyRandomness: bigint,
      ek: paillier.PublicKey,
      encryptedShare: bigint,
      sid: string,
      pid: string,
      keyPair: KeyPair
  ) {
    const { nTilde, h1, h2, xhi } = await generate_h1_h2_n_tilde(keyPair);
    const dLogStatement = new DLogStatement(nTilde, h1, h2);
    const compositeDLogProof = await CompositeDLogProof.prove(dLogStatement, xhi, sid, pid);

    // Generate PDL with slack statement, witness and proof
    const pDSwSlackStatement = new PDLwSlackStatement(
      encryptedShare,
      ek,
      PDLProof.G.multiply(x1),
      PDLProof.G,
      dLogStatement.g,
      dLogStatement.ni,
      dLogStatement.N,
    );

    const pDLwSlackWitness = new PDLwSlackWitness(x1, cKeyRandomness);

    const pDLwSlackProof = await PDLwSlackProof.prove(pDLwSlackWitness, pDSwSlackStatement, sid, pid);

    return {
      pdl_w_slack_statement: pDSwSlackStatement,
      pdl_w_slack_proof: pDLwSlackProof,
      composite_dlog_proof: compositeDLogProof,
    };
  }

  static async verify(
    compositeDLogProof: CompositeDLogProof,
    pDSwSlackStatement: PDLwSlackStatement,
    pDLwSlackProof: PDLwSlackProof,
    paillierPublicKey: paillier.PublicKey,
    encryptedSecretShare: bigint,
    q1: secp.Point,
    sid: string,
    pid: string
  ) {
    if (
      !utils.comparePaillierPublicKey(pDSwSlackStatement.ek, paillierPublicKey) ||
      pDSwSlackStatement.ciphertext !== encryptedSecretShare ||
      !pDSwSlackStatement.Q.equals(q1)
    ) {
      return false;
    }

    const dlogStatement = new DLogStatement(pDSwSlackStatement.nTilde, pDSwSlackStatement.h1, pDSwSlackStatement.h2);

    const cond1 = await compositeDLogProof.verify(dlogStatement, sid, pid);
    const cond2 = await pDLwSlackProof.verify(pDSwSlackStatement, sid, pid);
    return cond1 && cond2;
  }
}

async function generate_h1_h2_n_tilde(keyPair: KeyPair) {
  // const keyPair = await paillier.generateRandomKeys(2048, true);
  const ekTilde = keyPair.publicKey;
  const dkTilde = keyPair.privateKey;
  // @ts-ignore
  const phi = (dkTilde._p - BigInt(1)) * (dkTilde._q - BigInt(1));
  const h1 = utils.randBelow(phi);
  const s = BigInt(2) ** BigInt(256);
  const xhi = utils.randBelow(s);
  const h1Inv = utils.bigintModInv(h1, ekTilde.n);
  const h2 = utils.bigintModPow(h1Inv, xhi, ekTilde.n);
  const nTilde = ekTilde.n;
  return { nTilde, h1, h2, xhi };
}
