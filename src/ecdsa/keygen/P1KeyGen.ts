import {KeyGenMessage1} from "./KeyGenMessage1";
import {KeyGenMessage2} from "./KeyGenMessage2";
import {KeyGenMessage3} from "./KeyGenMessage3";
import {createCommitment} from "../../zkProofs/hashCommitment"
import NICorrectKeyProof from "../../zkProofs/NICorrectKeyProof";
import PDLProof from "../../zkProofs/pDLProof/PDLProof";
import DLogProof from "../../zkProofs/DLogProof";
import * as utils from "../../utils";
import {IP1KeyShare, P1KeyShare} from "../P1KeyShare";
import * as secp from "@noble/secp256k1";
import * as paillier from 'paillier-bigint';
import {KeyGenFailed} from "./KeyGenFailed";
import {PARTY_ID_1, PARTY_ID_2} from "../common";
import {KeyPair} from "paillier-bigint";


export interface IP1KeyGenResult {
	msg_to_send: string,
	p1_key_share: IP1KeyShare | null
}

enum P1KeyGenState {
    COMPLETE = 0,
    FAILED = -1,
	NOT_INITIALIZED = -2,
    CREATE_KEY_GEN_MSG_1 = 1,
    PROCESS_KEY_GEN_MSG_2 = 2
}

export class P1KeyGen {
	static G = secp.Point.BASE;
	static q = secp.CURVE.n;

    sessionId: string;
	x1: bigint;
	paillierPublicKey: paillier.PublicKey | any;
	paillierPrivateKey: paillier.PrivateKey | any;
	q1: secp.Point | any;
	dLogProof1: DLogProof | any;
	blindFactor1: bigint | any;
	eph1: bigint | any;
	e1: secp.Point | any;
	dLogProof2: DLogProof | any;
	blindFactor2: bigint | any;
	paillierKeyPairForProof: KeyPair | any;
	expectedPublicKey?: string;
	_state: P1KeyGenState;

    constructor(sessionId: string, x1?: Uint8Array, expectedPublicKey?: string) {
        this.sessionId = sessionId;
        this.expectedPublicKey = expectedPublicKey;
		if (x1) {
			if (x1.length !== 32) {
				throw new KeyGenFailed('Invalid length of x1');
			}
			this.x1 = utils.modPositive(utils.Uint8ArraytoBigint(x1), P1KeyGen.q);
		}
		else {
			this.x1 = utils.randomCurveScalar();
		}
        this._state = P1KeyGenState.NOT_INITIALIZED;
    }

	static getInstanceForKeyRefresh(sessionId: string, p1KeyShareObj: IP1KeyShare) {
		const p1KeyShare = P1KeyShare.fromObj(p1KeyShareObj);
		const expectedPublicKey = utils.pointToHex(p1KeyShare.publicKey);
		const x1Uint8Array = utils.bigintToUint8Array(p1KeyShare.x1);
		return new P1KeyGen(sessionId, x1Uint8Array, expectedPublicKey);
	}

	async init(keyPair1?: KeyPair, keyPair2?: KeyPair) {
		if (keyPair1 && keyPair2) {
			this.paillierPrivateKey = keyPair1.privateKey;
			this.paillierPublicKey = keyPair1.publicKey;
			this.paillierKeyPairForProof = keyPair2;
		}
		else {
			const [paillierKeyPair, paillierKeyPairForProof] = await Promise.all([
				paillier.generateRandomKeys(2048, true),
				paillier.generateRandomKeys(2048, true)
			]);
			this.paillierPrivateKey = paillierKeyPair.privateKey;
			this.paillierPublicKey = paillierKeyPair.publicKey;
			this.paillierKeyPairForProof = paillierKeyPairForProof;
		}
		this._state = P1KeyGenState.CREATE_KEY_GEN_MSG_1;
	}

    isActive(): boolean {
		const cond1 = this._state !== P1KeyGenState.NOT_INITIALIZED;
		const cond2 = this._state !== P1KeyGenState.FAILED;
		const cond3 = this._state !== P1KeyGenState.COMPLETE;
        return cond1 && cond2 && cond3;
    }

	async getKeyGenMessage1(): Promise<KeyGenMessage1> {
		if (this._state !== P1KeyGenState.CREATE_KEY_GEN_MSG_1) {
			this._state = P1KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid state');
		}

		this.q1 = P1KeyGen.G.multiply(this.x1);
		this.dLogProof1 = await DLogProof.prove(this.x1, this.q1, this.sessionId, PARTY_ID_1);
		this.blindFactor1 = await utils.randomNum(32);
		const commitment1 = await createCommitment(
			this.q1, this.dLogProof1, this.blindFactor1, this.sessionId, PARTY_ID_1
		);

		this.eph1 = utils.randomCurveScalar();
		this.e1 = P1KeyGen.G.multiply(this.eph1);
		this.dLogProof2 = await DLogProof.prove(this.eph1, this.e1, this.sessionId, PARTY_ID_1);
		this.blindFactor2 = await utils.randomNum(32);
		const commitment2 = await createCommitment(
			this.e1, this.dLogProof2, this.blindFactor2, this.sessionId, PARTY_ID_1
		);

		const keyGenMessage1 = new KeyGenMessage1(
			this.sessionId,
			commitment1,
			commitment2
		);
		this._state = P1KeyGenState.PROCESS_KEY_GEN_MSG_2;
		return keyGenMessage1;
	}

    async _processKeyGenMessage2(keyGenMessage2: KeyGenMessage2):
		Promise<{ key_gen_msg_3: KeyGenMessage3; p1_key_share: P1KeyShare }> {
        if (this._state !== P1KeyGenState.PROCESS_KEY_GEN_MSG_2) {
			this._state = P1KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid state');
        }
		if (this.sessionId !== keyGenMessage2.sessionId) {
			this._state = P1KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid sessionId');
		}

		const q2 = keyGenMessage2.q2;
		const dLogProof1 = keyGenMessage2.dLogProof1;
		if (!(await dLogProof1.verify(q2, this.sessionId, PARTY_ID_2))) {
			this._state = P1KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid dLogProof1');
		}

		const publicKey = q2.multiply(this.x1);
		if (this.expectedPublicKey !== undefined) {
			if (this.expectedPublicKey !== utils.pointToHex(publicKey)) {
				this._state = P1KeyGenState.FAILED;
				throw new KeyGenFailed('Invalid publicKey');
			}
		}

		const e2 = keyGenMessage2.e2;
		const dLogProof2 = keyGenMessage2.dLogProof2;
		if (!(await dLogProof2.verify(e2, this.sessionId, PARTY_ID_2))) {
			this._state = P1KeyGenState.FAILED;
			throw new KeyGenFailed('Invalid dLogProof2');
		}
		// rotate private share x1 to rotateValue1
		const ephPoint = e2.multiply(this.eph1);
		const rotateValue1 = ephPoint.x;
		this.x1 = utils.modPositive(this.x1 * rotateValue1, P1KeyGen.q);

		const nICorrectKeyProof = await NICorrectKeyProof.prove(this.paillierPrivateKey, this.sessionId, PARTY_ID_1);
		const randomness = utils.randBelow(this.paillierPublicKey.n);
		const cKeyX1 = this.paillierPublicKey.encrypt(this.x1, randomness);
		const { pdl_w_slack_statement, pdl_w_slack_proof, composite_dlog_proof } =
			await PDLProof.prove(
				this.x1, randomness, this.paillierPublicKey, cKeyX1, this.sessionId, PARTY_ID_1,
				this.paillierKeyPairForProof
			);

		const keyGenMessage3 = await new KeyGenMessage3(
			this.sessionId,
			this.q1,
			this.dLogProof1,
			this.blindFactor1,
			cKeyX1,
			this.paillierPublicKey,
			nICorrectKeyProof,
			pdl_w_slack_statement,
			pdl_w_slack_proof,
			composite_dlog_proof,
			this.e1,
			this.dLogProof2,
			this.blindFactor2,
		);

		const keyShare = new P1KeyShare(
			this.x1, publicKey, this.paillierPrivateKey, this.paillierPublicKey
		);

		this._state = P1KeyGenState.COMPLETE;
		return {
			key_gen_msg_3: keyGenMessage3,
			p1_key_share: keyShare
		};
    }

	async processMessage(messageString: string | null): Promise<IP1KeyGenResult> {
		if (!this.isActive()) {
			throw new KeyGenFailed('KeyGen was already Completed or Failed');
		}

		if (messageString == null) {
			const keyGenMessage1 = await this.getKeyGenMessage1();
			return {
				msg_to_send: keyGenMessage1.toStr(),
				p1_key_share: null
			};
		}

        const messageObj = JSON.parse(messageString);
        const messageSessionId = messageObj.session_id;
        if (this.sessionId !== messageSessionId)
            throw new Error('Invalid sessionId');

		try {
			if (this._state === P1KeyGenState.PROCESS_KEY_GEN_MSG_2) {
				const keyGenMessage2 = KeyGenMessage2.fromStr(messageString);
				const {key_gen_msg_3, p1_key_share} = await this._processKeyGenMessage2(keyGenMessage2);
				return {
					msg_to_send: key_gen_msg_3.toStr(),
					p1_key_share: p1_key_share.toObj()
				};
			}
		}
		catch (e) {
			this._state = P1KeyGenState.FAILED;
			throw e;
		}

		this._state = P1KeyGenState.FAILED;
		throw new KeyGenFailed('');
	}

}
