import { ethers } from "ethers";

import * as tss from "ecdsa-tss";
import { generateSign, performKeygen } from "./tss";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import {
	Signer,
	TypedDataDomain,
	TypedDataField,
	TypedDataSigner,
} from "@ethersproject/abstract-signer";
import { keccak256 } from "@ethersproject/keccak256";
import {
	BytesLike,
	hexZeroPad,
	joinSignature,
	Signature,
	splitSignature,
} from "@ethersproject/bytes";
import { resolveProperties } from "@ethersproject/properties";
import { getAddress } from "@ethersproject/address";
import { serialize, UnsignedTransaction } from "@ethersproject/transactions";
import { _TypedDataEncoder } from "@ethersproject/hash";
import { assert } from "console";

export async function main() {
	const provider = new ethers.providers.JsonRpcProvider(
		"http://127.0.0.1:8545",
	);

	let accounts;

	try {
		accounts = await provider.listAccounts();
	} catch (error) {
		if (error instanceof Error) {
			if (error.message.includes("ECONNREFUSED"))
				console.log(
					"Please start a local blockchain node (e.g foundry's anvil or ganache-cli in localhost) and try again.",
				);
		}
	}

	if (!accounts) return;

	console.log(accounts);

	const user = provider.getSigner(accounts[0]);

	console.log("User: ", await user.getAddress());

	const silentSigner = (await SilentWallet.generate()).connect(provider);
	const addr = await silentSigner.getAddress();

	const txn1 = await user.sendTransaction({
		to: await silentSigner.getAddress(),
		value: ethers.utils.parseEther("10.0"),
	});

	await txn1.wait();

	console.log("Funded silent wallet");
	const balance = await silentSigner.getBalance();
	console.log("Balance before: ", balance.toString());

	const txn2 = await silentSigner.sendTransaction({
		to: accounts[0],
		value: ethers.utils.parseEther("1.0"),
	});

	const receipt = await txn2.wait();
	console.log("Transaction receipt: ", receipt);

	console.log("Balance after: ", (await silentSigner.getBalance()).toString());

	const signedMsg = await silentSigner.signMessage(Buffer.from("Hello World"));
	const recovered = ethers.utils.recoverAddress(
		getKeccakHash(Buffer.from("Hello World")),
		signedMsg,
	);
	assert(recovered === addr, "Signature does not match");
}

main().catch((error) => {
	console.log(error);
	process.exitCode = 0;
});

// extends Signer implements TypedDataSigner
class SilentWallet extends Signer implements TypedDataSigner {
	public address: string;
	public public_key: string;
	private keyshares: [tss.IP1KeyShare, tss.IP2KeyShare];
	readonly provider?: ethers.providers.Provider;

	constructor(
		address: string,
		public_key: string,
		keyshares: [tss.IP1KeyShare, tss.IP2KeyShare],
		provider?: Provider,
	) {
		super();
		this.address = address;
		this.public_key = public_key;
		this.keyshares = keyshares;
		this.provider = provider;
	}

	public static async generate(): Promise<SilentWallet> {
		const keyshares = await performKeygen();
		if (!keyshares) {
			throw new Error("Failed to generate keyshares");
		}

		const publicKey = keyshares[0].public_key;
		const address = ethers.utils.computeAddress(`0x04${publicKey}`);
		return new SilentWallet(address, publicKey, keyshares);
	}

	async getAddress(): Promise<string> {
		return this.address;
	}

	async signMessage(message: ethers.utils.Bytes): Promise<string> {
		return joinSignature(await this.signDigest(keccak256(message)));
	}
	async signTransaction(transaction: TransactionRequest): Promise<string> {
		return resolveProperties(transaction).then(async (tx) => {
			if (tx.from != null) {
				if (getAddress(tx.from) !== this.address) {
					throw new Error(
						`transaction from address mismatch (from:${tx.from} address:${this.address})`,
					);
				}
				tx.from = undefined;
			}
			console.log("serialized txn", serialize(<UnsignedTransaction>tx));

			const signature = await this.signDigest(
				keccak256(serialize(<UnsignedTransaction>tx)),
			);

			return serialize(<UnsignedTransaction>tx, signature);
		});
	}

	public async signDigest(digest: BytesLike): Promise<Signature> {
		const sign = await generateSign(
			this.keyshares[0],
			this.keyshares[1],
			digest,
		);

		const signBytes = Buffer.from(sign[0], "hex");
		const r = signBytes.subarray(0, 32);
		const s = signBytes.subarray(32, 64);
		const recid = sign[1];
		// const recid = getRecoveryId(arrayify(digest), r, s, this.public_key);

		return splitSignature({
			recoveryParam: recid,
			r: hexZeroPad(`0x${r.toString("hex")}`, 32),
			s: hexZeroPad(`0x${s.toString("hex")}`, 32),
		});
	}

	connect(provider: Provider): SilentWallet {
		return new SilentWallet(
			this.address,
			this.public_key,
			this.keyshares,
			provider,
		);
	}
	async _signTypedData(
		domain: TypedDataDomain,
		types: Record<string, Array<TypedDataField>>,
		// rome-ignore lint/suspicious/noExplicitAny: Etherjs uses any
		value: Record<string, any>,
	): Promise<string> {
		// Populate any ENS names
		const populated = await _TypedDataEncoder.resolveNames(
			domain,
			types,
			value,
			//@ts-ignore
			(name: string) => {
				if (this.provider == null) {
					throw new Error("cannot resolve ENS names without a provider");
				}
				return this.provider.resolveName(name);
			},
		);

		return joinSignature(
			await this.signDigest(
				_TypedDataEncoder.hash(populated.domain, types, populated.value),
			),
		);
	}
}

function getKeccakHash(message: ethers.utils.Bytes): Uint8Array {
	return Buffer.from(keccak256(message).slice(2), "hex");
}
