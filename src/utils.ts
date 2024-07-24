// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

import * as secp from "@noble/secp256k1";
import * as paillier from "paillier-bigint";
import { gcd, modPow, randBetween, randBytes } from "bigint-crypto-utils";
import { IPaillierPrivateKey } from "./ecdsa/P1KeyShare";
import {Buffer} from 'buffer'

export async function sha256(arr: Uint8Array) {
	return await secp.utils.sha256(arr);
}

///// Conversions
export function stringToUint8Array(s: string): Uint8Array {
	return Uint8Array.from(Buffer.from(s, "utf8"));
}

export function hexToUint8Array(hexString: string): Uint8Array {
	return Uint8Array.from(Buffer.from(hexString, "hex"));
}

export function Uint8ArrayToHex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}

export function Uint8ArrayTob64(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64");
}

export function b64ToUint8Array(str: string): Uint8Array {
	return Uint8Array.from(Buffer.from(str, "base64"));
}

// bigint

export function bigintToUint8Array(num: bigint, order?: number): Uint8Array {
	if (order) {
		const width = order * 2; // i.e. width * 8 / 4
		const hex = bigintToHex(num).padStart(width, "0");
		return hexToUint8Array(hex);
	} else {
		let hex = bigintToHex(num);
		if (hex.length % 2) {
			hex = `0${hex}`;
		}
		return hexToUint8Array(hex);
	}
}

export function Uint8ArraytoBigint(arr: Uint8Array): bigint {
	return hexToBigint(Uint8ArrayToHex(arr));
}

export function b64ToBigint(str: string): bigint {
	return Uint8ArraytoBigint(b64ToUint8Array(str));
}

export function bigintTob64(num: bigint): string {
	return Uint8ArrayTob64(bigintToUint8Array(num));
}

export function bigintToHex(num: bigint): string {
	return num.toString(16);
}

export function hexToBigint(hex: string): bigint {
	return BigInt(`0x${hex}`);
}

// Point

export function pointToBytes(point: secp.Point): Uint8Array {
	// The noble-secp256k1 library adds a '0x04' byte at the start. We remove that through slice.
	return point.toRawBytes().slice(1);
}

export function b64ToPoint(str: string): secp.Point {
	const b = Uint8Array.from(Buffer.from(str, "base64"));
	const bytes = new Uint8Array(b.length + 1);
	for (let i = 0; i < b.length; i++) {
		bytes[i + 1] = b[i];
	}
	bytes[0] = 4;
	return secp.Point.fromHex(bytes);
}

export function pointTob64(point: secp.Point): string {
	// The noble-secp256k1 library adds a '0x04' byte at the start. We remove that through slice.
	return Uint8ArrayTob64(pointToBytes(point));
}

export function hexToPoint(hex: string): secp.Point {
	// adding '04' to start
	return secp.Point.fromHex(`04${hex}`);
}

export function pointToHex(point: secp.Point): string {
	// removing the '04' from start
	return point.toHex().slice(2);
}

export function paillierPublickeyFromStr(str: string): paillier.PublicKey {
	const n = b64ToBigint(str);
	return new paillier.PublicKey(n, n + BigInt(1));
}

export function paillierPublickeyToStr(publicKey: paillier.PublicKey): string {
	return bigintTob64(publicKey.n);
}

export function paillierPrivateKeyFromObj(
	key: IPaillierPrivateKey,
): paillier.PrivateKey {
	const p = b64ToBigint(key.p);
	const q = b64ToBigint(key.q);
	const n = p * q;
	const lambda = (p - BigInt(1)) * (q - BigInt(1));
	const mu = bigintModInv(lambda, n);
	const paillierPublicKey = new paillier.PublicKey(n, n + BigInt(1));
	return new paillier.PrivateKey(lambda, mu, paillierPublicKey, p, q);
}

export function paillierPrivateKeyToObj(privateKey: paillier.PrivateKey) {
	// @ts-ignore
	const p = privateKey._p;
	// @ts-ignore
	const q = privateKey._q;
	return {
		p: bigintTob64(p),
		q: bigintTob64(q),
	};
}

export function paillierEncryptedNumberFromStr(str: string): bigint {
	return b64ToBigint(str);
}

export function paillierEncryptedNumberToStr(num: bigint): string {
	return bigintTob64(num);
}

// signature

export function signatureToHex(r: bigint, s: bigint, order = 32) {
	return (
		Uint8ArrayToHex(bigintToUint8Array(r, order)) +
		Uint8ArrayToHex(bigintToUint8Array(s, order))
	);
}

export async function verifySignature(
	messageHash: Uint8Array,
	publicKey: secp.Point,
	signature: string,
) {
	// The noble-secp256k1 library requires that we manually hash the message
	return secp.verify(signature, messageHash, publicKey);
}

//// Math operations

export function bigintModPow(b: bigint, e: bigint, n: bigint): bigint {
	return modPow(b, e, n);
}

export function bigintModInv(a: bigint, n: bigint): bigint {
	return modPow(a, -1, n);
}

export function bigintGcd(a: bigint, b: bigint): bigint {
	return gcd(a, b);
}

export function modPositive(a: bigint, b: bigint): bigint {
	return ((a % b) + b) % b;
}

//// utility

export function concatUint8Arrays(arr: Uint8Array[]) {
	// Get the total length of all arrays.
	let length = 0;
	arr.forEach((item) => {
		length += item.length;
	});
	// Create a new array with total length and merge all source arrays.
	const mergedArray = new Uint8Array(length);
	let offset = 0;
	arr.forEach((item) => {
		mergedArray.set(item, offset);
		offset += item.length;
	});
	return mergedArray;
}

export function comparePaillierPublicKey(
	key1: paillier.PublicKey,
	key2: paillier.PublicKey,
) {
	return key1.n === key2.n && key1.g === key2.g;
}

export function compareArrays(arr1: bigint[], arr2: bigint[]) {
	let arraycomparison = false;
	if (arr1.length === arr2.length) {
		arraycomparison = true;
		for (let i = 0; i < arr1.length; i++) {
			if (arr1[i] !== arr2[i]) {
				arraycomparison = false;
			}
		}
	}
	return arraycomparison;
}

export function checkOwnKeys(keys: string[], object: object) {
	return keys.every((key) => object.hasOwnProperty(key));
}

//// random

export async function randomNum(n = 32): Promise<bigint> {
	return Uint8ArraytoBigint(await randBytes(n));
	// return Uint8ArraytoBigint(crypto.getRandomValues(new Uint8Array(n)));
}

export function randBelow(num: bigint) {
	return randBetween(BigInt(num) - BigInt(1), BigInt(1));
}

export function randomCurveScalar(): bigint {
	return randBelow(secp.CURVE.n);
}
