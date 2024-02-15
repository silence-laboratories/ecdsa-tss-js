// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

export class DLogStatement {
	N: bigint;
	g: bigint;
	ni: bigint;

	constructor(N: bigint, g: bigint, ni: bigint) {
		this.N = N;
		this.g = g;
		this.ni = ni;
	}
}
