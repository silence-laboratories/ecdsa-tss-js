// Copyright (c) Silence Laboratories Pte. Ltd.
// This software is licensed under the Silence Laboratories License Agreement.

export class KeyGenFailed extends Error {
	constructor(message: string) {
		super(message);
		this.name = "KeyGenFailed";
	}
}
