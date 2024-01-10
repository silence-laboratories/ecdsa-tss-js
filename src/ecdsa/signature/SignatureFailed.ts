export class SignatureFailed extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SignatureFailed";
	}
}
