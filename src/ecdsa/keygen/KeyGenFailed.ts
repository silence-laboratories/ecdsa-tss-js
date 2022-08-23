export class KeyGenFailed extends Error {
    constructor(message: string) {
        super(message);
        this.name = "KeyGenFailed";
    }
}
