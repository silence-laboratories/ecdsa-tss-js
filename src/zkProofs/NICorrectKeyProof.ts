import * as paillier from 'paillier-bigint';
import * as utils from '../utils';

export default class NICorrectKeyProof {
  static requiredFields = ['sigma_vec'];
  static salt = 'SilenceLaboratories';
  static M2 = BigInt(11);
  static DIGEST_SIZE = BigInt(256);
  static alphaPrimorial = BigInt(
    '44871651744009136248115543081640547413785854417842050160655833875792914833852769205831424979368719986889519256934239452438251108738670217298542180982547421007901019408155961940142468907900676141149633188172029947498666222471142795699128314649438784106402197023949268047384343715946006767671319388463922366703585708460135453240679421061304864609915827908896062350138633849514905858373339528086006145373712431756746905467935232935398951226852071323775412278763371089401544920873813490290672436809231516731065356763193493525160238868779310055137922174496115680527519932793977258424479253973670103634070028863591207614649216492780891961054287421831028229266989697058385612003557825398202548657910983931484180193293615175594925895929359108723671212631368891689462486968022029482413912928883488902454913524492340322599922718890878760895105937402913873414377276608236656947832307175090505396675623505955607363683869194683635689701238311577953994900734498406703176954324494694474545570839360607926610248093452739817614097197031607820417729009847465138388398887861935127785385309564525648905444610640901769290645369888935446477559073843982605496992468605588284307311971153579731703863970674466666844817336319390617551354845025116350295041840093627836067370100384861820888752358520276041000456608056339377573485917445104757987800101659688183150320442308091835974182809184299472568260682774683272697993855730500061223160274918361373258473553412704497335663924406111413972911417644029226449602417135116011968946232623154008710271296183350215563946003547561056456285939676838623311370087238225630994506113422922846572616538637723054222166159389475617214681282874373185283568512603887750846072033376432252677883915884203823739988948315257311383912016966925295975180180438969999175030785077627458887411146486902613291202008193902979800279637509789564807502239686755727063367075758492823731724669702442450502667810890608807091448688985203084972035197770874223259420649055450382725355162738490355628688943706634905982449810389530661328557381850782677221561924983234877936783136471890539395124220965982831778882400224156689487137227198030461624542872774217771594215907203725682315714199249588874271661233929713660269883273404764648327455796699366900022345171030564747210542398285078804310752063852249740561571105640741618793118627170070315410588646442647771802031066589341358879304845579387079972404386434238273904239604603511925708377008467129590636257287965232576327580009018475271364237665836186806027331208426256451429549641988386585949300254487647395222785274120561299318070944530096970076560461229486504018773252771360855091191876004370694539453020462096690084476681253865429278552786361828508910022714749051734108364178374765700925133405508684883070',
  );

  sigmaVec: bigint[];

  constructor(sigmaVec: bigint[]) {
    this.sigmaVec = sigmaVec;
  }

  static async _maskGeneration(outLength: bigint, seed: Uint8Array): Promise<bigint> {
    const mskLen = outLength / NICorrectKeyProof.DIGEST_SIZE + BigInt(1);
    const mskLenHashVec = [];
    for (let i = 0; i < mskLen; i++) {
      const data = [seed, utils.bigintToUint8Array(BigInt(i), 4)];
      const formattedData = utils.concatUint8Arrays(data);
      const h = await utils.sha256(formattedData);
      mskLenHashVec.push(new Uint8Array(h));
    }
    const msklenHashVecConcat = utils.concatUint8Arrays(mskLenHashVec);
    return utils.Uint8ArraytoBigint(msklenHashVecConcat);
  }

  static async _rhoVec(publicN: bigint, keyLength: number, sid: string, pid: string) {
    const resultVector: bigint[] = [];
    const sidBytes = utils.stringToUint8Array(sid);
    const pidBytes = utils.stringToUint8Array(pid);
    for (let i = 0; i < NICorrectKeyProof.M2; i++) {
      const encoder = new TextEncoder();
      const data = [
        utils.bigintToUint8Array(publicN),
        encoder.encode(NICorrectKeyProof.salt),
        utils.bigintToUint8Array(BigInt(i), 4),
        sidBytes,
        pidBytes,
      ];
      const formattedData = utils.concatUint8Arrays(data);
      const seedBn = await utils.sha256(formattedData);
      let value = await NICorrectKeyProof._maskGeneration(BigInt(keyLength), new Uint8Array(seedBn));
      value = utils.modPositive(value, publicN);
      resultVector.push(value);
    }
    return resultVector;
  }

  static _crtRecombine(rp: bigint, rq: bigint, p: bigint, q: bigint, pinv: bigint): bigint {
    const diff = utils.modPositive(rq - rp, q);
    const u = utils.modPositive(diff * pinv, q);
    const x = rp + u * p;
    return x;
  }

  static _extractNRoot(paillierPrivateKey: paillier.PrivateKey, value: bigint): bigint {
    // @ts-ignore
    const p: bigint = paillierPrivateKey._p;
    // @ts-ignore
    const q: bigint = paillierPrivateKey._q;
    const zp = utils.modPositive(value, p);
    const zq = utils.modPositive(value, q);

    const n = p * q;
    const pminusone = p - BigInt(1);
    const qminusone = q - BigInt(1);
    const phi = pminusone * qminusone;
    const dn = utils.bigintModInv(n, phi);
    const dp = utils.modPositive(dn, pminusone);
    const dq = utils.modPositive(dn, qminusone);
    const pinv = utils.bigintModInv(p, q);
    const rp = utils.bigintModPow(zp, dp, p);
    const rq = utils.bigintModPow(zq, dq, q);
    return NICorrectKeyProof._crtRecombine(rp, rq, p, q, pinv);
  }

  static async prove(paillierPrivateKey: paillier.PrivateKey, sid: string, pid: string) {
    const publicKey = paillierPrivateKey.publicKey;
    const publicN = publicKey.n;
    const keyLength = publicKey.bitLength;
    const rhoVec = await NICorrectKeyProof._rhoVec(publicN, keyLength, sid, pid);
    const sigmaVec: bigint[] = [];
    rhoVec.forEach((rhoValue) => {
      sigmaVec.push(NICorrectKeyProof._extractNRoot(paillierPrivateKey, rhoValue));
    });
    return new NICorrectKeyProof(sigmaVec);
  }

  async verify(paillierPublicKey: paillier.PublicKey, sid: string, pid: string) {
    const publicN = paillierPublicKey.n;
    const keyLength = paillierPublicKey.bitLength;
    const rhoVec = await NICorrectKeyProof._rhoVec(publicN, keyLength, sid, pid);
    const gcdTest = utils.bigintGcd(NICorrectKeyProof.alphaPrimorial, publicN);
    const derivedRhoVec: bigint[] = [];
    this.sigmaVec.forEach((item) => {
      derivedRhoVec.push(utils.bigintModPow(item, publicN, publicN));
    });
    const cond1 = utils.compareArrays(rhoVec, derivedRhoVec);
    const cond2 = gcdTest === BigInt(1);
    return cond1 && cond2;
  }

  toObj() {
    const sigmaVec: string[] = [];
    this.sigmaVec.forEach((item: bigint) => {
      sigmaVec.push(utils.bigintTob64(item));
    });
    return {
      sigma_vec: sigmaVec,
    };
  }

  toStr() {
    return JSON.stringify(this.toObj());
  }

  static fromObj(message: any) {
    if (!utils.checkOwnKeys(NICorrectKeyProof.requiredFields, message)) {
      throw new Error('NICorrectKeyProof object invalid');
    }
    const sigmaVec: bigint[] = [];
    message.sigma_vec.forEach((item: string) => {
      sigmaVec.push(utils.b64ToBigint(item));
    });
    return new NICorrectKeyProof(sigmaVec);
  }

  static fromStr(messageString: string) {
    const message = JSON.parse(messageString);
    return NICorrectKeyProof.fromObj(message);
  }
}
