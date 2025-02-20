import { httpbis, type SigningKey } from 'http-message-signatures';


import { createPublicKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { exportJWK, generateKeyPair, importJWK, JWK } from 'jose';

export type AsymmetricSigningAlgorithm =
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES256K'
  | 'ES384'
  | 'ES512'
  | 'EdDSA'
  | 'RS256'
  | 'RS384'
  | 'RS512';

export interface JWKS {
    keys: JWK[];
}

export interface AlgJwk extends JWK {
    alg: AsymmetricSigningAlgorithm;
}
  

const algMap = {
  'ES256': { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' },
  'ES384': { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' },
  'ES512': { name: 'ECDSA', namedCurve: 'P-512', hash: 'SHA-512' },
  'HS256': { name: 'HMAC', hash: 'SHA-256' },
  'HS384': { name: 'HMAC', hash: 'SHA-384' },
  'HS512': { name: 'HMAC', hash: 'SHA-512' },
  'PS256': { name: 'RSASSA-PSS', hash: 'SHA-256' },
  'PS384': { name: 'RSASSA-PSS', hash: 'SHA-384' },
  'PS512': { name: 'RSASSA-PSS', hash: 'SHA-512' },
  'RS256': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  'RS384': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  'RS512': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
}

/**
 * A {@link Fetcher} wrapper that signes requests. 
 */
export class SignedFetcher implements Fetcher {

  constructor(
    protected fetcher: Fetcher,
    protected baseUrl: string,
    protected keyGen: JwkGenerator, 
  ) {}

  public async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
    const jwk = await this.keyGen.getPrivateKey();

    const { alg, kid } = jwk;
    if (alg === 'EdDSA') throw new Error('EdDSA signing is not supported');
    if (alg === 'ES256K') throw new Error('ES256K signing is not supported');

    const key: SigningKey = {
      id: kid,
      alg: alg,
      async sign(data: BufferSource) {
        const params = algMap[alg];
        const key = await crypto.subtle.importKey('jwk', jwk, params, false, ['sign']);
        return Buffer.from(await crypto.subtle.sign(params, key, data));
      },
    };

    const url = input instanceof URL ? input.href : input instanceof Request ? input.url : input as string;

    const request = {
      ...init ?? {},
      url,
      method: init?.method ?? 'GET',
      headers: {} as Record<string, string>
    }
    ;
    new Headers(init?.headers).forEach((value, key) => request.headers[key] = value);
    request.headers['Authorization'] = `HttpSig cred="${this.baseUrl}"`;

    const signed = await httpbis.signMessage({ key, paramValues: { keyid: 'TODO' } }, request);
    
    return await this.fetcher.fetch(url, signed);
  }
}


/**
 * Shorthand for the parameters type of the Fetch API.
 */
export type FetchParams = Parameters<typeof fetch>;

/**
 * Any object implementing a fetch method adhering to the Fetch API signature.
 */
export interface Fetcher {
  fetch(...args: FetchParams): Promise<Response>;
};



/**
 * Generates a key pair once and then caches it using both an internal variable and a {@link KeyValueStorage}.
 * The storage makes sure the keys remain the same between server restarts,
 * while the internal variable makes it so the storage doesn't have to be accessed every time a key is needed.
 *
 * Only the private key is stored in the internal storage, using the `storageKey` parameter.
 * The public key is determined based on the private key and then also stored in memory.
 */
export class JwkGenerator {
  public readonly alg: AsymmetricSigningAlgorithm;

  private readonly key: string;
  private readonly storage: Map<string, JWKS>;

  private privateJwk?: AlgJwk;
  private publicJwk?: AlgJwk;

  public constructor(alg: AsymmetricSigningAlgorithm, storageKey: string, storage: Map<string, JWKS>) {
    this.alg = alg;
    this.key = storageKey;
    this.storage = storage;
  }

  public async getPrivateKey(): Promise<AlgJwk> {
    if (this.privateJwk) {
      return this.privateJwk;
    }

    // We store in JWKS format for backwards compatibility reasons.
    // If we want to just store the key instead we will need some way to do the migration.
    const jwks = await this.storage.get(this.key);
    if (jwks) {
      this.privateJwk = jwks.keys[0] as AlgJwk;
      return this.privateJwk;
    }

    const { privateKey } = await generateKeyPair(this.alg);

    // Make sure the JWK is a plain node object for storage
    const privateJwk = { ...await exportJWK(privateKey) } as AlgJwk;
    privateJwk.alg = this.alg;

    await this.storage.set(this.key, { keys: [ privateJwk ]});
    this.privateJwk = privateJwk;
    return privateJwk;
  }

  public async getPublicKey(): Promise<AlgJwk> {
    if (this.publicJwk) {
      return this.publicJwk;
    }

    const privateJwk = await this.getPrivateKey();

    // The main reason we generate the public key from the private key is, so we don't have to store it.
    // This allows our storage to not break previous versions where we only used the private key.
    // In practice this results in the same key.
    const privateKey = await importJWK(privateJwk);
    const publicKey = createPublicKey(privateKey as KeyObject);

    const publicJwk = { ...await exportJWK(publicKey) } as AlgJwk;
    // These fields get lost during the above proces
    publicJwk.alg = privateJwk.alg;

    this.publicJwk = publicJwk;

    return publicJwk;
  }
}