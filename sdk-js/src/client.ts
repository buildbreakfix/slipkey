import * as jose from 'jose';
import { generateRsaKeyPair, signJwt, jwkToSpkiPem } from './crypto';
import { solveProofOfWork } from './pow';

export interface SlipkeyClientConfig {
  defaultTargetScore?: number;
  defaultBlockSizeMs?: number;
  initialPrivateKeyJwk?: jose.JWK;
}

export class SlipkeyClient {
  private privateKeyJwk!: jose.JWK;
  private publicKeyJwk!: jose.JWK;
  private pemPublicKey!: string;

  public state: string | null = null;

  private defaultTargetScore: number = 1;
  private defaultBlockSizeMs: number = 60000; // 1 minute

  private constructor() {
  }

  public exportPrivateKeyJwk(): jose.JWK {
    if (!this.privateKeyJwk) {
      throw new Error('Client not fully initialized. Private key not available.');
    }
    return JSON.parse(JSON.stringify(this.privateKeyJwk));
  }

  private async _initializeAndCacheKeys(config?: SlipkeyClientConfig): Promise<void> {
    const initialPrivateKeyJwk = config?.initialPrivateKeyJwk;
    if (initialPrivateKeyJwk) {
      if (!initialPrivateKeyJwk.d || !initialPrivateKeyJwk.n || !initialPrivateKeyJwk.e || !initialPrivateKeyJwk.kty) {
          throw new Error("Provided initialPrivateKeyJwk is incomplete or not a valid RSA private key.");
      }
      this.privateKeyJwk = { ...initialPrivateKeyJwk }; // Use a copy
      if (!this.privateKeyJwk.alg) {
        this.privateKeyJwk.alg = 'RS256';
      }

      this.publicKeyJwk = {
          kty: this.privateKeyJwk.kty,
          n: this.privateKeyJwk.n,
          e: this.privateKeyJwk.e,
          alg: this.privateKeyJwk.alg, // Should be set now
      };
    } else {
      const keyPair = await generateRsaKeyPair();
      this.privateKeyJwk = keyPair.privateKey; // Already has alg: 'RS256' from generateRsaKeyPair
      this.publicKeyJwk = keyPair.publicKey;   // Already has alg: 'RS256'
    }
    this.pemPublicKey = await jwkToSpkiPem(this.publicKeyJwk);
  }

  public static async create(config?: SlipkeyClientConfig): Promise<SlipkeyClient> {
    const client = new SlipkeyClient();
    await client._initializeAndCacheKeys(config);

    client.defaultTargetScore = config?.defaultTargetScore ?? client.defaultTargetScore;
    client.defaultBlockSizeMs = config?.defaultBlockSizeMs ?? client.defaultBlockSizeMs;

    return client;
  }

  public getPublicKey(): string {
    if (!this.pemPublicKey) {
      throw new Error('Client not fully initialized. PEM Public key not available.');
    }
    return this.pemPublicKey;
  }

  public getPublicJwk(): jose.JWK {
    if (!this.publicKeyJwk) {
      throw new Error('Client not fully initialized. Public JWK not available.');
    }
    // Defensively ensure 'alg' is present on the returned JWK.
    // It should be set during _initializeAndCacheKeys from either generateRsaKeyPair or derived from initialPrivateKeyJwk.
    return {
        ...this.publicKeyJwk,
        alg: this.publicKeyJwk.alg || 'RS256'
    };
  }

  public async generateSlip(
    blockTimestampOrBlockSizeMs?: string | number,
    targetScore?: number,
    currentServerStateOverride?: string | null
  ): Promise<{ slipClaims: object; actualScore: number; nonce: string; hash: string; token: string } | null> {
    if (!this.pemPublicKey || !this.publicKeyJwk || !this.privateKeyJwk) { // Added privateKeyJwk check for robustness
      throw new Error('Client not fully initialized. Keys not available.');
    }

    const stateForPow = currentServerStateOverride !== undefined ? currentServerStateOverride : this.state;

    let actualBlockTimestamp: string;
    if (typeof blockTimestampOrBlockSizeMs === 'string') {
      actualBlockTimestamp = blockTimestampOrBlockSizeMs;
    } else if (typeof blockTimestampOrBlockSizeMs === 'number') {
      actualBlockTimestamp = new Date(Date.now() + blockTimestampOrBlockSizeMs).toISOString();
    } else {
      actualBlockTimestamp = new Date(Date.now() + this.defaultBlockSizeMs).toISOString();
    }

    const actualTargetScore = targetScore ?? this.defaultTargetScore;

    const powResult = await solveProofOfWork(
      this.pemPublicKey,
      actualBlockTimestamp,
      stateForPow,
      actualTargetScore
    );

    if (powResult) {
      const finalPowInputClient = `${this.pemPublicKey}${actualBlockTimestamp}${stateForPow === null ? '' : stateForPow}${powResult.nonce}`;
      console.log(`[CLIENT PoW INPUT]: "${finalPowInputClient}" (Score: ${powResult.score}, Hash: ${powResult.hash})`);
    } else {
      return null; // PoW failed
    }

    const createFlag = stateForPow === null;

    const slipClaims = {
      pubkey: this.getPublicJwk(), // Use getter to ensure consistent JWK (with alg)
      block: actualBlockTimestamp,
      nonce: powResult.nonce,
      state: stateForPow,
      create: createFlag,
    };

    const token = await signJwt(slipClaims as jose.JWTPayload, this.privateKeyJwk); // Corrected to signJwt

    return {
      slipClaims,
      actualScore: powResult.score,
      nonce: powResult.nonce,
      hash: powResult.hash,
      token: token,
    };
  }

  public processServerResponse(serverResponse: { state: string; [key: string]: any }): void {
    this.state = serverResponse.state;
  }

  public updateDefaults(newDefaults: { defaultTargetScore?: number; defaultBlockSizeMs?: number }): void {
    if (newDefaults.defaultTargetScore !== undefined) {
      if (newDefaults.defaultTargetScore > 0) {
        this.defaultTargetScore = newDefaults.defaultTargetScore;
      } else {
        console.warn(`Invalid defaultTargetScore provided: ${newDefaults.defaultTargetScore}. Must be positive. Retaining existing value: ${this.defaultTargetScore}.`);
      }
    }

    if (newDefaults.defaultBlockSizeMs !== undefined) {
      if (newDefaults.defaultBlockSizeMs > 0) {
        this.defaultBlockSizeMs = newDefaults.defaultBlockSizeMs;
      } else {
        console.warn(`Invalid defaultBlockSizeMs provided: ${newDefaults.defaultBlockSizeMs}. Must be positive. Retaining existing value: ${this.defaultBlockSizeMs}.`);
      }
    }
  }
}
