import * as jose from 'jose';
import { generateRsaKeyPair, signJwt, jwkToSpkiPem } from './crypto'; // Ensure jwkToSpkiPem is used
import { solveProofOfWork } from './pow';

/**
 * Configuration for the SlipkeyClient.
 */
export interface SlipkeyClientConfig {
  // Example: serverUrl?: string;
  // For now, no specific configuration is needed by the client's core logic.
}

export class SlipkeyClient {
  private privateKeyJwk!: jose.JWK; // Definite assignment assertion
  private publicKeyJwk!: jose.JWK;  // Definite assignment assertion
  private pemPublicKey!: string;    // Definite assignment assertion

  public state: string | null = null;

  // Private constructor to enforce instantiation via the static factory method.
  private constructor(config?: SlipkeyClientConfig) {
    // Configuration options can be used here if provided.
  }

  /**
   * Initializes the client's cryptographic keys.
   * This method is called by the static factory `create`.
   */
  private async _initializeAndCacheKeys(): Promise<void> {
    const keyPair = await generateRsaKeyPair();
    this.privateKeyJwk = keyPair.privateKey;
    this.publicKeyJwk = keyPair.publicKey;
    this.pemPublicKey = await jwkToSpkiPem(this.publicKeyJwk); // Use renamed function
  }

  /**
   * Creates and initializes a new SlipkeyClient instance.
   * @param config Optional configuration for the client.
   * @returns A promise that resolves to an initialized SlipkeyClient instance.
   */
  public static async create(config?: SlipkeyClientConfig): Promise<SlipkeyClient> {
    const client = new SlipkeyClient(config);
    await client._initializeAndCacheKeys();
    return client;
  }

  /**
   * Returns the client's public key in PEM format.
   * Throws an error if the key is not yet initialized (e.g., client not created via `create()`).
   * @returns The public key in PEM format.
   */
  public getPublicKey(): string {
    if (!this.pemPublicKey) {
      // This case should ideally not be reachable if instances are only created via `create()`
      throw new Error('Client not fully initialized. PEM Public key not available.');
    }
    return this.pemPublicKey;
  }

  /**
   * Returns the client's public key in JWK format.
   * Throws an error if the key is not yet initialized.
   * @returns The public key in JWK format.
   */
  public getPublicJwk(): jose.JWK {
    if (!this.publicKeyJwk) {
      throw new Error('Client not fully initialized. Public JWK not available.');
    }
    return this.publicKeyJwk;
  }

  /**
   * Generates the "slip" by solving a proof-of-work challenge and preparing claims.
   *
   * @param blockTimestamp The target block timestamp (ISO 8601 format string).
   * @param targetScore The PoW target score. Defaults to 1.
   * @param currentServerStateOverride Optional JWT from the server, overrides internal client state if provided.
   * @returns A promise that resolves to an object containing slip claims and PoW results,
   *          or null if PoW fails.
   */
  public async generateSlip(
    blockTimestamp: string,
    targetScore: number = 1,
    currentServerStateOverride?: string | null // Optional: can be undefined, null, or a string
  ): Promise<{ slipClaims: object; actualScore: number; nonce: string; hash: string } | null> {
    if (!this.pemPublicKey || !this.publicKeyJwk) {
      // This check ensures _initializeAndCacheKeys has completed.
      throw new Error('Client not fully initialized. Keys not available.');
    }

    // Determine the state to use for PoW:
    // 1. If currentServerStateOverride is explicitly provided (even if null), use it.
    // 2. Otherwise, use the client's internal state.
    const stateForPow = currentServerStateOverride !== undefined ? currentServerStateOverride : this.state;

    const powResult = await solveProofOfWork(
      this.pemPublicKey,
      blockTimestamp,
      stateForPow, // Pass null if that's the determined state
      targetScore
      // maxIterations can be added if needed, defaults in solveProofOfWork
    );

    if (!powResult) {
      return null; // PoW failed
    }

    const createFlag = stateForPow === null;

    const slipClaims = {
      pubkey: this.publicKeyJwk, // Client's public key in JWK format for the JWT
      block: blockTimestamp,     // Block identifier (timestamp)
      nonce: powResult.nonce,
      state: stateForPow,        // State used for PoW (null if creating new)
      create: createFlag,
    };

    return {
      slipClaims,
      actualScore: powResult.score,
      nonce: powResult.nonce,
      hash: powResult.hash,
    };
  }

  /**
   * Creates a client token (JWT) by signing the provided slip claims.
   *
   * @param slipClaims The slip claims object (intended as JWT payload).
   * @returns A promise that resolves to the signed JWT string.
   */
  public async createClientToken(slipClaims: object): Promise<string> {
    if (!this.privateKeyJwk) {
      throw new Error('Client not fully initialized. Private key not available.');
    }
    const payload = slipClaims as jose.JWTPayload;
    return signJwt(payload, this.privateKeyJwk);
  }

  /**
   * Processes the server's response and updates the client's internal state.
   *
   * @param serverResponse The server's response object, expected to have a `state` property (the new JWT).
   */
  public processServerResponse(serverResponse: { state: string; [key: string]: any }): void {
    this.state = serverResponse.state;
  }
}
