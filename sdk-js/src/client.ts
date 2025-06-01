import * as jose from 'jose';
import { generateRsaKeyPair, signJwt, jwkToSpkiPem } from './crypto'; // Ensure jwkToSpkiPem is used
import { solveProofOfWork } from './pow';

/**
 * Configuration for the SlipkeyClient.
 */
export interface SlipkeyClientConfig {
  defaultTargetScore?: number;
  defaultBlockSizeMs?: number;
  initialPrivateKeyJwk?: jose.JWK; // To allow providing an existing private key
}

export class SlipkeyClient {
  private privateKeyJwk!: jose.JWK;
  private publicKeyJwk!: jose.JWK;
  private pemPublicKey!: string;

  public state: string | null = null;

  // Default values for PoW parameters
  private defaultTargetScore: number = 1;
  private defaultBlockSizeMs: number = 60000; // 1 minute

  // Private constructor to enforce instantiation via the static factory method.
  private constructor() {
    // Initial values for score and block size are set via config in the create method
  }

  /**
   * Exports a copy of the client's private key in JWK format.
   * This allows the key to be persisted and reused.
   * @returns A deep copy of the private key JWK.
   */
  public exportPrivateKeyJwk(): jose.JWK {
    if (!this.privateKeyJwk) {
      throw new Error('Client not fully initialized. Private key not available.');
    }
    // Return a deep copy to prevent external modification of the internal key
    return JSON.parse(JSON.stringify(this.privateKeyJwk));
  }

  /**
   * Initializes the client's cryptographic keys, optionally using a provided private key.
   * Also converts the public key to PEM format and caches it.
   * This method is called by the static factory `create`.
   */
  private async _initializeAndCacheKeys(config?: SlipkeyClientConfig): Promise<void> {
    const initialPrivateKeyJwk = config?.initialPrivateKeyJwk;
    if (initialPrivateKeyJwk) {
      // Validate that essential private key fields and corresponding public fields are present
      if (!initialPrivateKeyJwk.d || !initialPrivateKeyJwk.n || !initialPrivateKeyJwk.e || !initialPrivateKeyJwk.kty) {
          throw new Error("Provided initialPrivateKeyJwk is incomplete or not a valid RSA private key.");
      }
      this.privateKeyJwk = initialPrivateKeyJwk;
      this.publicKeyJwk = { // Construct public JWK from private JWK's components
          kty: initialPrivateKeyJwk.kty,
          n: initialPrivateKeyJwk.n,
          e: initialPrivateKeyJwk.e,
          alg: initialPrivateKeyJwk.alg || 'RS256', // Ensure alg is present
      };
    } else {
      const keyPair = await generateRsaKeyPair(); // This returns { publicKey, privateKey } after jose.exportJWK
      this.privateKeyJwk = keyPair.privateKey;
      this.publicKeyJwk = keyPair.publicKey;
    }
    this.pemPublicKey = await jwkToSpkiPem(this.publicKeyJwk);
  }

  /**
   * Creates and initializes a new SlipkeyClient instance.
   * @param config Optional configuration for the client, including initial keys or PoW parameter defaults.
   * @returns A promise that resolves to an initialized SlipkeyClient instance.
   */
  public static async create(config?: SlipkeyClientConfig): Promise<SlipkeyClient> {
    const client = new SlipkeyClient();
    // Initialize keys first, possibly using a key from config
    await client._initializeAndCacheKeys(config);

    // Set PoW parameter defaults from config, or keep pre-defined defaults
    client.defaultTargetScore = config?.defaultTargetScore ?? client.defaultTargetScore;
    client.defaultBlockSizeMs = config?.defaultBlockSizeMs ?? client.defaultBlockSizeMs;

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
   * @param blockTimestampOrBlockSizeMs Optional. Either an ISO 8601 timestamp string for the block,
   *                                    or a number representing block size in milliseconds (to be added to current time).
   *                                    If undefined, uses `this.defaultBlockSizeMs`.
   * @param targetScore Optional. The PoW target score. If undefined, uses `this.defaultTargetScore`.
   * @param currentServerStateOverride Optional. JWT from the server, overrides internal client state if provided.
   * @returns A promise that resolves to an object containing slip claims and PoW results,
   *          or null if PoW fails.
   */
  public async generateSlip(
    blockTimestampOrBlockSizeMs?: string | number,
    targetScore?: number,
    currentServerStateOverride?: string | null
  ): Promise<{ slipClaims: object; actualScore: number; nonce: string; hash: string; token: string } | null> {
    if (!this.pemPublicKey || !this.publicKeyJwk) {
      throw new Error('Client not fully initialized. Keys not available.');
    }

    // Determine the state to use for PoW:
    // 1. If currentServerStateOverride is explicitly provided (even if null), use it.
    // 2. Otherwise, use the client's internal state.
    const stateForPow = currentServerStateOverride !== undefined ? currentServerStateOverride : this.state;

    // Determine actualBlockTimestamp
    let actualBlockTimestamp: string;
    if (typeof blockTimestampOrBlockSizeMs === 'string') {
      actualBlockTimestamp = blockTimestampOrBlockSizeMs;
    } else if (typeof blockTimestampOrBlockSizeMs === 'number') {
      actualBlockTimestamp = new Date(Date.now() + blockTimestampOrBlockSizeMs).toISOString();
    } else {
      actualBlockTimestamp = new Date(Date.now() + this.defaultBlockSizeMs).toISOString();
    }

    // Determine actualTargetScore
    const actualTargetScore = targetScore ?? this.defaultTargetScore;

    // For debugging PoW input string consistency
    const powInputClient = `${this.pemPublicKey}${actualBlockTimestamp}${stateForPow === null ? '' : stateForPow}`;
    // Nonce will be added by solveProofOfWork, but this is the base string it works with internally for each attempt.
    // solveProofOfWork itself would log the full string with nonce for a more direct comparison if needed.
    // However, solveProofOfWork returns the successful nonce and hash.
    // We need the string that *led* to that successful hash.

    const powResult = await solveProofOfWork(
      this.pemPublicKey,
      actualBlockTimestamp,
      stateForPow,
      actualTargetScore
    );

    // Log the input that resulted in the successful PoW
    if (powResult) {
      const finalPowInputClient = `${this.pemPublicKey}${actualBlockTimestamp}${stateForPow === null ? '' : stateForPow}${powResult.nonce}`;
      console.log(`[CLIENT PoW INPUT]: "${finalPowInputClient}" (Score: ${powResult.score}, Hash: ${powResult.hash})`);
    }

    if (!powResult) {
      return null; // PoW failed
    }

    const createFlag = stateForPow === null;

    const slipClaims = {
      pubkey: this.publicKeyJwk,
      block: actualBlockTimestamp,
      nonce: powResult.nonce,
      state: stateForPow,
      create: createFlag,
    };

    // Sign the slipClaims to generate the client token
    if (!this.privateKeyJwk) { // Should be initialized if this method is callable
      throw new Error('Client not fully initialized. Private key not available for signing.');
    }
    const token = await signJwt(slipClaims as jose.JWTPayload, this.privateKeyJwk);

    return {
      slipClaims,
      actualScore: powResult.score,
      nonce: powResult.nonce,
      hash: powResult.hash,
      token: token, // Include the generated token in the result
    };
  }

  // createClientToken method is now removed.

  /**
   * Processes the server's response and updates the client's internal state.
   *
   * @param serverResponse The server's response object, expected to have a `state` property (the new JWT).
   */
  public processServerResponse(serverResponse: { state: string; [key: string]: any }): void {
    this.state = serverResponse.state;
  }

  /**
   * Updates the client's default Proof-of-Work parameters.
   * @param newDefaults An object containing new default values for targetScore and/or blockSizeMs.
   */
  public updateDefaults(newDefaults: { defaultTargetScore?: number; defaultBlockSizeMs?: number }): void {
    if (newDefaults.defaultTargetScore !== undefined) {
      if (newDefaults.defaultTargetScore > 0) {
        this.defaultTargetScore = newDefaults.defaultTargetScore;
      } else {
        console.warn(`Invalid defaultTargetScore provided: ${newDefaults.defaultTargetScore}. Must be positive. Retaining existing value: ${this.defaultTargetScore}.`);
        // Or: throw new Error('defaultTargetScore must be positive.');
      }
    }

    if (newDefaults.defaultBlockSizeMs !== undefined) {
      if (newDefaults.defaultBlockSizeMs > 0) {
        this.defaultBlockSizeMs = newDefaults.defaultBlockSizeMs;
      } else {
        console.warn(`Invalid defaultBlockSizeMs provided: ${newDefaults.defaultBlockSizeMs}. Must be positive. Retaining existing value: ${this.defaultBlockSizeMs}.`);
        // Or: throw new Error('defaultBlockSizeMs must be positive.');
      }
    }
  }
}
