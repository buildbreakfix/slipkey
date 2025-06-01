import * as jose from 'jose';
import {
    generateRsaKeyPair,
    jwkToSpkiPem,
    signJwt as internalSignJwt,
    verifyJwt as internalVerifyJwt
} from './crypto.js';
import { sha256 } from './pow.js';

const DEFAULT_SERVER_JWT_EXPIRATION = "7d";

// Types for custom credit calculation
export interface ServerCreditMetadata {
  blockTimestamp: string;
  timeSolved: Date;       // Actual time PoW solution was processed by server
  powScore: number;
  chainLength: number;
  clientPublicKeyJwk: jose.JWK;
  previousCredit: number;
  previousChainLength: number;
  // Consider adding nonce, previous block timestamp if available/needed from old state JWT
}
export type CreditCalculationFunction = (metadata: ServerCreditMetadata) => number;


export interface SlipkeyServerConfig {
  initialPrivateKeyJwk?: jose.JWK;
  initialPublicKeyJwk?: jose.JWK;
  serverName?: string;
  defaultStateTokenExpiration?: string | number;
  calculateCredit?: CreditCalculationFunction; // Custom credit calculation function
}

export class SlipkeyServer {
  private serverPrivateKeyJwk!: jose.JWK;
  private serverPublicKeyJwk!: jose.JWK;
  private serverName: string;
  private stateTokenExpiration: string | number;
  private calculateCredit: CreditCalculationFunction;

  private defaultCalculateCredit(metadata: ServerCreditMetadata): number {
    // Default logic: previous credit + (score * 10 as base) + new chain length as bonus
    return metadata.previousCredit + (metadata.powScore * 10) + metadata.chainLength;
  }

  private constructor(config?: SlipkeyServerConfig) {
    this.serverName = config?.serverName || "SlipkeyServerDefault";
    this.stateTokenExpiration = config?.defaultStateTokenExpiration || DEFAULT_SERVER_JWT_EXPIRATION;
    this.calculateCredit = config?.calculateCredit || this.defaultCalculateCredit;
  }

  public static async create(config?: SlipkeyServerConfig): Promise<SlipkeyServer> {
    const server = new SlipkeyServer(config);

    if (config?.initialPrivateKeyJwk) {
      if (!config.initialPrivateKeyJwk.d ||
          !config.initialPrivateKeyJwk.n ||
          !config.initialPrivateKeyJwk.e ||
          !config.initialPrivateKeyJwk.kty) {
          throw new Error("Provided initialPrivateKeyJwk is incomplete or not a valid RSA private key.");
      }
      server.serverPrivateKeyJwk = config.initialPrivateKeyJwk;
      if (!server.serverPrivateKeyJwk.alg) server.serverPrivateKeyJwk.alg = 'RS256';

      if (config.initialPublicKeyJwk) {
        if (config.initialPublicKeyJwk.n !== server.serverPrivateKeyJwk.n ||
            config.initialPublicKeyJwk.e !== server.serverPrivateKeyJwk.e ||
            config.initialPublicKeyJwk.kty !== server.serverPrivateKeyJwk.kty) {
            throw new Error("Provided initialPublicKeyJwk does not match components of initialPrivateKeyJwk.");
        }
        server.serverPublicKeyJwk = config.initialPublicKeyJwk;
        if (!server.serverPublicKeyJwk.alg) server.serverPublicKeyJwk.alg = 'RS256';
      } else {
        server.serverPublicKeyJwk = {
          kty: server.serverPrivateKeyJwk.kty!,
          n: server.serverPrivateKeyJwk.n!,
          e: server.serverPrivateKeyJwk.e!,
          alg: server.serverPrivateKeyJwk.alg || 'RS256',
        };
      }
    } else {
      const keyPair = await generateRsaKeyPair();
      server.serverPrivateKeyJwk = keyPair.privateKey;
      server.serverPublicKeyJwk = keyPair.publicKey;
    }

    if (!server.serverPrivateKeyJwk || !server.serverPublicKeyJwk) {
      throw new Error("Server keys failed to initialize.");
    }
    if (!server.serverPublicKeyJwk.alg) server.serverPublicKeyJwk.alg = 'RS256';
    if (!server.serverPrivateKeyJwk.alg) server.serverPrivateKeyJwk.alg = 'RS256';

    return server;
  }

  public getPublicKeyJwk(): jose.JWK {
    if (!this.serverPublicKeyJwk) {
      throw new Error('Server not fully initialized. Public JWK not available.');
    }
    return this.serverPublicKeyJwk;
  }


  public async processClientToken(
    clientToken: string,
    expectedTargetScore: number = 1
  ): Promise<
    { newServerStateToken: string; score: number; creditEarned: number; // This 'creditEarned' will be total credit
      chainLength: number; error?: undefined } |
    { error: string }
  > {
    let clientPublicJwkFromClaim: jose.JWK;

    try {
      const decodedPayload = jose.decodeJwt(clientToken);
      if (!decodedPayload || typeof decodedPayload.pubkey !== 'object' || decodedPayload.pubkey === null) {
        return { error: "Invalid or missing public key in client token claims." };
      }
      clientPublicJwkFromClaim = decodedPayload.pubkey as jose.JWK;
      if (!clientPublicJwkFromClaim.alg) clientPublicJwkFromClaim.alg = 'RS256';
    } catch (e) {
      return { error: `Failed to decode client token: ${(e as Error).message}` };
    }

    let slipClaims: jose.JWTPayload & { pubkey: jose.JWK, block: string, nonce: string, state: string | null, create: boolean };
    try {
      const { payload } = await internalVerifyJwt(clientToken, clientPublicJwkFromClaim);
      slipClaims = payload as typeof slipClaims;
    } catch (e) {
      return { error: `Client token verification failed: ${(e as Error).message}` };
    }

    const blockTime = new Date(slipClaims.block).getTime();
    const currentTime = Date.now();
     if (blockTime > currentTime + (60 * 60 * 1000)) {
      // return { error: `Block timestamp too far in future: ${slipClaims.block}`};
    }

    let previousChainLength = 0;
    let previousCredit = 0;
    let previousBlockTimestamp = 0;

    if (slipClaims.create === true && slipClaims.state !== null) {
      return { error: "Invalid slip: 'create' is true but 'state' is present." };
    }
    if (slipClaims.create === false && slipClaims.state === null) {
      return { error: "Invalid slip: 'create' is false but 'state' is missing." };
    }

    if (slipClaims.state) {
      try {
        const { payload: prevStatePayload } = await internalVerifyJwt(slipClaims.state, this.serverPublicKeyJwk);

        if (!prevStatePayload.publicKey || typeof prevStatePayload.publicKey !== 'object') {
            return { error: "Invalid 'publicKey' claim in previous server state." };
        }
        const prevClientPubKeyJwk = prevStatePayload.publicKey as jose.JWK;
        if (prevClientPubKeyJwk.n !== clientPublicJwkFromClaim.n || prevClientPubKeyJwk.e !== clientPublicJwkFromClaim.e) {
            return { error: "Client public key in current slip does not match 'publicKey' claim in previous server state." };
        }

        previousChainLength = (prevStatePayload.len as number) || 0;
        previousCredit = (prevStatePayload.credit as number) || 0;
        if (prevStatePayload.block && typeof prevStatePayload.block === 'string') {
            previousBlockTimestamp = new Date(prevStatePayload.block).getTime();
            if (blockTime <= previousBlockTimestamp) {
                // return { error: `New block timestamp (${slipClaims.block}) must be after previous block timestamp (${prevStatePayload.block}).`};
            }
        }

      } catch (e) {
        return { error: `Previous server state (JWT) is invalid: ${(e as Error).message}` };
      }
    }

    let pemClientPublicKeyForPow: string;
    try {
      pemClientPublicKeyForPow = await jwkToSpkiPem(clientPublicJwkFromClaim);
    } catch (e) {
      return { error: `Failed to convert client public key JWK to PEM for PoW: ${(e as Error).message}`};
    }

    const stateForPowString = slipClaims.state === null ? '' : slipClaims.state;
    const powInputServer = `${pemClientPublicKeyForPow}${slipClaims.block}${stateForPowString}${slipClaims.nonce}`;
    const currentHash = await sha256(powInputServer);
    let score = 0;
    for (let i = 0; i < currentHash.length; i++) {
      if (currentHash[i] === '0') score++; else break;
    }

    if (score < expectedTargetScore) {
      return { error: `Proof-of-Work score too low: ${score} < ${expectedTargetScore}. Hash: ${currentHash}` };
    }

    const newChainLength = previousChainLength + 1;

    const creditMetadata: ServerCreditMetadata = {
        blockTimestamp: slipClaims.block,
        timeSolved: new Date(), // Server's current time as processing time
        powScore: score,
        chainLength: newChainLength,
        clientPublicKeyJwk: clientPublicJwkFromClaim,
        previousCredit: previousCredit,
        previousChainLength: previousChainLength,
    };
    const newTotalCredit = this.calculateCredit(creditMetadata);

    const newServerStatePayload: jose.JWTPayload = {
      iat: Math.floor(Date.now() / 1000),
      iss: this.serverName,
      sub: await jwkToSpkiPem(clientPublicJwkFromClaim),
      publicKey: clientPublicJwkFromClaim,
      block: slipClaims.block,
      len: newChainLength,
      credit: newTotalCredit, // Use the result from calculateCredit
    };

    let newServerStateToken: string;
    try {
      newServerStateToken = await internalSignJwt(newServerStatePayload, this.serverPrivateKeyJwk, this.stateTokenExpiration);
    } catch (e) {
      return { error: `Failed to sign new server state token: ${(e as Error).message}`};
    }

    return {
      newServerStateToken,
      score,
      creditEarned: newTotalCredit, // This field in response means total credit
      chainLength: newChainLength,
      error: undefined,
    };
  }
}
