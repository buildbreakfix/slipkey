import * as jose from 'jose';
import {
    generateRsaKeyPair,
    jwkToSpkiPem,
    signJwt as internalSignJwt,
    verifyJwt as internalVerifyJwt
} from './crypto';
import { sha256 } from './pow';

export interface SlipkeyServerConfig {
  initialPrivateKeyJwk?: jose.JWK;
  initialPublicKeyJwk?: jose.JWK;
  serverName?: string;
}

export class SlipkeyServer {
  private serverPrivateKeyJwk!: jose.JWK;
  private serverPublicKeyJwk!: jose.JWK;
  private serverName: string;

  private constructor(config?: SlipkeyServerConfig) {
    this.serverName = config?.serverName || "SlipkeyServerDefault";
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

      if (config.initialPublicKeyJwk) {
        if (config.initialPublicKeyJwk.n !== server.serverPrivateKeyJwk.n ||
            config.initialPublicKeyJwk.e !== server.serverPrivateKeyJwk.e ||
            config.initialPublicKeyJwk.kty !== server.serverPrivateKeyJwk.kty) {
            throw new Error("Provided initialPublicKeyJwk does not match components of initialPrivateKeyJwk.");
        }
        server.serverPublicKeyJwk = config.initialPublicKeyJwk;
        if (!server.serverPublicKeyJwk.alg && server.serverPrivateKeyJwk.alg) {
            server.serverPublicKeyJwk.alg = server.serverPrivateKeyJwk.alg;
        } else if (!server.serverPublicKeyJwk.alg) {
            server.serverPublicKeyJwk.alg = 'RS256';
        }

      } else {
        server.serverPublicKeyJwk = {
          kty: server.serverPrivateKeyJwk.kty,
          n: server.serverPrivateKeyJwk.n,
          e: server.serverPrivateKeyJwk.e,
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
    if (!server.serverPublicKeyJwk.alg) {
        server.serverPublicKeyJwk.alg = 'RS256';
    }
    if (!server.serverPrivateKeyJwk.alg) {
        server.serverPrivateKeyJwk.alg = 'RS256';
    }

    return server;
  }

  /**
   * Returns the server's public key in JWK format.
   * Throws an error if the key is not yet initialized.
   * @returns The public key in JWK format.
   */
  public getPublicKeyJwk(): jose.JWK {
    if (!this.serverPublicKeyJwk) {
      // This case should ideally not be reachable if server is always created via `create()`
      throw new Error('Server not fully initialized. Public JWK not available.');
    }
    return this.serverPublicKeyJwk;
  }


  public async processClientToken(
    clientToken: string,
    expectedTargetScore: number = 1
  ): Promise<
    { newServerStateToken: string; score: number; creditEarned: number; chainLength: number; error?: undefined } |
    { error: string }
  > {
    let clientPublicJwkFromClaim: jose.JWK;

    try {
      const decodedPayload = jose.decodeJwt(clientToken);
      if (!decodedPayload || typeof decodedPayload.pubkey !== 'object' || decodedPayload.pubkey === null) {
        console.log("[SERVER ERROR]: Invalid or missing public key in client token claims.");
        return { error: "Invalid or missing public key in client token claims." };
      }
      clientPublicJwkFromClaim = decodedPayload.pubkey as jose.JWK;
      if (!clientPublicJwkFromClaim.alg) clientPublicJwkFromClaim.alg = 'RS256';
    } catch (e) {
      const errorMessage = `Failed to decode client token: ${(e as Error).message}`;
      console.log(`[SERVER ERROR]: ${errorMessage}`);
      return { error: errorMessage };
    }

    let slipClaims: jose.JWTPayload & { pubkey: jose.JWK, block: string, nonce: string, state: string | null, create: boolean };
    try {
      const { payload } = await internalVerifyJwt(clientToken, clientPublicJwkFromClaim);
      slipClaims = payload as typeof slipClaims;
    } catch (e) {
      const errorMessage = `Client token verification failed: ${(e as Error).message}`;
      console.log(`[SERVER ERROR]: ${errorMessage}`);
      return { error: errorMessage };
    }

    const blockTime = new Date(slipClaims.block).getTime();
    const currentTime = Date.now();
    if (blockTime < currentTime - (10 * 60 * 1000)) {
        // console.log(`[SERVER WARN]: Block timestamp is older than 10 minutes: ${slipClaims.block}`);
    }
    if (blockTime > currentTime + (60 * 60 * 1000)) {
        // console.log(`[SERVER WARN]: Block timestamp too far in future: ${slipClaims.block}`);
    }

    let previousChainLength = 0;
    let previousCredit = 0;

    if (slipClaims.create === true && slipClaims.state !== null) {
      console.log("[SERVER ERROR]: Invalid slip: 'create' is true but 'state' is present.");
      return { error: "Invalid slip: 'create' is true but 'state' is present." };
    }
    if (slipClaims.create === false && slipClaims.state === null) {
      console.log("[SERVER ERROR]: Invalid slip: 'create' is false but 'state' is missing.");
      return { error: "Invalid slip: 'create' is false but 'state' is missing." };
    }

    if (slipClaims.state) {
      try {
        const { payload: prevStatePayload } = await internalVerifyJwt(slipClaims.state, this.serverPublicKeyJwk);

        if (!prevStatePayload.publicKey || typeof prevStatePayload.publicKey !== 'object') {
            console.log("[SERVER ERROR]: Invalid 'publicKey' claim in previous server state.");
            return { error: "Invalid 'publicKey' claim in previous server state." };
        }
        const prevClientPubKeyJwk = prevStatePayload.publicKey as jose.JWK;
        // Log keys for debugging mismatch test
        // console.log("[SERVER PREV KEY N]:", prevClientPubKeyJwk.n);
        // console.log("[SERVER CURR KEY N]:", clientPublicJwkFromClaim.n);
        if (prevClientPubKeyJwk.n !== clientPublicJwkFromClaim.n || prevClientPubKeyJwk.e !== clientPublicJwkFromClaim.e) {
            console.log("[SERVER ERROR]: Client public key in current slip does not match 'publicKey' claim in previous server state.");
            return { error: "Client public key in current slip does not match 'publicKey' claim in previous server state." };
        }

        previousChainLength = (prevStatePayload.len as number) || 0;
        previousCredit = (prevStatePayload.credit as number) || 0;
      } catch (e) {
        const errorMessage = `Previous server state (JWT) is invalid: ${(e as Error).message}`;
        console.log(`[SERVER ERROR]: ${errorMessage}`);
        return { error: errorMessage };
      }
    }

    let pemClientPublicKeyForPow: string;
    try {
      pemClientPublicKeyForPow = await jwkToSpkiPem(clientPublicJwkFromClaim);
    } catch (e) {
      const errorMessage = `Failed to convert client public key JWK to PEM for PoW: ${(e as Error).message}`;
      console.log(`[SERVER ERROR]: ${errorMessage}`);
      return { error: errorMessage };
    }

    const stateForPowString = slipClaims.state === null ? '' : slipClaims.state;
    const powInputServer = `${pemClientPublicKeyForPow}${slipClaims.block}${stateForPowString}${slipClaims.nonce}`;
    // console.log(`[SERVER PoW INPUT]: "${powInputServer}"`); // Kept for debugging if needed
    const currentHash = await sha256(powInputServer);
    let score = 0;
    for (let i = 0; i < currentHash.length; i++) {
      if (currentHash[i] === '0') score++; else break;
    }
    // console.log(`[SERVER PoW RESULT]: Score ${score}, Hash ${currentHash}`); // Kept for debugging

    if (score < expectedTargetScore) {
      const errorMessage = `Proof-of-Work score too low: ${score} < ${expectedTargetScore}. Hash: ${currentHash}`;
      console.log(`[SERVER ERROR]: ${errorMessage}`);
      return { error: errorMessage };
    }

    const newChainLength = previousChainLength + 1;
    const creditEarnedThisSlip = (score * 10) + newChainLength;
    const newCredit = previousCredit + creditEarnedThisSlip;

    const newServerStatePayload: jose.JWTPayload = {
      iat: Math.floor(Date.now() / 1000),
      iss: this.serverName,
      sub: await jwkToSpkiPem(clientPublicJwkFromClaim),
      publicKey: clientPublicJwkFromClaim,
      block: slipClaims.block,
      len: newChainLength,
      credit: newCredit,
      // exp: Math.floor(Date.now() / 1000) + (60 * 60), // Optional: 1 hour expiration
    };

    let newServerStateToken: string;
    try {
      newServerStateToken = await internalSignJwt(newServerStatePayload, this.serverPrivateKeyJwk);
    } catch (e) {
      const errorMessage = `Failed to sign new server state token: ${(e as Error).message}`;
      console.log(`[SERVER ERROR]: ${errorMessage}`);
      return { error: errorMessage };
    }

    const successResponse = {
      newServerStateToken,
      score,
      creditEarned: newCredit,
      chainLength: newChainLength,
      error: undefined,
    };
    // console.log("[SERVER SUCCESS]: ", successResponse); // Kept for debugging
    return successResponse;
  }
}
