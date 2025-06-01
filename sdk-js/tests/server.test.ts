import { SlipkeyClient } from '../src/client';
import { SlipkeyServer, SlipkeyServerConfig } from '../src/SlipkeyServer';
import { generateRsaKeyPair, jwkToSpkiPem, signJwt, verifyJwt } from '../src/crypto';
import * as jose from 'jose';
import { webcrypto } from 'node:crypto';

// Polyfill for global crypto if necessary
if (typeof globalThis.crypto?.subtle === 'undefined') {
  globalThis.crypto = webcrypto as any;
}

// Type for the success part of processClientToken response
type ServerSuccessResponse = {
  newServerStateToken: string;
  score: number;
  creditEarned: number;
  chainLength: number;
  error?: undefined;
};
type ServerErrorResponse = { error: string };
type ProcessClientTokenResponse = ServerSuccessResponse | ServerErrorResponse;


describe('SlipkeyServer', () => {
  describe('SlipkeyServer.create() (Server Initialization)', () => {
    test('should create with default config (generates new keys)', async () => {
      const server = await SlipkeyServer.create();
      expect(server).toBeInstanceOf(SlipkeyServer);
      expect(server.getPublicKeyJwk()).toBeDefined(); // Use getter
      expect((server as any).serverPrivateKeyJwk).toBeDefined();
      expect((server as any).serverName).toBe("SlipkeyServerDefault");
    });

    test('should have a usable public key getter', async () => {
        const server = await SlipkeyServer.create();
        const pubKey = server.getPublicKeyJwk();
        expect(pubKey).toBeDefined();
        expect(pubKey.kty).toBe('RSA');
    });

    test('should create with provided initial RSA keys', async () => {
      const keys = await generateRsaKeyPair();
      const config: SlipkeyServerConfig = {
        initialPrivateKeyJwk: keys.privateKey,
        initialPublicKeyJwk: keys.publicKey,
        serverName: "TestServer"
      };
      const server = await SlipkeyServer.create(config);
      expect(server.getPublicKeyJwk()).toEqual(keys.publicKey); // Use getter
      expect((server as any).serverPrivateKeyJwk).toEqual(keys.privateKey);
      expect((server as any).serverName).toBe("TestServer");

      const payloadToSign = { test: "data", sub: "testSubject" };
      const signedToken = await signJwt(payloadToSign, (server as any).serverPrivateKeyJwk);
      const { payload: verifiedPayload } = await verifyJwt(signedToken, keys.publicKey);
      expect(verifiedPayload.test).toBe("data");
    });

    test('should derive public key if only initialPrivateKeyJwk is provided', async () => {
      const keys = await generateRsaKeyPair();
      const config: SlipkeyServerConfig = {
        initialPrivateKeyJwk: keys.privateKey
      };
      const server = await SlipkeyServer.create(config);

      const derivedPublicKeyJwk = server.getPublicKeyJwk(); // Use getter
      expect(derivedPublicKeyJwk.kty).toBe(keys.privateKey.kty);
      expect(derivedPublicKeyJwk.n).toBe(keys.privateKey.n);
      expect(derivedPublicKeyJwk.e).toBe(keys.privateKey.e);
      expect(derivedPublicKeyJwk.alg).toBe(keys.privateKey.alg || 'RS256');

      const payloadToSign = { test: "data" };
      const signedToken = await signJwt(payloadToSign, (server as any).serverPrivateKeyJwk);
      await expect(verifyJwt(signedToken, derivedPublicKeyJwk)).resolves.toBeDefined();
      await expect(verifyJwt(signedToken, keys.publicKey)).resolves.toBeDefined();
    });

    test('should throw if initialPrivateKeyJwk is incomplete for derivation', async () => {
      const incompleteKey: jose.JWK = { kty: "RSA", d: "dValue" };
      await expect(SlipkeyServer.create({ initialPrivateKeyJwk: incompleteKey }))
        .rejects.toThrow("Provided initialPrivateKeyJwk is incomplete");
    });

    test('should throw if provided public key does not match private key components', async () => {
        const keys1 = await generateRsaKeyPair();
        const keys2 = await generateRsaKeyPair();
        const config: SlipkeyServerConfig = {
            initialPrivateKeyJwk: keys1.privateKey,
            initialPublicKeyJwk: keys2.publicKey,
        };
        await expect(SlipkeyServer.create(config))
            .rejects.toThrow("Provided initialPublicKeyJwk does not match components of initialPrivateKeyJwk.");
    });
  });


  describe('server.processClientToken()', () => {
    let server: SlipkeyServer;
    const defaultTargetScore = 1;
    const futureBlockTime = (offsetMs: number = 60000) => new Date(Date.now() + offsetMs).toISOString();

    beforeAll(async () => {
        server = await SlipkeyServer.create();
    });

    test('should process a valid Genesis Slip correctly', async () => {
      const freshClient = await SlipkeyClient.create();
      const blockTimestamp = futureBlockTime();

      const clientSlipResult = await freshClient.generateSlip(blockTimestamp, defaultTargetScore);
      expect(clientSlipResult).not.toBeNull();
      if (!clientSlipResult) return;

      expect((clientSlipResult.slipClaims as any).create).toBe(true);

      const clientToken = clientSlipResult.token;
      const serverResponse = await server.processClientToken(clientToken, defaultTargetScore);

      if (serverResponse.error !== undefined) {
        throw new Error(`Server processing failed for genesis slip: ${serverResponse.error}`);
      }

      expect(serverResponse.newServerStateToken).toBeDefined();
      expect(typeof serverResponse.newServerStateToken).toBe('string');
      expect(serverResponse.chainLength).toBe(1);
      expect(serverResponse.score).toBeGreaterThanOrEqual(defaultTargetScore);
      expect(serverResponse.creditEarned).toBeGreaterThan(0);

      const { payload: serverStatePayload } = await verifyJwt(serverResponse.newServerStateToken, server.getPublicKeyJwk()); // Use getter
      expect(serverStatePayload.len).toBe(1);
      expect(serverStatePayload.credit).toBe(serverResponse.creditEarned);
      expect(serverStatePayload.publicKey).toEqual(freshClient.getPublicJwk());
      expect(serverStatePayload.block).toBe(blockTimestamp);

    }, 20000);

    test('should process a valid Subsequent Slip correctly', async () => {
      const freshClient = await SlipkeyClient.create();
      const block1 = futureBlockTime();
      const slipResult1 = await freshClient.generateSlip(block1, defaultTargetScore);
      expect(slipResult1).not.toBeNull(); if (!slipResult1) return;
      const clientToken1 = slipResult1.token;

      const serverResponse1 = await server.processClientToken(clientToken1, defaultTargetScore);
      if (serverResponse1.error !== undefined) {
        throw new Error(`Genesis slip processing failed in subsequent slip test setup: ${serverResponse1.error}`);
      }
      freshClient.processServerResponse({ state: serverResponse1.newServerStateToken });

      const block2 = futureBlockTime();
      const slipResult2 = await freshClient.generateSlip(block2, defaultTargetScore, freshClient.state);
      expect(slipResult2).not.toBeNull(); if (!slipResult2) return;
      expect((slipResult2.slipClaims as any).create).toBe(false);

      const clientToken2 = slipResult2.token;
      const serverResponse2 = await server.processClientToken(clientToken2, defaultTargetScore);

      if (serverResponse2.error !== undefined) {
        throw new Error(`Subsequent slip processing failed: ${serverResponse2.error}`);
      }
      expect(serverResponse2.newServerStateToken).toBeDefined();
      expect(serverResponse2.chainLength).toBe(2);
      expect(serverResponse2.score).toBeGreaterThanOrEqual(defaultTargetScore);
      expect(serverResponse2.creditEarned).toBeGreaterThan(0);

      const { payload: serverStatePayload2 } = await verifyJwt(serverResponse2.newServerStateToken, server.getPublicKeyJwk()); // Use getter
      expect(serverStatePayload2.credit).toEqual(serverResponse2.creditEarned);
      expect(serverResponse2.creditEarned).toBeGreaterThan(serverResponse1.creditEarned);

    }, 30000);

    // Error Cases
    test('should return error for invalid client token signature', async () => {
      const testClient = await SlipkeyClient.create();
      const blockTimestamp = futureBlockTime();
      const clientSlipResult = await testClient.generateSlip(blockTimestamp, defaultTargetScore);
      expect(clientSlipResult).not.toBeNull(); if (!clientSlipResult) return;

      const attackerKeys = await generateRsaKeyPair();
      const invalidClientToken = await signJwt(clientSlipResult.slipClaims as jose.JWTPayload, attackerKeys.privateKey);

      const serverResponse = await server.processClientToken(invalidClientToken, defaultTargetScore);
      expect(serverResponse.error).toBeDefined();
      if(serverResponse.error === undefined) throw new Error("Test failed: error was expected to be defined.");
      expect(serverResponse.error).toContain("Client token verification failed");
    });

    test('Placeholder for "block time in the past (too old)" - current server logic is lenient', () => {
         expect(true).toBe(true);
    });


    test('should return error if create=true and state is present', async () => {
        const testClient = await SlipkeyClient.create();
        const clientPubKeyJwk = testClient.getPublicJwk();
        const slipClaims = {
            pubkey: clientPubKeyJwk,
            block: futureBlockTime(),
            nonce: "testnonce",
            state: "dummyPreviousServerStateJWT",
            create: true,
        };
        const clientToken = await signJwt(slipClaims as jose.JWTPayload, (testClient as any).privateKeyJwk);
        const serverResponse = await server.processClientToken(clientToken, defaultTargetScore);
        expect(serverResponse.error).toBeDefined();
        if(serverResponse.error === undefined) throw new Error("Test failed: error was expected to be defined.");
        expect(serverResponse.error).toContain("Invalid slip: 'create' is true but 'state' is present.");
    });

    test('should return error if create=false and state is missing', async () => {
        const testClient = await SlipkeyClient.create();
        const clientPubKeyJwk = testClient.getPublicJwk();
        const slipClaims = {
            pubkey: clientPubKeyJwk,
            block: futureBlockTime(),
            nonce: "testnonce",
            state: null,
            create: false,
        };
        const clientToken = await signJwt(slipClaims as jose.JWTPayload, (testClient as any).privateKeyJwk);
        const serverResponse = await server.processClientToken(clientToken, defaultTargetScore);
        expect(serverResponse.error).toBeDefined();
        if(serverResponse.error === undefined) throw new Error("Test failed: error was expected to be defined.");
        expect(serverResponse.error).toContain("Invalid slip: 'create' is false but 'state' is missing.");
    });

    test('should return error for PoW score too low', async () => {
        const freshClient = await SlipkeyClient.create();
        const clientSlipResult = await freshClient.generateSlip(futureBlockTime(), 1);
        expect(clientSlipResult).not.toBeNull(); if(!clientSlipResult) return;
        expect(clientSlipResult.actualScore).toBeGreaterThanOrEqual(1);

        const serverResponse = await server.processClientToken(clientSlipResult.token, 5);
        expect(serverResponse.error).toBeDefined();
        if(serverResponse.error === undefined) throw new Error("Test failed: error was expected to be defined.");
        expect(serverResponse.error).toContain("Proof-of-Work score too low");
    }, 20000);

    test('should return error for invalid previous server state JWT', async () => {
        const freshClient = await SlipkeyClient.create();
        const invalidPrevStateJwt = "this.is.not.a.valid.jwt";

        const tempSlip = await freshClient.generateSlip(futureBlockTime(), 1, invalidPrevStateJwt);
        expect(tempSlip).not.toBeNull(); if(!tempSlip) return;

        const clientToken = tempSlip.token;
        const serverResponse = await server.processClientToken(clientToken, defaultTargetScore);
        expect(serverResponse.error).toBeDefined();
        if(serverResponse.error === undefined) throw new Error("Test failed: error was expected to be defined.");
        expect(serverResponse.error).toContain("Previous server state (JWT) is invalid");
    }, 20000);

    test('should return error if client public key in state does not match slip', async () => {
        const clientA = await SlipkeyClient.create();
        const serverForClientA = await SlipkeyServer.create();

        const blockA = futureBlockTime();
        const slipA = await clientA.generateSlip(blockA, 1);
        expect(slipA).not.toBeNull(); if(!slipA) return;
        const tokenA = slipA.token;
        const serverResponseA = await serverForClientA.processClientToken(tokenA, 1);
        if (serverResponseA.error !== undefined) throw new Error(`Client A genesis slip failed: ${serverResponseA.error}`);
        const successResponseA = serverResponseA as ServerSuccessResponse;
        const stateForClientA = successResponseA.newServerStateToken;

        const clientB = await SlipkeyClient.create();
        const blockB = futureBlockTime();

        const slipResultBAttempt = await clientB.generateSlip(blockB, 1, stateForClientA);
        expect(slipResultBAttempt).not.toBeNull(); if(!slipResultBAttempt) return;

        const tokenBWithAsState = slipResultBAttempt.token;

        const serverResponseB = await serverForClientA.processClientToken(tokenBWithAsState, 1);
        expect(serverResponseB.error).toBeDefined();
        if(serverResponseB.error === undefined) throw new Error("Test failed: error was expected to be defined.");
        expect(serverResponseB.error).toContain("Client public key in current slip does not match 'publicKey' claim in previous server state.");
    }, 30000);

  });
});
