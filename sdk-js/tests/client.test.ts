import { jest } from '@jest/globals';
import { SlipkeyClient, SlipkeyClientConfig } from '../src/client';
import { verifyJwt, jwkToSpkiPem, generateRsaKeyPair as sdkGenerateRsaKeyPair } from '../src/crypto';
import * as jose from 'jose';
import { webcrypto } from 'node:crypto';

import {
  generateServerRsaKeys,
  processSlipAndIssueState,
  ServerKeys,
  SlipWallet,
} from '../src/server';

import type * as OriginalPowTypes from '../src/pow';


// Polyfill for global crypto
if (typeof globalThis.crypto?.subtle === 'undefined') {
  globalThis.crypto = webcrypto as any;
}

type ServerSuccessResponse = {
  state: string;
  credit: number;
  len: number;
  block: string;
  expires: number;
  error?: undefined;
};


describe('SlipkeyClient', () => {
  describe('SlipkeyClient.create() and Configuration', () => {
    test('should create with default settings if no config provided', async () => {
      const freshClient = await SlipkeyClient.create();
      expect(freshClient).toBeInstanceOf(SlipkeyClient);
      expect(freshClient.getPublicKey()).toBeDefined();
      expect(freshClient.getPublicJwk()).toBeDefined();
      expect(freshClient.state).toBeNull();
      expect((freshClient as any).defaultTargetScore).toBe(1);
      expect((freshClient as any).defaultBlockSizeMs).toBe(60000);
    });

    test('should use provided defaultTargetScore and defaultBlockSizeMs from config', async () => {
      const config: SlipkeyClientConfig = {
        defaultTargetScore: 3,
        defaultBlockSizeMs: 30000,
      };
      const configuredClient = await SlipkeyClient.create(config);
      expect((configuredClient as any).defaultTargetScore).toBe(3);
      expect((configuredClient as any).defaultBlockSizeMs).toBe(30000);
    });

    test('should use provided initialPrivateKeyJwk to initialize keys', async () => {
      const { privateKey: testPrivateJwk, publicKey: expectedPublicJwk } = await sdkGenerateRsaKeyPair();
      const clientFromPKey = await SlipkeyClient.create({ initialPrivateKeyJwk: testPrivateJwk });

      const clientPublicJwk = clientFromPKey.getPublicJwk();
      expect(clientPublicJwk.n).toEqual(expectedPublicJwk.n);
      expect(clientPublicJwk.e).toEqual(expectedPublicJwk.e);

      const pem = clientFromPKey.getPublicKey();
      const pemFromOriginal = await jwkToSpkiPem(expectedPublicJwk);
      expect(pem).toEqual(pemFromOriginal);

      // Test if client can sign with this private key
      const blockTimestamp = new Date(Date.now() + 60000).toISOString();
      const slipResult = await clientFromPKey.generateSlip(blockTimestamp, 1);
      expect(slipResult).not.toBeNull();
      if (!slipResult) return; // Type guard

      expect(typeof slipResult.token).toBe('string');
      await expect(verifyJwt(slipResult.token, clientPublicJwk)).resolves.toBeDefined();
    });

    test('should throw if initialPrivateKeyJwk is incomplete', async () => {
        const incompleteKey: jose.JWK = { kty: 'RSA', e: 'AQAB' };
        await expect(SlipkeyClient.create({ initialPrivateKeyJwk: incompleteKey }))
            .rejects.toThrow("Provided initialPrivateKeyJwk is incomplete or not a valid RSA private key.");
    });

    test('should correctly re-initialize from an exported private key', async () => {
      const client1 = await SlipkeyClient.create();
      const exportedPrivateKeyJwk = client1.exportPrivateKeyJwk();
      const originalPublicJwk = client1.getPublicJwk();

      const client2 = await SlipkeyClient.create({ initialPrivateKeyJwk: exportedPrivateKeyJwk });

      const newPublicJwk = client2.getPublicJwk();
      expect(newPublicJwk.n).toEqual(originalPublicJwk.n);
      expect(newPublicJwk.e).toEqual(originalPublicJwk.e);
      expect(client2.getPublicKey()).toEqual(await jwkToSpkiPem(originalPublicJwk));

      const blockTimestamp = new Date(Date.now() + 60000).toISOString();
      const slipResult = await client2.generateSlip(blockTimestamp, 1);
      expect(slipResult).not.toBeNull();
      if (!slipResult) return;

      expect(typeof slipResult.token).toBe('string');
      await expect(verifyJwt(slipResult.token, newPublicJwk)).resolves.toBeDefined();
    });
  });

  describe('Client Operations', () => {
    let serverKeys: ServerKeys;
    const wallets: Map<string, SlipWallet> = new Map();
    const defaultTestTargetScore = 1;
    const futureBlockTime = (offsetMs: number = 60000) => new Date(Date.now() + offsetMs).toISOString();

    beforeAll(async () => {
      serverKeys = await generateServerRsaKeys();
    });

    beforeEach(() => {
        wallets.clear();
    });

    describe('generateSlip variations', () => {
        let client: SlipkeyClient;
        beforeEach(async () => {
            client = await SlipkeyClient.create();
        });

        test('should use default blockSize and targetScore, and return token', async () => {
            const slipResult = await client.generateSlip();
            expect(slipResult).not.toBeNull();
            if(!slipResult) return;
            const claims = slipResult.slipClaims as any;
            const defaultBlockSizeMs = (client as any).defaultBlockSizeMs;
            const defaultTargetScore = (client as any).defaultTargetScore;
            const expectedMinTime = Date.now() + defaultBlockSizeMs - 5000;
            const expectedMaxTime = Date.now() + defaultBlockSizeMs + 5000;
            expect(new Date(claims.block).getTime()).toBeGreaterThanOrEqual(expectedMinTime);
            expect(new Date(claims.block).getTime()).toBeLessThanOrEqual(expectedMaxTime);
            expect(slipResult.actualScore).toBeGreaterThanOrEqual(defaultTargetScore);
            expect(typeof slipResult.token).toBe('string');
            // Verify token
            const { payload } = await verifyJwt(slipResult.token, client.getPublicJwk());
            expect(payload.block).toEqual(claims.block);
            expect(payload.nonce).toEqual(claims.nonce);
        }, 20000);

        test('should use provided blockSizeMs (number) for block timestamp', async () => {
            const customBlockSizeMs = 30000;
            const slipResult = await client.generateSlip(customBlockSizeMs);
            expect(slipResult).not.toBeNull();
            if(!slipResult) return;
            const claims = slipResult.slipClaims as any;
            const expectedMinTime = Date.now() + customBlockSizeMs - 5000;
            const expectedMaxTime = Date.now() + customBlockSizeMs + 5000;
            expect(new Date(claims.block).getTime()).toBeGreaterThanOrEqual(expectedMinTime);
            expect(new Date(claims.block).getTime()).toBeLessThanOrEqual(expectedMaxTime);
            expect(typeof slipResult.token).toBe('string');
        }, 20000);

        test('should use provided blockTimestamp (string)', async () => {
            const specificTimestamp = futureBlockTime(120000);
            const slipResult = await client.generateSlip(specificTimestamp);
            expect(slipResult).not.toBeNull();
            if(!slipResult) return;
            const claims = slipResult.slipClaims as any;
            expect(claims.block).toBe(specificTimestamp);
            expect(typeof slipResult.token).toBe('string');
        }, 20000);

        test('should use provided targetScore', async () => {
            const customTargetScore = 2;
            const slipResult = await client.generateSlip(undefined, customTargetScore);
            expect(slipResult).not.toBeNull();
            if(!slipResult) return;
            expect(slipResult.actualScore).toBeGreaterThanOrEqual(customTargetScore);
            expect(typeof slipResult.token).toBe('string');
        }, 30000);
    });


    describe('Full Lifecycle Test (Genesis and Subsequent Slip)', () => {
      test('Genesis Slip and Subsequent Slip', async () => {
        const freshClient = await SlipkeyClient.create();

        const block1 = futureBlockTime();
        const slipResult1 = await freshClient.generateSlip(block1, defaultTestTargetScore);
        expect(slipResult1).not.toBeNull(); if (!slipResult1) return;
        // const clientToken1 = await freshClient.createClientToken(slipResult1.slipClaims); // Old way
        const clientToken1 = slipResult1.token; // New way

        const serverResponse1 = await processSlipAndIssueState(
          clientToken1, freshClient.getPublicJwk(), serverKeys.privateKey, wallets, block1, null, defaultTestTargetScore
        );
        if (serverResponse1.error !== undefined) throw new Error(`Genesis slip failed: ${serverResponse1.error}`);
        freshClient.processServerResponse(serverResponse1 as ServerSuccessResponse);
        expect(freshClient.state).toBe(serverResponse1.state);
        expect((serverResponse1 as ServerSuccessResponse).credit).toBe(1);

        const initialServerState = freshClient.state;
        const block2 = futureBlockTime();
        const slipResult2 = await freshClient.generateSlip(block2, defaultTestTargetScore);
        expect(slipResult2).not.toBeNull(); if (!slipResult2) return;
        expect((slipResult2.slipClaims as any).create).toBe(false);
        expect((slipResult2.slipClaims as any).state).toBe(initialServerState);
        // const clientToken2 = await freshClient.createClientToken(slipResult2.slipClaims); // Old way
        const clientToken2 = slipResult2.token; // New way

        const serverResponse2 = await processSlipAndIssueState(
          clientToken2, freshClient.getPublicJwk(), serverKeys.privateKey, wallets, block2, initialServerState, defaultTestTargetScore
        );
        if (serverResponse2.error !== undefined) throw new Error(`Subsequent slip failed: ${serverResponse2.error}`);
        expect(serverResponse2.state).not.toBe(initialServerState);
        expect((serverResponse2 as ServerSuccessResponse).len).toBe(1);
        freshClient.processServerResponse(serverResponse2 as ServerSuccessResponse);
        expect(freshClient.state).toBe(serverResponse2.state);
      }, 45000);
    });

    // Remove describe block for 'createClientToken()' as it's no longer a public method
    // describe('createClientToken()', () => { ... });

    describe('processServerResponse()', () => {
      test('should update client.state', async () => {
        const freshClient = await SlipkeyClient.create();
        const serverResponse = { state: 'newStateJWTFromServer' };
        freshClient.processServerResponse(serverResponse);
        expect(freshClient.state).toBe('newStateJWTFromServer');
      });
    });
  });

  describe('generateSlip create flag logic', () => {
    let client: SlipkeyClient;
    const blockTimestamp = new Date(Date.now() + 60000).toISOString();
    const targetScore = 1;

    beforeEach(async () => {
      client = await SlipkeyClient.create();
    });

    test('should set create=true when client.state is null and no override is given', async () => {
      expect(client.state).toBeNull();
      const result = await client.generateSlip(blockTimestamp, targetScore);
      expect(result).not.toBeNull();
      expect((result!.slipClaims as any).create).toBe(true);
      expect((result!.slipClaims as any).state).toBeNull();
      expect(typeof result!.token).toBe('string');
    });

    test('should set create=false when client.state has a value and no override is given', async () => {
      client.state = "dummy-server-jwt";
      const result = await client.generateSlip(blockTimestamp, targetScore);
      expect(result).not.toBeNull();
      expect((result!.slipClaims as any).create).toBe(false);
      expect((result!.slipClaims as any).state).toBe("dummy-server-jwt");
      expect(typeof result!.token).toBe('string');
    });

    test('should set create=true when currentServerStateOverride is null, regardless of client.state', async () => {
      client.state = "dummy-server-jwt";
      const result = await client.generateSlip(blockTimestamp, targetScore, null);
      expect(result).not.toBeNull();
      expect((result!.slipClaims as any).create).toBe(true);
      expect((result!.slipClaims as any).state).toBeNull();
      expect(typeof result!.token).toBe('string');
    });

    test('should set create=false when currentServerStateOverride is a string, regardless of client.state', async () => {
      client.state = null;
      const overrideState = "override-server-jwt";
      const result = await client.generateSlip(blockTimestamp, targetScore, overrideState);
      expect(result).not.toBeNull();
      expect((result!.slipClaims as any).create).toBe(false);
      expect((result!.slipClaims as any).state).toBe(overrideState);
      expect(typeof result!.token).toBe('string');
    });

    test('should set create=true when currentServerStateOverride is explicitly undefined and client.state is null', async () => {
      expect(client.state).toBeNull();
      const result = await client.generateSlip(blockTimestamp, targetScore, undefined);
      expect(result).not.toBeNull();
      expect((result!.slipClaims as any).create).toBe(true);
      expect((result!.slipClaims as any).state).toBeNull();
      expect(typeof result!.token).toBe('string');
    });

    test('should set create=false when currentServerStateOverride is explicitly undefined and client.state has a value', async () => {
      client.state = "dummy-server-jwt";
      const result = await client.generateSlip(blockTimestamp, targetScore, undefined);
      expect(result).not.toBeNull();
      expect((result!.slipClaims as any).create).toBe(false);
      expect((result!.slipClaims as any).state).toBe("dummy-server-jwt");
      expect(typeof result!.token).toBe('string');
    });
  });

  describe('updateDefaults()', () => {
    let client: SlipkeyClient;

    beforeEach(async () => {
      client = await SlipkeyClient.create();
    });

    test('should update defaultTargetScore correctly', () => {
      client.updateDefaults({ defaultTargetScore: 5 });
      expect((client as any).defaultTargetScore).toBe(5);
    });

    test('should update defaultBlockSizeMs correctly', () => {
      client.updateDefaults({ defaultBlockSizeMs: 90000 });
      expect((client as any).defaultBlockSizeMs).toBe(90000);
    });

    test('should update both parameters when provided', () => {
      client.updateDefaults({ defaultTargetScore: 10, defaultBlockSizeMs: 100000 });
      expect((client as any).defaultTargetScore).toBe(10);
      expect((client as any).defaultBlockSizeMs).toBe(100000);
    });

    test('should not change existing values if parameters are undefined', () => {
      const initialScore = (client as any).defaultTargetScore;
      const initialBlockSize = (client as any).defaultBlockSizeMs;

      client.updateDefaults({});
      expect((client as any).defaultTargetScore).toBe(initialScore);
      expect((client as any).defaultBlockSizeMs).toBe(initialBlockSize);

      client.updateDefaults({ defaultTargetScore: undefined, defaultBlockSizeMs: undefined });
      expect((client as any).defaultTargetScore).toBe(initialScore);
      expect((client as any).defaultBlockSizeMs).toBe(initialBlockSize);
    });

    test('should not update with invalid values (0 or negative) and warn', () => {
      const originalScore = (client as any).defaultTargetScore;
      const originalBlockSize = (client as any).defaultBlockSizeMs;
      const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      client.updateDefaults({ defaultTargetScore: 0 });
      expect((client as any).defaultTargetScore).toBe(originalScore);
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid defaultTargetScore'));

      consoleWarnSpy.mockClear();
      client.updateDefaults({ defaultTargetScore: -1 });
      expect((client as any).defaultTargetScore).toBe(originalScore);
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid defaultTargetScore'));

      consoleWarnSpy.mockClear();
      client.updateDefaults({ defaultBlockSizeMs: 0 });
      expect((client as any).defaultBlockSizeMs).toBe(originalBlockSize);
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid defaultBlockSizeMs'));

      consoleWarnSpy.mockClear();
      client.updateDefaults({ defaultBlockSizeMs: -100 });
      expect((client as any).defaultBlockSizeMs).toBe(originalBlockSize);
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid defaultBlockSizeMs'));

      consoleWarnSpy.mockRestore();
    });

    test('generateSlip should use updated defaults', async () => {
      const newScore = 2;
      const newBlockSizeMs = 75000;
      client.updateDefaults({ defaultTargetScore: newScore, defaultBlockSizeMs: newBlockSizeMs });

      const slipResult = await client.generateSlip();
      expect(slipResult).not.toBeNull();
      if (!slipResult) return;

      expect(slipResult.actualScore).toBeGreaterThanOrEqual(newScore);
      expect(typeof slipResult.token).toBe('string');

      const claims = slipResult.slipClaims as any;
      const expectedMinTime = Date.now() + newBlockSizeMs - 5000;
      const expectedMaxTime = Date.now() + newBlockSizeMs + 5000;
      expect(new Date(claims.block).getTime()).toBeGreaterThanOrEqual(expectedMinTime);
      expect(new Date(claims.block).getTime()).toBeLessThanOrEqual(expectedMaxTime);
    }, 30000);
  });

  describe('generateSlip PoW Failure Handling', () => {
    let clientForPowFailure: SlipkeyClient;
    const mockSolveProofOfWorkFn = jest.fn() as jest.MockedFunction<typeof OriginalPowTypes.solveProofOfWork>;

    beforeAll(async () => {
        jest.resetModules();
        jest.doMock('../src/pow', () => {
            // const originalPowModule = jest.requireActual('../src/pow') as typeof OriginalPowTypes; // Not needed if only mocking one function
            return {
                __esModule: true,
                solveProofOfWork: mockSolveProofOfWorkFn,
                // sha256: originalPowModule.sha256, // Only provide if client.ts imports it directly from pow.ts
            };
        });
        const { SlipkeyClient: ClientWithMockedPow } = await import('../src/client');
        clientForPowFailure = await ClientWithMockedPow.create();
    }, 30000);

    beforeEach(() => {
      mockSolveProofOfWorkFn.mockReset().mockResolvedValue(null);
    });

    afterAll(() => {
        jest.resetModules();
    });

    test('should return null if solveProofOfWork fails', async () => {
      const blockTimestamp = new Date().toISOString();
      const result = await clientForPowFailure.generateSlip(blockTimestamp);
      expect(result).toBeNull();
      expect(mockSolveProofOfWorkFn).toHaveBeenCalled();
    }, 30000);
  });

  describe('Error Handling (Conceptual)', () => {
    let client: SlipkeyClient;
    let serverKeys: ServerKeys;
    const wallets: Map<string, SlipWallet> = new Map();
    const defaultTestTargetScore = 1;
    const futureBlockTime = () => new Date(Date.now() + 1000 * 60).toISOString();

    beforeEach(async () => {
      client = await SlipkeyClient.create();
      serverKeys = await generateServerRsaKeys();
      wallets.clear();
    });

    test('client can generate a new slip if a previous conceptual submission failed', async () => {
      const block1 = futureBlockTime();
      const slipResult1 = await client.generateSlip(block1, defaultTestTargetScore);
      expect(slipResult1).not.toBeNull(); if (!slipResult1) return;

      const oldClientState = client.state;

      const block2 = futureBlockTime();
      const slipResult2 = await client.generateSlip(block2, defaultTestTargetScore);
      expect(slipResult2).not.toBeNull(); if (!slipResult2) return;

      expect((slipResult2.slipClaims as any).state).toBe(oldClientState);
      expect((slipResult2.slipClaims as any).create).toBe(oldClientState === null);

      // const clientToken2 = await client.createClientToken(slipResult2.slipClaims); // Old way
      const clientToken2 = slipResult2.token; // New way

      const serverResponse2 = await processSlipAndIssueState(
        clientToken2, client.getPublicJwk(), serverKeys.privateKey, wallets, block2, oldClientState, defaultTestTargetScore
      );

      if (serverResponse2.error !== undefined) {
        throw new Error(`Server processing failed for second slip: ${serverResponse2.error}`);
      }

      expect(serverResponse2.state).toBeDefined();
      client.processServerResponse(serverResponse2 as ServerSuccessResponse);
      expect(client.state).toBe(serverResponse2.state);

    }, 30000);
  });
});
