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

import type * as OriginalPowTypes from '../src/pow'; // For typing jest.requireActual


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
  describe('Standard Operations', () => {
    let client: SlipkeyClient;
    let serverKeys: ServerKeys;
    const wallets: Map<string, SlipWallet> = new Map();
    const targetScore = 1;
    const futureBlockTime = () => new Date(Date.now() + 1000 * 60).toISOString();

    beforeAll(async () => {
      client = await SlipkeyClient.create();
      serverKeys = await generateServerRsaKeys();
    });

    beforeEach(() => {
        wallets.clear();
        client.state = null;
    });

    describe('SlipkeyClient.create() and getters', () => {
        test('should create an instance of SlipkeyClient', async () => {
            const freshClient = await SlipkeyClient.create();
            expect(freshClient).toBeInstanceOf(SlipkeyClient);
        });

        test('should have a valid PEM public key via getPublicKey()', async () => {
            const publicKeyPem = client.getPublicKey();
            expect(typeof publicKeyPem).toBe('string');
            expect(publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
            expect(publicKeyPem).toMatch(/-----END PUBLIC KEY-----$/);
            await expect(jose.importSPKI(publicKeyPem, 'RS256')).resolves.toBeDefined();
        });

        test('should have a valid public JWK via getPublicJwk()', () => {
            const publicKeyJwk = client.getPublicJwk();
            expect(publicKeyJwk).toBeDefined();
            expect(publicKeyJwk.kty).toBe('RSA');
        });

        test('should have client.state initialized to null (on a freshly created client)', async () => {
            const freshClient = await SlipkeyClient.create();
            expect(freshClient.state).toBeNull();
        });
    });

    describe('Full Lifecycle Test (Genesis and Subsequent Slip)', () => {
      test('Genesis Slip: client generates slip, server validates and issues state, client processes', async () => {
        const block1 = futureBlockTime();
        const freshClient = await SlipkeyClient.create();

        const slipResult1 = await freshClient.generateSlip(block1, targetScore);
        expect(slipResult1).not.toBeNull();
        if (!slipResult1) return;

        const clientToken1 = await freshClient.createClientToken(slipResult1.slipClaims);

        const serverResponse1 = await processSlipAndIssueState(
          clientToken1, freshClient.getPublicJwk(), serverKeys.privateKey, wallets, block1, null, targetScore
        );

        if (serverResponse1.error !== undefined) {
          throw new Error(`Server processing failed for genesis slip: ${serverResponse1.error}`);
        }

        expect(serverResponse1.state).toBeDefined();
        expect(serverResponse1.credit).toBe(1);

        freshClient.processServerResponse(serverResponse1 as ServerSuccessResponse);
        expect(freshClient.state).toBe(serverResponse1.state);
      }, 30000);

      test('Subsequent Slip: client uses new state, server validates, client processes', async () => {
        const freshClient = await SlipkeyClient.create();
        const block1 = futureBlockTime();
        const slipResult1 = await freshClient.generateSlip(block1, targetScore);
        expect(slipResult1).not.toBeNull(); if (!slipResult1) return;
        const clientToken1 = await freshClient.createClientToken(slipResult1.slipClaims);
        const serverResponse1 = await processSlipAndIssueState(
            clientToken1, freshClient.getPublicJwk(), serverKeys.privateKey, wallets, block1, null, targetScore
        );
        if (serverResponse1.error !== undefined) throw new Error("Genesis failed in subsequent slip test setup: " + serverResponse1.error);
        freshClient.processServerResponse(serverResponse1 as ServerSuccessResponse);

        const initialServerState = freshClient.state;
        expect(initialServerState).not.toBeNull(); if(!initialServerState) return;

        const block2 = futureBlockTime();
        const slipResult2 = await freshClient.generateSlip(block2, targetScore);
        expect(slipResult2).not.toBeNull(); if (!slipResult2) return;

        expect((slipResult2.slipClaims as any).create).toBe(false);
        expect((slipResult2.slipClaims as any).state).toBe(initialServerState);

        const clientToken2 = await freshClient.createClientToken(slipResult2.slipClaims);
        const serverResponse2 = await processSlipAndIssueState(
          clientToken2, freshClient.getPublicJwk(), serverKeys.privateKey, wallets, block2, initialServerState, targetScore
        );

        if (serverResponse2.error !== undefined) {
          throw new Error(`Server processing failed for subsequent slip: ${serverResponse2.error}`);
        }

        expect(serverResponse2.state).not.toBe(initialServerState);
        expect(serverResponse2.credit).toBeGreaterThanOrEqual(1);
        expect(serverResponse2.len).toBe(1);

        freshClient.processServerResponse(serverResponse2 as ServerSuccessResponse);
        expect(freshClient.state).toBe(serverResponse2.state);
      }, 30000);
    });

    describe('createClientToken()', () => {
      test('should create a valid JWT string', async () => {
        const freshClient = await SlipkeyClient.create();
        const sampleSlipClaims = {
          pubkey: freshClient.getPublicJwk(),
          block: new Date().toISOString(),
          nonce: 'testNonce123',
          state: null,
          create: true,
        };
        const token = await freshClient.createClientToken(sampleSlipClaims);
        expect(typeof token).toBe('string');

        const { payload } = await verifyJwt(token, freshClient.getPublicJwk());
        expect(payload.pubkey).toEqual(sampleSlipClaims.pubkey);
        expect(payload.block).toBe(sampleSlipClaims.block);
      });
    });

    describe('processServerResponse()', () => {
      test('should update client.state', async () => {
        const freshClient = await SlipkeyClient.create();
        const serverResponse = { state: 'newStateJWTFromServer' };
        freshClient.processServerResponse(serverResponse);
        expect(freshClient.state).toBe('newStateJWTFromServer');
      });
    });
  }); // End of Standard Operations describe

  describe('generateSlip PoW Failure Handling', () => {
    let clientForPowFailure: SlipkeyClient;
    const mockSolveProofOfWorkFn = jest.fn() as jest.MockedFunction<typeof OriginalPowTypes.solveProofOfWork>;

    beforeAll(async () => {
        jest.resetModules();
        jest.doMock('../src/pow', () => {
            const originalPowModule = jest.requireActual('../src/pow') as typeof OriginalPowTypes;
            return {
                __esModule: true,
                solveProofOfWork: mockSolveProofOfWorkFn,
                sha256: originalPowModule.sha256,
            };
        });
        const { SlipkeyClient: ClientWithMockedPow } = await import('../src/client');
        clientForPowFailure = await ClientWithMockedPow.create();
    }, 30000); // Increased timeout for beforeAll to 30s

    beforeEach(() => {
      mockSolveProofOfWorkFn.mockReset().mockResolvedValue(null);
    });

    afterAll(() => {
        jest.resetModules();
    });

    test('should return null if solveProofOfWork fails', async () => {
      const blockTimestamp = new Date().toISOString();
      const result = await clientForPowFailure.generateSlip(blockTimestamp, 5);
      expect(result).toBeNull();
      expect(mockSolveProofOfWorkFn).toHaveBeenCalled();
    }, 30000); // Increased timeout for this test to 30s
  });

  describe('Error Handling (Conceptual)', () => {
    let client: SlipkeyClient;
    let serverKeys: ServerKeys;
    const wallets: Map<string, SlipWallet> = new Map();
    const targetScore = 1;
    const futureBlockTime = () => new Date(Date.now() + 1000 * 60).toISOString();

    beforeEach(async () => {
      client = await SlipkeyClient.create();
      serverKeys = await generateServerRsaKeys();
      wallets.clear();
    });

    test('client can generate a new slip if a previous conceptual submission failed', async () => {
      const block1 = futureBlockTime();
      const slipResult1 = await client.generateSlip(block1, targetScore);
      expect(slipResult1).not.toBeNull(); if (!slipResult1) return;

      const oldClientState = client.state;

      const block2 = futureBlockTime();
      const slipResult2 = await client.generateSlip(block2, targetScore);
      expect(slipResult2).not.toBeNull(); if (!slipResult2) return;

      expect((slipResult2.slipClaims as any).state).toBe(oldClientState);
      expect((slipResult2.slipClaims as any).create).toBe(oldClientState === null);

      const clientToken2 = await client.createClientToken(slipResult2.slipClaims);
      const serverResponse2 = await processSlipAndIssueState(
        clientToken2, client.getPublicJwk(), serverKeys.privateKey, wallets, block2, oldClientState, targetScore
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
