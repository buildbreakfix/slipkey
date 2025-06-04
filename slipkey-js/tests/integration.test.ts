import { jest } from '@jest/globals';
import { SlipkeyClient, SlipkeyClientConfig } from '../src/client';
import { SlipkeyServer, SlipkeyServerConfig as ServerConfig } from '../src/server';
import { verifyJwt, generateRsaKeyPair, jwkToSpkiPem } from '../src/crypto';
import * as jose from 'jose';
import { webcrypto } from 'node:crypto';

// Polyfill for global crypto
if (typeof globalThis.crypto?.subtle === 'undefined') {
  globalThis.crypto = webcrypto as any;
}

// Jest timeout for potentially long-running PoW
jest.setTimeout(30000);

type ServerSuccessResponse = {
  newServerStateToken: string;
  score: number;
  creditEarned: number;
  chainLength: number;
  isBelowTargetScore: boolean; // New field
  error?: undefined;
};

describe('Slipkey Client-Server Integration Tests', () => {
  let client: SlipkeyClient;
  let server: SlipkeyServer;

  beforeEach(async () => {
    client = await SlipkeyClient.create();
    server = await SlipkeyServer.create();
  });

  test('Full Lifecycle: Genesis Slip -> Subsequent Slip', async () => {
    // --- Genesis Slip ---
    const genesisResult = await client.generateSlip();
    expect(genesisResult).not.toBeNull();
    if (!genesisResult) return;

    expect(genesisResult.token).toBeDefined();
    expect(typeof genesisResult.token).toBe('string');
    expect((genesisResult.slipClaims as any).create).toBe(true);

    const serverResponse1 = await server.processClientToken(genesisResult.token);

    if (serverResponse1.error !== undefined) {
      throw new Error(`Server failed on genesis slip: ${serverResponse1.error}`);
    }
    expect(serverResponse1.isBelowTargetScore).toBe(false); // Assuming client target (1) meets server default target (1)

    expect(serverResponse1.newServerStateToken).toBeDefined();
    expect(typeof serverResponse1.newServerStateToken).toBe('string');

    const serverPubKeyJwk = server.getPublicKeyJwk();
    const { payload: serverStatePayload1 } = await verifyJwt(serverResponse1.newServerStateToken, serverPubKeyJwk);
    expect(serverStatePayload1.len).toBe(1);
    expect(serverStatePayload1.credit as number).toBeGreaterThanOrEqual(1);

    const clientJwkForComparison1 = client.getPublicJwk();
    const serverStateClientPublicKey1 = serverStatePayload1.publicKey as jose.JWK;
    expect(serverStateClientPublicKey1.kty).toEqual(clientJwkForComparison1.kty);
    expect(serverStateClientPublicKey1.n).toEqual(clientJwkForComparison1.n);
    expect(serverStateClientPublicKey1.e).toEqual(clientJwkForComparison1.e);
    expect(serverStateClientPublicKey1.alg).toEqual(clientJwkForComparison1.alg || 'RS256');


    client.processServerResponse({
      state: serverResponse1.newServerStateToken,
      credit: serverResponse1.creditEarned,
      len: serverResponse1.chainLength,
      block: (genesisResult.slipClaims as any).block,
    });
    expect(client.state).toBe(serverResponse1.newServerStateToken);

    // --- Subsequent Slip ---
    const subsequentResult = await client.generateSlip();
    expect(subsequentResult).not.toBeNull();
    if (!subsequentResult) return;

    expect(subsequentResult.token).toBeDefined();
    expect((subsequentResult.slipClaims as any).create).toBe(false);
    expect((subsequentResult.slipClaims as any).state).toBe(serverResponse1.newServerStateToken);

    const serverResponse2 = await server.processClientToken(subsequentResult.token);

    if (serverResponse2.error !== undefined) {
      throw new Error(`Server failed on subsequent slip: ${serverResponse2.error}`);
    }
    expect(serverResponse2.isBelowTargetScore).toBe(false); // Assuming client target (1) meets server default target (1)

    expect(serverResponse2.newServerStateToken).toBeDefined();
    const { payload: serverStatePayload2 } = await verifyJwt(serverResponse2.newServerStateToken, serverPubKeyJwk);
    expect(serverStatePayload2.len).toBe(2);
    // Compare total credit in payload2 vs total credit in payload1
    expect(serverStatePayload2.credit as number).toBeGreaterThan(serverStatePayload1.credit as number);

    client.processServerResponse({ state: serverResponse2.newServerStateToken, credit: serverResponse2.creditEarned, len: serverResponse2.chainLength, block: (subsequentResult.slipClaims as any).block });
    expect(client.state).toBe(serverResponse2.newServerStateToken);
  });

  test('Client using an imported key can successfully interact with server', async () => {
    const client1 = await SlipkeyClient.create();
    const privateKeyJwk = client1.exportPrivateKeyJwk();
    const originalPublicKeyJwk = client1.getPublicJwk();

    const client2 = await SlipkeyClient.create({ initialPrivateKeyJwk: privateKeyJwk });
    const client2PublicJwk = client2.getPublicJwk();
    expect(client2PublicJwk.n).toEqual(originalPublicKeyJwk.n);
    expect(client2PublicJwk.e).toEqual(originalPublicKeyJwk.e);
    expect(client2PublicJwk.kty).toEqual(originalPublicKeyJwk.kty);
    expect(client2PublicJwk.alg).toEqual(originalPublicKeyJwk.alg || 'RS256');


    const genesisResultClient2 = await client2.generateSlip();
    expect(genesisResultClient2).not.toBeNull();
    if (!genesisResultClient2) return;
    expect(genesisResultClient2.token).toBeDefined();

    const slipClaimsPubJwk = (genesisResultClient2.slipClaims as any).pubkey as jose.JWK;
    expect(slipClaimsPubJwk.n).toEqual(originalPublicKeyJwk.n);
    expect(slipClaimsPubJwk.e).toEqual(originalPublicKeyJwk.e);
    expect(slipClaimsPubJwk.alg).toEqual(originalPublicKeyJwk.alg || 'RS256');


    const testServer = await SlipkeyServer.create();
    const serverResponse = await testServer.processClientToken(genesisResultClient2.token);

    if (serverResponse.error !== undefined) {
      throw new Error(`Server failed to process token from re-initialized client: ${serverResponse.error}`);
    }
    expect(serverResponse.newServerStateToken).toBeDefined();

    const serverStatePayload = (await verifyJwt(serverResponse.newServerStateToken, testServer.getPublicKeyJwk())).payload;
    const serverStateClientPublicKey = serverStatePayload.publicKey as jose.JWK;
    const client2JwkForComparison = client2.getPublicJwk();

    expect(serverStateClientPublicKey.kty).toEqual(client2JwkForComparison.kty);
    expect(serverStateClientPublicKey.n).toEqual(client2JwkForComparison.n);
    expect(serverStateClientPublicKey.e).toEqual(client2JwkForComparison.e);
    expect(serverStateClientPublicKey.alg).toEqual(client2JwkForComparison.alg || 'RS256');

    expect(serverStatePayload.len).toBe(1);
  });

  test('Server should return error for a corrupted/invalid client token', async () => {
    const validResult = await client.generateSlip();
    expect(validResult).not.toBeNull();
    if (!validResult) return;

    const corruptedToken = validResult.token.slice(0, -10) + "XXXXXcorrupt";

    const errorResponse = await server.processClientToken(corruptedToken);
    expect(errorResponse.error).toBeDefined();
    expect(typeof errorResponse.error).toBe('string');
  });

  test('should process slip with score below server expectedTargetScore as valid but with adjusted credit', async () => {
    // Client aims for score 1 (default)
    const clientForLowScore = await SlipkeyClient.create({ defaultTargetScore: 1 });
    let result = await clientForLowScore.generateSlip(undefined, 1);

    let attempts = 0;
    while(result && result.actualScore !== 1 && attempts < 20) {
        result = await clientForLowScore.generateSlip(undefined, 1);
        attempts++;
    }
    expect(result).not.toBeNull(); if (!result) return;
    // Ensure actual score is 1 for this test's credit logic to be precise
    expect(result.actualScore).toBe(1);


    const serverExpectedScore = 2; // Server expects a higher score
    const serverResponse = await server.processClientToken(result.token, serverExpectedScore);

    expect(serverResponse.error).toBeUndefined(); // Should be a success response
    if (serverResponse.error) throw new Error(`Test failed, expected success but got: ${serverResponse.error}`);

    const successResponse = serverResponse as Required<Omit<typeof serverResponse, 'error'>>;
    expect(successResponse.isBelowTargetScore).toBe(true); // score 1 is less than expected 2
    expect(successResponse.score).toBe(1);
    // For genesis slip, with default credit logic, and score below target, total credit is 0.
    expect(successResponse.creditEarned).toBe(0);
    expect(successResponse.chainLength).toBe(1);

    const { payload: serverStatePayload } = await verifyJwt(successResponse.newServerStateToken, server.getPublicKeyJwk());
    expect(serverStatePayload.credit).toBe(0);
  }, 30000);

  test('should process slip with score meeting server expectedTargetScore with normal credit', async () => {
    const clientForNormalScore = await SlipkeyClient.create({ defaultTargetScore: 2 });
    let result = await clientForNormalScore.generateSlip(undefined, 2); // Client aims for score 2

    let attempts = 0;
    while(result && result.actualScore < 2 && attempts < 30) { // Try harder to get score 2+
        result = await clientForNormalScore.generateSlip(undefined, 2);
        attempts++;
    }
    expect(result).not.toBeNull(); if (!result) return;
    expect(result.actualScore).toBeGreaterThanOrEqual(2);

    const serverExpectedScore = 2; // Server also expects score 2
    const serverResponse = await server.processClientToken(result.token, serverExpectedScore);

    expect(serverResponse.error).toBeUndefined();
    if (serverResponse.error) throw new Error(`Test failed, expected success but got: ${serverResponse.error}`);

    const successResponse = serverResponse as Required<Omit<typeof serverResponse, 'error'>>;
    expect(successResponse.isBelowTargetScore).toBe(false);
    expect(successResponse.score).toBe(result.actualScore);
    // For genesis slip, with default credit logic, and score meeting target: (actualScore * 10) + chainLength (1)
    expect(successResponse.creditEarned).toBe((result.actualScore * 10) + 1);
    expect(successResponse.chainLength).toBe(1);

    const { payload: serverStatePayload } = await verifyJwt(successResponse.newServerStateToken, server.getPublicKeyJwk());
    expect(serverStatePayload.credit).toBe(successResponse.creditEarned);
  }, 40000);

});
