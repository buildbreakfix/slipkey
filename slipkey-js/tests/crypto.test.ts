import { webcrypto } from 'node:crypto';

// Polyfill for global crypto if its 'subtle' property is not available.
// Jose relies on globalThis.crypto.subtle.
// Node.js versions 15+ should have crypto.subtle available globally,
// but test environments or specific Node configurations might differ.
if (typeof globalThis.crypto?.subtle === 'undefined') {
  // Assign the Node.js webcrypto implementation to globalThis.crypto.
  // This makes crypto.subtle available for jose.
  globalThis.crypto = webcrypto as any;
}

import { generateRsaKeyPair, signJwt, verifyJwt, jwkToSpkiPem } from '../src/crypto';
import * as jose from 'jose';

describe('Crypto Functions', () => {
  let keyPair: { publicKey: jose.JWK; privateKey: jose.JWK };

  beforeAll(async () => {
    keyPair = await generateRsaKeyPair();
  });

  it('generateRsaKeyPair should return public and private keys', () => {
    expect(keyPair).toBeDefined();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
    expect(keyPair.publicKey.kty).toBe('RSA');
    expect(keyPair.privateKey.kty).toBe('RSA');
    // Check for 'alg' field added in generateRsaKeyPair
    expect(keyPair.publicKey.alg).toBe('RS256');
    expect(keyPair.privateKey.alg).toBe('RS256');
  });

  it('signJwt and verifyJwt should correctly sign and verify a JWT', async () => {
    const payload = { userId: 'testUser123', data: 'some important data' };
    const jwt = await signJwt(payload, keyPair.privateKey);

    expect(typeof jwt).toBe('string');

    const { payload: verifiedPayload } = await verifyJwt(jwt, keyPair.publicKey);

    expect(verifiedPayload.userId).toBe(payload.userId);
    expect(verifiedPayload.data).toBe(payload.data);
    expect(verifiedPayload.iss).toBeUndefined(); // No issuer set in this example
    expect(verifiedPayload.aud).toBeUndefined(); // No audience set
  });

  it('verifyJwt should fail with a different public key', async () => {
    const payload = { userId: 'testUser456' };
    const jwt = await signJwt(payload, keyPair.privateKey);

    // Generate a new, different key pair
    const differentKeyPair = await generateRsaKeyPair();

    await expect(verifyJwt(jwt, differentKeyPair.publicKey))
      .rejects
      .toThrowError(jose.errors.JWSSignatureVerificationFailed);
  });

  it('verifyJwt should fail for an expired JWT', async () => {
    const payload = { userId: 'testUser789' };
    // Sign a JWT that expires immediately
    const privateKeyForJose = await jose.importJWK(keyPair.privateKey, 'RS256');
    const expiredJwt = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('0s') // Expires immediately
      .sign(privateKeyForJose);

    // Allow a small delay for the token to definitely be expired
    await new Promise(resolve => setTimeout(resolve, 50));


    await expect(verifyJwt(expiredJwt, keyPair.publicKey))
      .rejects
      .toThrowError(jose.errors.JWTExpired);
  });

  it('verifyJwt should fail for a JWT signed with a different private key', async () => {
    const payload = { userId: 'testUser101' };
    const differentKeyPair = await generateRsaKeyPair(); // Sign with a different private key
    const jwtSignedWithOtherKey = await signJwt(payload, differentKeyPair.privateKey);

    // Try to verify with the original public key
    await expect(verifyJwt(jwtSignedWithOtherKey, keyPair.publicKey))
      .rejects
      .toThrowError(jose.errors.JWSSignatureVerificationFailed);
  });
});
