import * as jose from 'jose';

/**
 * Generates an RSA key pair (public and private keys).
 * Uses 'RS256' algorithm suitable for JWT signing.
 * Keys are marked as extractable to allow exporting to JWK format.
 *
 * @returns A promise that resolves to an object containing the public and private keys in JWK format.
 */
export async function generateRsaKeyPair(): Promise<{ publicKey: jose.JWK; privateKey: jose.JWK }> {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
    modulusLength: 2048, // Standard modulus length for RSA
    extractable: true,   // Allows keys to be exported to JWK format
  });
  return { publicKey: await jose.exportJWK(publicKey), privateKey: await jose.exportJWK(privateKey) };
}

/**
 * Signs a payload and creates a JWT.
 *
 * @param payload The payload to sign (must be a plain object).
 * @param privateKeyJwk The private key in JWK format.
 * @returns A promise that resolves to the JWT string.
 */
export async function signJwt(payload: jose.JWTPayload, privateKeyJwk: jose.JWK): Promise<string> {
  const privateKey = await jose.importJWK(privateKeyJwk, 'RS256');
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt()
    .setExpirationTime('2h') // Example expiration time
    .sign(privateKey);
  return jwt;
}

/**
 * Verifies a JWT using a public key.
 *
 * @param jwt The JWT string to verify.
 * @param publicKeyJwk The public key in JWK format.
 * @returns A promise that resolves to the decoded payload if verification is successful.
 * @throws Error if verification fails (e.g., signature mismatch, expired token).
 */
export async function verifyJwt(jwt: string, publicKeyJwk: jose.JWK): Promise<jose.JWTVerifyResult> {
  const publicKey = await jose.importJWK(publicKeyJwk, 'RS256');
  const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey);
  return { payload, protectedHeader };
}

/**
 * Converts a public JWK to PEM format.
 *
 * @param keyJwk The public key in JWK format.
 * @returns A promise that resolves to the PEM string representation of the public key (SPKI format).
 */
export async function jwkToSpkiPem(keyJwk: jose.JWK): Promise<string> {
  const keyAlgorithm = keyJwk.alg || 'RS256';
  // For RSA public keys, importJWK should return a CryptoKey object when using Web Crypto.
  // The broader return type of importJWK (KeyLike | Uint8Array) includes Uint8Array for symmetric keys.
  // We assert to CryptoKey as we expect an RSA public key here and exportSPKI needs CryptoKey or KeyObject.
  const publicKey = await jose.importJWK(keyJwk, keyAlgorithm) as CryptoKey;
  const pem = await jose.exportSPKI(publicKey);
  return pem;
}
