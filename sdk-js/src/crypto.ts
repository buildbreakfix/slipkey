import * as jose from 'jose';

/**
 * Generates an RSA key pair (public and private keys).
 * Uses 'RS256' algorithm suitable for JWT signing.
 * Keys are marked as extractable to allow exporting to JWK format.
 * Ensures 'alg': 'RS256' is included in the exported JWKs.
 *
 * @returns A promise that resolves to an object containing the public and private keys in JWK format.
 */
export async function generateRsaKeyPair(): Promise<{ publicKey: jose.JWK; privateKey: jose.JWK }> {
  const { publicKey: pkCryptoKey, privateKey: privCryptoKey } = await jose.generateKeyPair('RS256', {
    modulusLength: 2048, // Standard modulus length for RSA
    extractable: true,   // Allows keys to be exported to JWK format
  });

  const publicJwk = await jose.exportJWK(pkCryptoKey);
  const privateJwk = await jose.exportJWK(privCryptoKey); // Removed 'true' argument

  // Ensure 'alg' is present for consistency, as other parts of the system might add/expect it.
  publicJwk.alg = 'RS256';
  privateJwk.alg = 'RS256';

  return { publicKey: publicJwk, privateKey: privateJwk };
}

/**
 * Signs a payload and creates a JWT.
 *
 * @param payload The payload to sign (must be a plain object).
 * @param privateKeyJwk The private key in JWK format.
 * @returns A promise that resolves to the JWT string.
 */
export async function signJwt(payload: jose.JWTPayload, privateKeyJwk: jose.JWK): Promise<string> {
  // Ensure alg is present in JWK for import, default if necessary
  const alg = privateKeyJwk.alg || 'RS256';
  const privateKey = await jose.importJWK({...privateKeyJwk, alg }, alg);
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256' }) // Standardize on RS256 for signing
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
  // Ensure alg is present in JWK for import, default if necessary
  const alg = publicKeyJwk.alg || 'RS256';
  const publicKey = await jose.importJWK({...publicKeyJwk, alg }, alg);
  const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey, {
    algorithms: ['RS256'], // Explicitly expect RS256 signed tokens
  });
  return { payload, protectedHeader };
}

/**
 * Converts a public JWK to PEM format (SPKI).
 *
 * @param keyJwk The public key in JWK format.
 * @returns A promise that resolves to the PEM string representation of the public key (SPKI format).
 */
export async function jwkToSpkiPem(keyJwk: jose.JWK): Promise<string> {
  const keyAlgorithm = keyJwk.alg || 'RS256';
  const publicKey = await jose.importJWK({...keyJwk, alg: keyAlgorithm }, keyAlgorithm) as CryptoKey;
  const pem = await jose.exportSPKI(publicKey);
  return pem;
}
