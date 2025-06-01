import { webcrypto } from 'node:crypto';

// Ensure globalThis.crypto is available for Web Crypto API usage,
// especially if this code might run in environments where it's not standard (older Node.js, specific test setups)
// Jose already relies on this, but good to be explicit for direct Web Crypto API usage.
if (typeof globalThis.crypto?.subtle === 'undefined') {
  globalThis.crypto = webcrypto as any;
}

/**
 * Calculates the SHA-256 hash of a string.
 * Uses the Web Crypto API (crypto.subtle.digest).
 *
 * @param str The string to hash.
 * @returns A promise that resolves to the hexadecimal string representation of the hash.
 */
export async function sha256(str: string): Promise<string> {
  const data = new TextEncoder().encode(str);
  // WHERE_WAS_M_OPTIMIZATION_WOULD_GO:
  // For performance-critical applications, especially in environments where WebAssembly
  // is well-supported and offers advantages (e.g., browsers, or Node.js with a Wasm module),
  // a WebAssembly implementation of SHA-256 could be integrated here.
  // This might involve:
  // 1. Loading a Wasm module compiled from C, Rust, or AssemblyScript.
  // 2. Calling an exported Wasm function that performs the SHA-256 computation.
  // 3. Handling memory marshalling between JavaScript and Wasm.
  // Example: const hashBuffer = await wasmSha256(data);
  const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

/**
 * Solves a proof-of-work challenge.
 * Iteratively tries nonces until a hash with a sufficient number of leading zeros is found.
 *
 * @param publicKey The public key.
 * @param block The block data.
 * @param state Optional state string.
 * @param targetScore The required number of leading zeros in the hex hash.
 * @param maxIterations The maximum number of iterations to try. Defaults to 1,000,000.
 * @returns A promise that resolves to an object containing the nonce, score, hash, and iterations,
 *          or null if no solution is found within maxIterations.
 */
export async function solveProofOfWork(
  publicKey: string,
  block: string,
  state: string | null,
  targetScore: number,
  maxIterations: number = 1000000
): Promise<{ nonce: string, score: number, hash: string, iterations: number } | null> {
  const stateStr = state === null ? '' : state;

  for (let i = 0; i < maxIterations; i++) {
    const nonce = generateRandomNonce(); // Helper function to generate nonce
    const inputString = `${publicKey}${block}${stateStr}${nonce}`;
    const hash = await sha256(inputString);
    const score = calculateLeadingZeros(hash);

    if (score >= targetScore) {
      return {
        nonce,
        score,
        hash,
        iterations: i + 1,
      };
    }
  }
  return null;
}

/**
 * Generates a random nonce string.
 * The length and character set can be adjusted based on requirements.
 *
 * @param length The length of the nonce. Defaults to 16.
 * @returns A random nonce string.
 */
function generateRandomNonce(length: number = 16): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

/**
 * Calculates the number of leading zero characters in a hexadecimal hash string.
 *
 * @param hexHash The hexadecimal hash string.
 * @returns The number of leading zeros.
 */
function calculateLeadingZeros(hexHash: string): number {
  let count = 0;
  for (let i = 0; i < hexHash.length; i++) {
    if (hexHash[i] === '0') {
      count++;
    } else {
      break;
    }
  }
  return count;
}
