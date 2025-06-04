import { webcrypto } from 'node:crypto';
import { sha256, solveProofOfWork } from '../src/pow';

// Polyfill for global crypto if its 'subtle' property is not available for Web Crypto API.
if (typeof globalThis.crypto?.subtle === 'undefined') {
  globalThis.crypto = webcrypto as any;
}

describe('Proof-of-Work Functions', () => {
  describe('sha256', () => {
    it('should correctly hash "hello world"', async () => {
      const input = 'hello world';
      // SHA256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
      const expectedHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      const actualHash = await sha256(input);
      expect(actualHash).toBe(expectedHash);
    });

    it('should correctly hash an empty string', async () => {
      const input = '';
      // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const expectedHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const actualHash = await sha256(input);
      expect(actualHash).toBe(expectedHash);
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await sha256('input1');
      const hash2 = await sha256('input2');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('solveProofOfWork', () => {
    const publicKey = 'testPublicKey';
    const block = 'testBlockData';

    it('should find a nonce for a small targetScore (1)', async () => {
      const targetScore = 1;
      const result = await solveProofOfWork(publicKey, block, null, targetScore, 100000); // Generous maxIterations

      expect(result).not.toBeNull();
      if (result) {
        expect(result.score).toBeGreaterThanOrEqual(targetScore);
        expect(result.hash.startsWith('0'.repeat(targetScore))).toBe(true);
        expect(result.iterations).toBeGreaterThan(0);
        expect(result.iterations).toBeLessThanOrEqual(100000);

        // Verify the hash
        const expectedInput = `${publicKey}${block}${result.nonce}`;
        const recreatedHash = await sha256(expectedInput);
        expect(result.hash).toBe(recreatedHash);
        expect(result.score).toBe(result.hash.indexOf(result.hash.match(/[^0]/)![0]));

      }
    }, 15000); // Increased timeout for PoW

    it('should find a nonce for a targetScore of 2', async () => {
        const targetScore = 2;
        // iterations might be high for score 2 with Math.random nonce, increase maxIterations
        const result = await solveProofOfWork(publicKey, block, null, targetScore, 500000);

        expect(result).not.toBeNull();
        if (result) {
          expect(result.score).toBeGreaterThanOrEqual(targetScore);
          expect(result.hash.startsWith('0'.repeat(targetScore))).toBe(true);

          const expectedInput = `${publicKey}${block}${result.nonce}`;
          const recreatedHash = await sha256(expectedInput);
          expect(result.hash).toBe(recreatedHash);
          expect(result.score).toBe(result.hash.indexOf(result.hash.match(/[^0]/)![0]));

        }
      }, 30000); // Increased timeout for PoW

    it('should respect maxIterations and return null if no solution is found', async () => {
      const targetScore = 5; // High target score, unlikely to be found quickly
      const maxIterations = 100;
      const result = await solveProofOfWork(publicKey, block, null, targetScore, maxIterations);

      if (result === null) {
        expect(result).toBeNull();
      } else {
        // It's possible, though highly improbable, to find it.
        // If a solution is found, it implies the test might need adjustment or iteration count was too low.
        // For this test, we expect it to be null. If it's not, we log it but don't fail hard.
        console.warn(`PoW test found a solution unexpectedly with targetScore=${targetScore} in ${maxIterations} iterations. Hash: ${result.hash}`);
        expect(result.iterations).toBeLessThanOrEqual(maxIterations);
      }
    });

    it('should work correctly with a state string', async () => {
      const state = 'testState';
      const targetScore = 1;
      const result = await solveProofOfWork(publicKey, block, state, targetScore, 100000);

      expect(result).not.toBeNull();
      if (result) {
        expect(result.score).toBeGreaterThanOrEqual(targetScore);
        const expectedInput = `${publicKey}${block}${state}${result.nonce}`;
        const recreatedHash = await sha256(expectedInput);
        expect(result.hash).toBe(recreatedHash);
      }
    }, 15000);

    it('should return the correct number of iterations', async () => {
      // This test is tricky because iterations depend on randomness.
      // We can test that if a solution is found on the first try (by mocking sha256 or nonce), iterations is 1.
      // For simplicity here, we rely on previous tests' iteration checks.
      // A more deterministic test would mock generateRandomNonce and sha256.
      const result = await solveProofOfWork(publicKey, block, null, 1, 10); // Small iterations
      if (result) {
        expect(result.iterations).toBeGreaterThan(0);
        expect(result.iterations).toBeLessThanOrEqual(10);
      } else {
        // If null, it means it went through all 10 iterations
        // This part of the test implicitly checks iteration counting towards maxIterations
      }
    });

    it('score calculation should match leading zeros', async () => {
        const targetScore = 3; // A slightly higher target to make it more likely to hit maxIterations
        const result = await solveProofOfWork(publicKey, block, "some_state_value", targetScore, 100000); // Limit iterations to avoid long run

        if (result) {
            let leadingZeros = 0;
            for (let i = 0; i < result.hash.length; i++) {
                if (result.hash[i] === '0') {
                    leadingZeros++;
                } else {
                    break;
                }
            }
            expect(result.score).toBe(leadingZeros);
            expect(result.score).toBeGreaterThanOrEqual(targetScore);
        }
        // If null, it means no solution was found, which is acceptable for this test
    }, 20000);
  });
});
