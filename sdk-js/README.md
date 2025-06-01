# Slipkey SDK for JavaScript/TypeScript

## Introduction

Slipkey is a lightweight, stateless authentication mechanism designed for scenarios where traditional session management is cumbersome or undesirable. It uses a combination of JWTs and a client-side Proof-of-Work (PoW) challenge to provide a "slip" that a client can present to a server for authentication or authorization. For more details on the Slipkey standard, please refer to the [main project README](../../README.md).

This SDK provides a `SlipkeyClient` class to help developers integrate Slipkey into their JavaScript or TypeScript applications, abstracting the cryptographic operations and PoW logic.

## Features

*   Compliant with the Slipkey authentication standard.
*   Supports both Node.js (version 16+) and modern web browsers via Web Crypto API.
*   Generates RSA key pairs for client identity.
*   Implements client-side SHA-256 based Proof-of-Work.
*   Creates and manages client-side JWTs (slips).
*   Provides methods for interacting with a Slipkey-compatible server flow.
*   Written in TypeScript, providing type safety.

## Installation

To install the Slipkey SDK, use npm (or your preferred package manager):

```bash
npm install slipkey-sdk
```
*(Note: `slipkey-sdk` is a placeholder package name. Replace with the actual package name when published.)*

## Getting Started / Basic Usage

### Importing

**TypeScript / ES Modules (e.g., Node.js, Webpack, Rollup):**
```typescript
import { SlipkeyClient } from 'slipkey-sdk';
```

**JavaScript (ES Modules):**
```javascript
// Ensure your environment supports ES modules (e.g., Node.js with "type": "module" in package.json)
import { SlipkeyClient } from 'slipkey-sdk';
// Or, if using a direct bundle file (e.g., for older browser setups without a bundler):
// import { SlipkeyClient } from './path/to/slipkey-sdk.esm.js';
```

### Client Initialization

The client needs to generate its own RSA key pair for signing slips. This is done asynchronously.

```typescript
async function initializeClient(): Promise<SlipkeyClient> {
  // The create method handles asynchronous key generation.
  const client = await SlipkeyClient.create();

  console.log("Client Public Key (PEM format):", client.getPublicKey());
  console.log("Client Public Key (JWK format):", client.getPublicJwk());
  // Initial client state is null (no previous interaction with server)
  console.log("Initial client state:", client.state);

  return client;
}

// Usage:
// initializeClient().then(client => {
//   // Use the client instance here
// });
```

### Generating a Slip (Genesis / First Slip)

A "slip" is essentially a request for a new session or state from the server. The first slip is a "genesis" slip.

```typescript
import { SlipkeyClient } from 'slipkey-sdk'; // Assuming this is in a module

async function generateFirstSlip(client: SlipkeyClient) {
  // blockTimestamp should ideally be a recent or future timestamp agreed upon with the server,
  // or a server-provided challenge. For example, 1 minute in the future:
  const blockTimestamp = new Date(Date.now() + 60000).toISOString();
  const targetScore = 1; // Minimum PoW score required (number of leading zeros in hash)

  console.log(`Attempting to generate genesis slip for block: ${blockTimestamp}`);
  // For the first slip, client.state is null, so currentServerStateOverride is omitted or null.
  const slipResult = await client.generateSlip(blockTimestamp, targetScore);

  if (slipResult) {
    console.log("Genesis slip generated successfully!");
    console.log("  Slip Claims:", slipResult.slipClaims);
    console.log("  PoW Nonce:", slipResult.nonce);
    console.log("  PoW Hash:", slipResult.hash);
    console.log("  PoW Score (actual):", slipResult.actualScore);

    // Create the client token (JWT) from the slip claims
    const clientToken = await client.createClientToken(slipResult.slipClaims);
    console.log("Client Token (JWT to send to server):", clientToken);

    return clientToken;
  } else {
    console.error("Failed to generate genesis slip (PoW might have failed or client not initialized).");
    return null;
  }
}

// Example usage:
// initializeClient().then(async (client) => {
//   const token = await generateFirstSlip(client);
//   if (token) {
//     // Send token to server...
//   }
// });
```

### Simulating Server Interaction (Conceptual)

The `clientToken` generated above would be sent to a Slipkey-compatible server. The server validates the token (including the PoW and signature) and, if valid, issues a new "state" JWT back to the client.

```typescript
// Assume 'client' is an initialized SlipkeyClient instance that has generated a token.

// This is a conceptual server response.
// The actual response structure might vary slightly but must include 'state'.
const mockServerResponse = {
  state: "eyJhbGciOiJSUzI1NiIsImtpZCI6InNrvInR5cCI6IkpXVCJ9.eyJzdWIiOiItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxuTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFvSUFpVjBjUm1VMFpyelJ6ZEdBOFE5YXcxSTc5Y3BOaCtQL1xubTVVMitEWFZzY1hFNk5SVVBJMHNsZTJWQVZDbHRxWlREWDg1MVd0eFd2b2lFVzd1Z0o2SFdnN1RScEhHY2ducU93cWNNWlV6LXlMQTBUbmxua0VRdzBUbnRYMlNVWk5Xa2gxdmMyNm5pdDZWZ0dXK2xKQTJia1oxMEovU1BhZ2xhSHFvc01Pc0R5MUhLTTYwZytXWk44UWpaVUxXR0VJRGYrUG0xbHRyQTF3VVF3b1dyb21BTElTV0paRDhsU0o3OVN0aVlUR2F4M1FoSzJSc3k2ZzFLQjE2SXR1NVFuY3dzNlRqNzR4TTFhaThoZjV5VDR3NjVFVjBIbzN4WUw4by9laFBqZTJLak5qdU5icDdUT0JETEgyWXFRbVhxWERKbGw1d0lnZW1TOUY0WDR0ZStkOWNRSURBUUFCLlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iLCJpc3MiOiJTbGlwa2V5U2VydmVyIiwiaWF0IjoxNzE3MjgzMjg2LCJleHAiOjE3MTcyODY4ODYsImNyZWRpdCI6MSwibGVuIjowLCJibG9jayI6IjIwMjUtMDUtMzFUMjI6NDU6MDQuNzg3WiJ9.exampleSignature", // New JWT from the server
  len: 0,
  credit: 1,
  block: "2025-05-31T22:45:04.787Z", // Block corresponding to this new state
  expires: Math.floor(Date.now() / 1000) + 3600 // Example expiration
};

// Client processes this response to update its internal state
client.processServerResponse(mockServerResponse);
console.log("Client state updated. New current state (JWT from server):", client.state);
```

### Generating a Subsequent Slip

Once the client has a state from the server, subsequent slips will use this state.

```typescript
async function generateNextSlip(client: SlipkeyClient) {
  if (!client.state) {
    console.error("Client has no state. Cannot generate a subsequent slip.");
    return null;
  }

  const blockTimestamp = new Date(Date.now() + 60000).toISOString(); // New block time
  const targetScore = 1;

  console.log(`Attempting to generate subsequent slip for block: ${blockTimestamp}`);
  // client.generateSlip will automatically use client.state if currentServerStateOverride is not provided.
  const slipResult = await client.generateSlip(blockTimestamp, targetScore);

  if (slipResult) {
    console.log("Subsequent slip generated successfully!");
    console.log("  Slip Claims:", slipResult.slipClaims); // Note: create flag should be false
    console.log("  PoW Nonce:", slipResult.nonce);
    console.log("  PoW Score (actual):", slipResult.actualScore);

    const clientToken = await client.createClientToken(slipResult.slipClaims);
    console.log("Client Token for subsequent slip:", clientToken);

    // This new token would be sent to the server.
    // The server would validate it against its expected state (the previous JWT it sent).
    // client.processServerResponse(...) would be called with the server's new response.
    return clientToken;
  } else {
    console.error("Failed to generate subsequent slip.");
    return null;
  }
}

// Example usage (assuming client has state from a previous interaction):
// if (client.state) {
//   generateNextSlip(client).then(nextToken => {
//     if (nextToken) { /* send to server */ }
//   });
// }
```

## API Reference (Brief)

Let `client` be an instance of `SlipkeyClient`.

*   **`static async SlipkeyClient.create(): Promise<SlipkeyClient>`**
    Asynchronously creates and initializes a new client instance, including its RSA key pair.

*   **`client.getPublicKey(): string`**
    Returns the client's public key in SPKI PEM format.

*   **`client.getPublicJwk(): jose.JWK`**
    Returns the client's public key in JWK format.

*   **`client.generateSlip(blockTimestamp: string, targetScore: number = 1, currentServerStateOverride?: string | null): Promise<SlipResult | null>`**
    Generates a slip.
    *   `blockTimestamp`: ISO 8601 string for the "block" claim.
    *   `targetScore`: Required PoW score (leading zeros). Defaults to 1.
    *   `currentServerStateOverride`: Optional. If provided, this JWT string is used as the "previous state" for PoW, overriding the client's internal `state`. Use `null` explicitly for a genesis slip if overriding.
    *   Returns a promise that resolves to an object `{ slipClaims: object; actualScore: number; nonce: string; hash: string }` if successful, or `null` if PoW fails.
        *   `slipClaims`: Object containing `pubkey` (client's public JWK), `block`, `nonce`, `state` (the state used for PoW), and `create` (boolean flag).

*   **`client.createClientToken(slipClaims: object): Promise<string>`**
    Signs the `slipClaims` object with the client's private key and returns a JWT string.

*   **`client.processServerResponse(serverResponse: { state: string, ...any }): void`**
    Updates the client's internal state with the new JWT provided by the server.
    *   `serverResponse.state`: The new JWT string from the server.

*   **`client.state: string | null`**
    The current state JWT held by the client, received from the server. Initially `null`.

## Error Handling

*   `SlipkeyClient.create()` may throw errors during key generation.
*   `client.generateSlip(...)` returns `null` if the Proof-of-Work challenge is not solved within the default iteration limit (currently 1,000,000 in `pow.ts`).
*   The SDK itself does not handle network errors or HTTP status codes from a server. The application using this SDK is responsible for managing server communication, interpreting server responses (like 401 Unauthorized), and deciding on retry strategies or state reversion as per the main Slipkey protocol recommendations.

## Browser Usage

This SDK uses the Web Crypto API (`crypto.subtle`) which is available in all modern web browsers. When using this SDK in a browser project, you will typically bundle it with your application using a tool like Webpack, Rollup, or Parcel. These bundlers will handle the ES module imports.

## Node.js Usage

The SDK works in Node.js versions that support the Web Crypto API (Node.js >= v15.0.0, or v16+ for stable support). Ensure your `package.json` has `"type": "module"` or use the `.mjs` extension for files that use ES module `import` statements.

## Advanced Topics

*   **WebAssembly for Proof-of-Work:** The current Proof-of-Work (SHA-256) uses the native Web Crypto API. For potential performance improvements in environments where WebAssembly is highly optimized, the SHA-256 hashing could be delegated to a WebAssembly module. This is noted as a future optimization path in `src/pow.ts`.
*   **Server Error Handling (e.g., 401 Revert):** The Slipkey protocol describes how a client might react to a 401 error from the server, potentially by reverting to a previously known good state and re-generating a slip. This SDK provides the mechanism to set and use state (`client.state`, `currentServerStateOverride` in `generateSlip`), but the logic for managing a history of states or complex retry strategies is currently outside the scope of this client and should be implemented by the consuming application if needed.

## Contributing

Contributions are welcome! Please refer to the main project's contribution guidelines. (Placeholder - link to main project or define specific guidelines).

## License

This SDK is released under the MIT License. See the main project's LICENSE file for details.
