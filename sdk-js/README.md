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
    console.log("  Client Token (JWT):", slipResult.token); // Token is now part of slipResult

    return slipResult.token;
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
    console.log("  Client Token (JWT):", slipResult.token); // Token is now part of slipResult

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

    *   `client.generateSlip(blockTimestampOrBlockSizeMs?: string | number, targetScore?: number, currentServerStateOverride?: string | null): Promise<{ slipClaims: object; actualScore: number; nonce: string; hash: string; token: string } | null>`**
    Generates a slip and the corresponding client JWT.
    *   `blockTimestampOrBlockSizeMs`: Optional. ISO 8601 string for `block` or number for block size in ms from now. Uses client default if omitted.
    *   `targetScore`: Optional. Required PoW score. Uses client default if omitted.
    *   `currentServerStateOverride`: Optional. Previous state JWT to override client's internal state.
    *   Returns a promise that resolves to an object containing `slipClaims`, PoW details (`actualScore`, `nonce`, `hash`), and the generated `token` string if successful, or `null` if PoW fails.
        *   `slipClaims`: Object containing `pubkey` (client's public JWK), `block`, `nonce`, `state` (the state used for PoW), and `create` (boolean flag). This is the payload of the generated `token`.

*   **`client.processServerResponse(serverResponse: { state: string, ...any }): void`**
    Updates the client's internal state with the new JWT provided by the server.
    *   `serverResponse.state`: The new JWT string from the server.

*   **`client.state: string | null`**
    The current state JWT held by the client, received from the server. Initially `null`.

*   **`client.exportPrivateKeyJwk(): jose.JWK`**
    Exports a deep copy of the client's private key in JWK format. Useful for persisting the key.

*   **`client.updateDefaults(newDefaults: { defaultTargetScore?: number; defaultBlockSizeMs?: number }): void`**
    Updates the client's default PoW parameters (`defaultTargetScore`, `defaultBlockSizeMs`).

## Managing Client Keys (Persistence)

To maintain the same Slipkey identity across different sessions or even devices, the client's RSA private key must be persisted. If a key is not persisted, `SlipkeyClient.create()` will generate a new key pair each time, resulting in a new, distinct identity.

The SDK allows you to export the private key and then re-initialize a `SlipkeyClient` instance with it.

### Exporting the Key

```typescript
// Assuming 'client' is an initialized SlipkeyClient instance
const privateKeyJwk = client.exportPrivateKeyJwk();
// Now you can store `privateKeyJwk` (e.g., as a JSON string).
```

### Saving and Loading (Browser localStorage Example)

This example shows how to save the private key to `localStorage` and load it when initializing a new client.

```typescript
// --- Saving the key ---
// const client = await SlipkeyClient.create(); // Or your existing client instance
// const privateKeyToSave = client.exportPrivateKeyJwk();
// localStorage.setItem('slipkeyPrivateKey', JSON.stringify(privateKeyToSave));
// console.log("Private key saved to localStorage.");

// --- Later, in a new session or page load ---
async function getClientWithPersistence() {
  const storedKeyString = localStorage.getItem('slipkeyPrivateKey');
  let initialKeyJwk: jose.JWK | undefined = undefined;

  if (storedKeyString) {
    try {
      initialKeyJwk = JSON.parse(storedKeyString);
      console.log("Private key loaded from localStorage.");
    } catch (e) {
      console.error("Error parsing stored private key:", e);
      // Optionally clear the invalid key: localStorage.removeItem('slipkeyPrivateKey');
    }
  }

  // Initialize client:
  // If initialKeyJwk is valid, it will be used.
  // If initialKeyJwk is undefined or invalid (and create() handles invalid keys by generating new ones,
  // or throws an error which you should catch), a new key pair will be generated.
  const client = await SlipkeyClient.create({ initialPrivateKeyJwk: initialKeyJwk });

  // If you want to ensure the key is saved again if it was newly generated:
  // if (!initialKeyJwk && client.exportPrivateKeyJwk) { // Check if a new key was generated
  //    const newPrivateKey = client.exportPrivateKeyJwk();
  //    localStorage.setItem('slipkeyPrivateKey', JSON.stringify(newPrivateKey));
  //    console.log("New private key generated and saved.");
  // }

  return client;
}

// Example usage:
// getClientWithPersistence().then(client => {
//   console.log("Client ready, public key (PEM):", client.getPublicKey());
// });
```

### Saving and Loading (Node.js File Example - Conceptual)

This is a conceptual example for Node.js environments. It requires file system access (e.g., using the `fs/promises` module).

```javascript
// Node.js - Conceptual Example (requires 'fs/promises')
// import { writeFile, readFile } from 'fs/promises';
// import path from 'path'; // For constructing file paths

// async function saveKeyToFile(keyJwk, filePath) {
//   try {
//     await writeFile(filePath, JSON.stringify(keyJwk, null, 2), 'utf-8');
//     console.log(`Key saved to ${filePath}`);
//   } catch (e) {
//     console.error(`Error saving key to file:`, e);
//   }
// }

// async function loadKeyFromFile(filePath) {
//   try {
//     const keyString = await readFile(filePath, 'utf-8');
//     return JSON.parse(keyString);
//   } catch (e) {
//     if (e.code === 'ENOENT') {
//       console.log(`Key file not found at ${filePath}. A new key will be generated if this was for initialization.`);
//     } else {
//       console.error(`Error loading key from file ${filePath}:`, e);
//     }
//     return null; // Return null if not found or error
//   }
// }

// // Example Usage:
// // const keyFilePath = path.join(__dirname, 'my-slipkey.json'); // Or some other persistent path
// //
// // async function main() {
// //   let loadedKey = await loadKeyFromFile(keyFilePath);
// //   const client = await SlipkeyClient.create({ initialPrivateKeyJwk: loadedKey });
// //
// //   // If a new key was generated because one wasn't loaded, save it.
// //   if (!loadedKey) {
// //     const privateKeyToSave = client.exportPrivateKeyJwk();
// //     await saveKeyToFile(privateKeyToSave, keyFilePath);
// //   }
// //
// //   console.log("Client ready. Public Key (PEM):", client.getPublicKey());
// // }
// // main();
```
Make sure to handle file paths and permissions appropriately in a real Node.js application.

### Security Note
**Important:** Private keys are sensitive credentials. Storing them in plaintext in mediums like `localStorage` might be acceptable for certain low-risk browser applications but is generally not recommended for applications handling valuable assets or sensitive data. For more secure storage, consider platform-specific secure storage mechanisms (like browser's Web Storage API with caution, or `crypto.subtle` for non-exportable keys if the use case changes) or, in Node.js, appropriately permissioned files or system keychain services. The security of the stored key is the responsibility of the application using this SDK.

## Error Handling

*   `SlipkeyClient.create()` may throw errors during key generation.
*   `client.generateSlip(...)` returns `null` if the Proof-of-Work challenge is not solved within the default iteration limit (currently 1,000,000 in `pow.ts`).
*   The SDK itself does not handle network errors or HTTP status codes from a server. The application using this SDK is responsible for managing server communication, interpreting server responses (like 401 Unauthorized), and deciding on retry strategies or state reversion as per the main Slipkey protocol recommendations.

## Browser Usage

This SDK uses the Web Crypto API (`crypto.subtle`) which is available in all modern web browsers.

### Using with a Module Bundler (Recommended)
When using this SDK in a modern browser project, you will typically bundle it with your application using a tool like Webpack, Rollup, or Parcel. These bundlers will handle the ES module imports correctly.
```typescript
// Your application code (e.g., main.ts or app.js)
import { SlipkeyClient } from 'slipkey-sdk';

async function main() {
  const client = await SlipkeyClient.create();
  // ... use client
}
main();
```

### Using with a `<script>` Tag (Standalone Bundle)

For direct browser usage without a module bundler, a standalone bundle (e.g., in UMD or IIFE format) of the SDK would be needed. Such a bundle would typically expose the `SlipkeyClient` on a global object (e.g., `window.SlipkeyClient` or `window.SlipkeySDK.SlipkeyClient`).

Here's an example of how you might use it:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Slipkey SDK Script Tag Example</title>
  <!--
    Assuming 'slipkey-sdk.umd.js' is the standalone bundle.
    Replace with the actual path to your SDK's bundle file.
  -->
  <script src="path/to/slipkey-sdk.umd.js"></script>
</head>
<body>
  <h1>Slipkey SDK Test</h1>
  <button onclick="runSlipkeyDemo()">Run Demo</button>
  <pre id="output"></pre>

  <script>
    async function runSlipkeyDemo() {
      const outputEl = document.getElementById('output');
      outputEl.textContent = 'Initializing client...\n';

      // Check if the SDK is loaded and SlipkeyClient is available globally
      if (typeof window.SlipkeyClient === 'undefined') {
        outputEl.textContent += 'Error: SlipkeyClient not found on window. Ensure the SDK bundle is loaded correctly and exposes SlipkeyClient globally.\n';
        return;
      }
      const SlipkeyClient = window.SlipkeyClient; // Assign for convenience

      try {
        const client = await SlipkeyClient.create();
        outputEl.textContent += 'Client created successfully.\n';
        outputEl.textContent += 'Public Key (PEM): ' + client.getPublicKey() + '\n\n';

        const blockTime = new Date(Date.now() + 30000).toISOString(); // 30s in the future
        outputEl.textContent += 'Attempting to generate slip for block: ' + blockTime + '\n';

        // Note: The structure of slipResult and how the token is obtained might change
        // if client.createClientToken() is internalized into generateSlip() in future versions.
        // This example assumes generateSlip returns an object that includes the client token
        // or the necessary claims to create one.
        // For now, we reflect the state *after* Step 6 (internalize createClientToken).

        const slipResult = await client.generateSlip(blockTime, 1); // targetScore 1

        if (slipResult && slipResult.slipClaims) { // Assuming slipClaims contains the token after internalizing createClientToken
          outputEl.textContent += 'Slip and Token generated!\n';
          outputEl.textContent += '  Nonce: ' + slipResult.nonce + '\n';
          outputEl.textContent += '  Score: ' + slipResult.actualScore + '\n';
          // Let's assume for this example the token is part of slipClaims or directly on slipResult
          // For the purpose of this README, we'll assume the token is directly available for simplicity,
          outputEl.textContent += 'Slip and Token generated!\n';
          outputEl.textContent += '  Nonce: ' + slipResult.nonce + '\n';
          outputEl.textContent += '  Score: ' + slipResult.actualScore + '\n';
          outputEl.textContent += '  Client Token: ' + slipResult.token + '\n';
          outputEl.textContent += '\nDemo finished. This clientToken would be sent to a server.\n';
        } else {
          outputEl.textContent += 'Failed to generate slip.\n';
        }
      } catch (error) {
        outputEl.textContent += 'Error: ' + error.message + '\n';
        console.error('Slipkey Demo Error:', error);
      }
    }
  </script>
</body>
</html>
```
**Note:** The availability and exact name/path of the UMD/IIFE bundle (e.g., `slipkey-sdk.umd.js`) and how `SlipkeyClient` is exposed globally (`window.SlipkeyClient` or `window.SlipkeySDK.SlipkeyClient`) depend on the project's specific bundling configuration if such a bundle is created. Refer to the SDK's release information or bundling setup for these details.

## Node.js Usage

The SDK works in Node.js versions that support the Web Crypto API (Node.js >= v15.0.0, or v16+ for stable support). Ensure your `package.json` has `"type": "module"` or use the `.mjs` extension for files that use ES module `import` statements.

## Advanced Topics

*   **WebAssembly for Proof-of-Work:** The current Proof-of-Work (SHA-256) uses the native Web Crypto API. For potential performance improvements in environments where WebAssembly is highly optimized, the SHA-256 hashing could be delegated to a WebAssembly module. This is noted as a future optimization path in `src/pow.ts`.
*   **Server Error Handling (e.g., 401 Revert):** The Slipkey protocol describes how a client might react to a 401 error from the server, potentially by reverting to a previously known good state and re-generating a slip. This SDK provides the mechanism to set and use state (`client.state`, `currentServerStateOverride` in `generateSlip`), but the logic for managing a history of states or complex retry strategies is currently outside the scope of this client and should be implemented by the consuming application if needed.

## Contributing

Contributions are welcome! Please refer to the main project's contribution guidelines. (Placeholder - link to main project or define specific guidelines).

## License

This SDK is released under the MIT License. See the main project's LICENSE file for details.
