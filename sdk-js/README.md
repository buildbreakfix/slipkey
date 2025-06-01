# Slipkey SDK for JavaScript/TypeScript

## Introduction

Slipkey is a lightweight, stateless authentication mechanism designed for scenarios where traditional session management is cumbersome or undesirable. It uses a combination of JWTs and a client-side Proof-of-Work (PoW) challenge to provide a "slip" that a client can present to a server for authentication or authorization. For more details on the Slipkey standard, please refer to the [main project README](../../README.md).

This SDK provides `SlipkeyClient` and `SlipkeyServer` classes to help developers integrate Slipkey into their JavaScript or TypeScript applications.

## Features

*   Compliant with the Slipkey authentication standard.
*   Supports both Node.js (version 16+) and modern web browsers via Web Crypto API.
*   Generates RSA key pairs for client and server identities.
*   Implements client-side SHA-256 based Proof-of-Work.
*   Client-side creation and management of "slip" JWTs.
*   Server-side processing and validation of client slips, and issuance of state JWTs.
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
import { SlipkeyClient, SlipkeyServer } from 'slipkey-sdk';
```

**JavaScript (ES Modules):**
```javascript
// Ensure your environment supports ES modules
import { SlipkeyClient, SlipkeyServer } from 'slipkey-sdk';
```

### Client Initialization

The client can be initialized to generate a new key pair or by providing an existing private key (see "Managing Client Keys"). Configuration options for default PoW parameters can also be provided.

```typescript
async function initializeNewClient(): Promise<SlipkeyClient> {
  // Creates a client with a new RSA key pair and default settings
  const client = await SlipkeyClient.create();

  console.log("Client Public Key (PEM format):", client.getPublicKey());
  console.log("Client Public Key (JWK format):", client.getPublicJwk());
  console.log("Initial client state (JWT from server):", client.state); // Initially null

  // Example: Initialize with custom default PoW parameters
  const clientWithCustomDefaults = await SlipkeyClient.create({
    defaultTargetScore: 2,
    defaultBlockSizeMs: 120000, // 2 minutes
  });

  // Example: Initialize with an existing private key (see "Managing Client Keys" for how to get 'previouslyExportedKey')
  // const previouslyExportedKey = /* ... load your JWK ... */;
  // const clientFromExistingKey = await SlipkeyClient.create({
  //   initialPrivateKeyJwk: previouslyExportedKey
  // });

  return client;
}
```

### Generating a Slip and Client Token

The `generateSlip` method performs the Proof-of-Work and directly returns an object containing the slip claims and the client token (JWT) to be sent to the server.

```typescript
async function generateSlipAndToken(client: SlipkeyClient) {
  // Example: Generate a slip using client's default PoW parameters.
  // For a genesis slip, client.state is null.
  const slipResult = await client.generateSlip();

  // Example: Generate a slip with a specific block timestamp and target score.
  // const blockTimestamp = new Date(Date.now() + 60000).toISOString(); // 1 minute in the future
  // const targetScore = 2;
  // const slipResult = await client.generateSlip(blockTimestamp, targetScore);

  if (slipResult) {
    console.log("Slip and Token generated successfully!");
    console.log("  Slip Claims (JWT Payload):", slipResult.slipClaims);
    console.log("  PoW Nonce:", slipResult.nonce);
    console.log("  PoW Hash:", slipResult.hash);
    console.log("  PoW Score (actual):", slipResult.actualScore);
    console.log("  Client Token (JWT to send to server):", slipResult.token);

    return slipResult.token;
  } else {
    console.error("Failed to generate slip (PoW might have failed or client not initialized).");
    return null;
  }
}
```

### Server-Side Handling (Example using `SlipkeyServer`)

This shows how a server might use the `SlipkeyServer` class to process a client's token.

```typescript
// Conceptual server-side usage
async function handleClientRequest(clientToken: string, server: SlipkeyServer) {
  console.log("Server received client token:", clientToken);

  // Server processes the token.
  // It might have its own expectedTargetScore policy (e.g., 1).
  const serverResponse = await server.processClientToken(clientToken, 1);

  if (serverResponse.error) {
    console.error("Server Error:", serverResponse.error);
    // Respond to client with an error (e.g., HTTP 401)
    return null;
  } else {
    console.log("Server processed successfully!");
    console.log("  New Server State Token:", serverResponse.newServerStateToken);
    console.log("  PoW Score Verified:", serverResponse.score);
    console.log("  Chain Length:", serverResponse.chainLength);
    console.log("  Total Credit:", serverResponse.creditEarned);

    return serverResponse;
  }
}

// --- Example Flow ---
// async function runFullFlow() {
//   const client = await SlipkeyClient.create();
//   const server = await SlipkeyServer.create();

//   const clientToken1 = await generateSlipAndToken(client);
//   if (clientToken1) {
//     const serverResponse1 = await handleClientRequest(clientToken1, server);
//     if (serverResponse1 && !serverResponse1.error) {
//       // Client updates its state using the new JWT from the server
//       client.processServerResponse({
//         state: serverResponse1.newServerStateToken,
//         // other details like credit/len can be passed if client needs them
//       });
//       console.log("Client state updated:", client.state);

//       // Generate a subsequent slip
//       const clientToken2 = await generateSlipAndToken(client); // Will use new client.state
//       if (clientToken2) {
//         const serverResponse2 = await handleClientRequest(clientToken2, server);
//         // ... and so on
//       }
//     }
//   }
// }
// runFullFlow();
```

## API Reference

### `SlipkeyClient`

*   **`static async SlipkeyClient.create(config?: SlipkeyClientConfig): Promise<SlipkeyClient>`**
    *   Creates and initializes a new client instance.
    *   `config.initialPrivateKeyJwk` (optional `jose.JWK`): Initialize client with an existing private key.
    *   `config.defaultTargetScore` (optional `number`): Set default PoW target score for `generateSlip`. Defaults to 1.
    *   `config.defaultBlockSizeMs` (optional `number`): Set default block timespan (in ms from now) for `generateSlip`. Defaults to 60000 (1 minute).

*   **`client.getPublicKey(): string`**
    *   Returns the client's public key in SPKI PEM format.

*   **`client.getPublicJwk(): jose.JWK`**
    *   Returns the client's public key in JWK format (ensures `alg: 'RS256'` is present).

*   **`client.generateSlip(blockTimestampOrBlockSizeMs?: string | number, targetScore?: number, currentServerStateOverride?: string | null): Promise<{ slipClaims: object; actualScore: number; nonce: string; hash: string; token: string } | null>`**
    *   Generates a slip, performs PoW, and creates the client JWT.
    *   `blockTimestampOrBlockSizeMs`: Optional. Either an ISO 8601 string for the `block` claim, or a number representing the block size in milliseconds (to be added to current time). If undefined, uses `client.defaultBlockSizeMs`.
    *   `targetScore`: Optional. Required PoW score (leading zeros). If undefined, uses `client.defaultTargetScore`.
    *   `currentServerStateOverride`: Optional. If provided, this JWT string is used as the "previous state" for PoW, overriding the client's internal `state`. Use `null` explicitly for a genesis slip if the client already has a state but a genesis slip is desired.
    *   Returns a promise that resolves to an object containing `slipClaims` (the JWT payload), PoW details (`actualScore`, `nonce`, `hash`), and the client `token` (JWT string) if successful, or `null` if PoW fails.
        *   `slipClaims`: Object containing `pubkey` (client's public JWK), `block`, `nonce`, `state` (the state used for PoW), and `create` (boolean flag indicating if it was a genesis slip). This is the payload of the generated `token`.

*   **`client.processServerResponse(serverResponse: { state: string, ...any }): void`**
    *   Updates the client's internal `state` with the new JWT provided by the server.
    *   `serverResponse.state`: The new JWT string from the server. Other properties from the server response can be included but are not used by the client's core state logic.

*   **`client.exportPrivateKeyJwk(): jose.JWK`**
    *   Exports a deep copy of the client's private key in JWK format (ensures `alg: 'RS256'` is present). Useful for persisting the key.

*   **`client.updateDefaults(newDefaults: { defaultTargetScore?: number; defaultBlockSizeMs?: number }): void`**
    *   Updates the client's default PoW parameters (`defaultTargetScore`, `defaultBlockSizeMs`). Validates inputs (must be positive).

*   **`client.state: string | null`**
    *   The current state JWT held by the client, received from the server. Initially `null`.

### `SlipkeyServer`

The `SlipkeyServer` class provides methods to handle client requests on the server side.

*   **`static async SlipkeyServer.create(config?: SlipkeyServerConfig): Promise<SlipkeyServer>`**
    *   Creates and initializes a new server instance.
    *   `config.initialPrivateKeyJwk` (optional `jose.JWK`): Server's private key. If provided, `initialPublicKeyJwk` can also be given, or it will be derived. New keys generated if omitted.
    *   `config.initialPublicKeyJwk` (optional `jose.JWK`): Server's public key.
    *   `config.serverName` (optional `string`): Issuer name for server-issued JWTs (defaults to "SlipkeyServerDefault").

*   **`server.getPublicKeyJwk(): jose.JWK`**
    *   Returns the server's public key in JWK format (ensures `alg: 'RS256'` is present). Useful for clients or other services that might need to verify tokens issued by this server.

*   **`server.processClientToken(clientToken: string, expectedTargetScore?: number): Promise<ServerResponseShape>`**
    *   Processes a client's submitted JWT. It validates the client's token signature, Proof-of-Work, and state progression. If valid, it issues a new server state JWT.
    *   `clientToken`: The JWT string received from the client.
    *   `expectedTargetScore`: Optional. The PoW score the server expects for this slip (defaults to 1). This allows the server to enforce a minimum difficulty.
    *   Returns a Promise resolving to:
        *   On Success: `{ newServerStateToken: string; score: number; creditEarned: number; chainLength: number; error?: undefined }`
            *   `newServerStateToken`: The new JWT for the client to use as its state.
            *   `score`: The PoW score calculated by the server.
            *   `creditEarned`: The total credit for the client after this slip (example logic).
            *   `chainLength`: The new length of the client's slip chain.
        *   On Error: `{ error: string }` detailing the validation failure.

**Example: `SlipkeyServer` Usage**
```typescript
// Basic server-side setup and request processing
import { SlipkeyServer, SlipkeyClient } from 'slipkey-sdk';

async function serverDemo() {
  // Initialize the server (e.g., on application startup)
  // This might involve loading keys from a secure configuration or generating them.
  const server = await SlipkeyServer.create({ serverName: "MySlipkeyAppServer" });
  console.log("SlipkeyServer initialized. Public Key JWK:", server.getPublicKeyJwk());

  // --- Simulate receiving a request from a client ---
  // For demonstration, we'll create a client and have it generate a token.
  const client = await SlipkeyClient.create();
  const slipResult = await client.generateSlip(); // Client generates a genesis slip

  if (!slipResult) {
    console.error("Client failed to generate slip for demo.");
    return;
  }
  const clientToken = slipResult.token;
  console.log("Client Token to be processed by server:", clientToken);

  // Server processes the received client token
  const serverResponse = await server.processClientToken(clientToken);

  if (serverResponse.error) {
    console.error("Server Error processing client token:", serverResponse.error);
    // In a real server, you would send an appropriate HTTP error response (e.g., 401)
  } else {
    console.log("Server processed client token successfully!");
    console.log("  New Server State Token:", serverResponse.newServerStateToken);
    console.log("  Client's PoW Score (verified by server):", serverResponse.score);
    console.log("  Client's New Chain Length:", serverResponse.chainLength);
    console.log("  Client's New Total Credit:", serverResponse.creditEarned);
    // In a real server, you would send newServerStateToken (and other relevant data)
    // back to the client in the HTTP success response.
  }
}

// serverDemo();
```

## Managing Client Keys (Persistence)
(This section is largely unchanged but reviewed for consistency with API updates)
...

### Security Note
(Unchanged)
...

## Error Handling
*   `SlipkeyClient.create()` and `SlipkeyServer.create()` may throw errors during key generation or if invalid initial keys are provided.
*   `client.generateSlip(...)` returns `null` if PoW fails.
*   `server.processClientToken(...)` returns an object with an `error` property if validation fails.
*   The SDK itself does not handle network errors. The application using this SDK is responsible for managing server communication and interpreting server HTTP responses.

## Browser Usage
...
### Using with a `<script>` Tag (Standalone Bundle)
(Example updated to reflect `slipResult.token`)
```html
<!DOCTYPE html>
<html>
<head>
  <title>Slipkey SDK Script Tag Example</title>
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

      if (typeof window.SlipkeyClient === 'undefined') { // Basic check
        outputEl.textContent += 'Error: SlipkeyClient not found on window...\n';
        return;
      }
      const SlipkeyClient = window.SlipkeyClient;

      try {
        const client = await SlipkeyClient.create();
        outputEl.textContent += 'Client created successfully.\n';
        outputEl.textContent += 'Public Key (PEM): ' + client.getPublicKey() + '\n\n';

        const blockTime = new Date(Date.now() + 30000).toISOString();
        outputEl.textContent += 'Attempting to generate slip for block: ' + blockTime + '\n';

        const slipResult = await client.generateSlip(blockTime, 1); // targetScore 1

        if (slipResult) {
          outputEl.textContent += 'Slip and Token generated!\n';
          outputEl.textContent += '  Nonce: ' + slipResult.nonce + '\n';
          outputEl.textContent += '  Score: ' + slipResult.actualScore + '\n';
          outputEl.textContent += '  Client Token: ' + slipResult.token + '\n'; // Token is now in slipResult
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
(Note on bundle availability remains the same)
... (rest of README remains the same)
