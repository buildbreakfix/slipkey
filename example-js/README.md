# Slipkey JavaScript Example Application (Node.js)

This example demonstrates the usage of the `slipkey-sdk` with `SlipkeyClient` and `SlipkeyServer` interacting in a Node.js environment.

## Prerequisites

- Node.js (version 18.x or 20.x recommended)
- The `sdk-js` package must be built in the parent directory (`../sdk-js`). If you haven't built it yet, navigate to `../sdk-js` and run `npm run build` (or `npx tsc`). This compiles the TypeScript source to JavaScript modules.

## Setup (Node.js Example)

1.  Navigate to this directory:
    ```bash
    cd example-js
    ```
2.  Install dependencies. This will link the local `slipkey-sdk` (from `../sdk-js/dist/esm`) and install other necessary packages for the Node.js example.
    ```bash
    npm install
    ```

## Running the Node.js Example

To run the Node.js example script (`src/example.ts`):
```bash
npm start
```
This will execute `src/example.ts` using `ts-node`, showcasing a `SlipkeyClient` generating genesis and subsequent slips, and a `SlipkeyServer` processing them in a simulated Node.js environment.

---

## Vanilla JS Browser Example (`index.html`)

This example demonstrates using the `SlipkeyClient` directly in a browser using a UMD (Universal Module Definition) bundle.

### Prerequisites for Browser Example

1.  **Build the SDK Bundle:**
    The `sdk-js` must be bundled into a UMD file. Navigate to the `sdk-js` directory and run the bundling script:
    ```bash
    cd ../sdk-js
    npm run build:bundle
    ```
    This command uses `esbuild` to create `../sdk-js/dist/bundles/slipkey-sdk.umd.js`. This bundle can be included directly in an HTML file.

### Running the Browser Example

1.  **Open `index.html`:**
    After ensuring the bundle `../sdk-js/dist/bundles/slipkey-sdk.umd.js` exists, simply open the `example-js/index.html` file directly in your web browser (e.g., by double-clicking it or using "File > Open" in your browser).

2.  **Click "Run Client Demo":**
    The page will load, and you can click the button to see the `SlipkeyClient` in action.

### What the Browser Example Demonstrates

-   How to include the bundled `slipkey-sdk.umd.js` in an HTML page.
-   How to instantiate `SlipkeySDK.SlipkeyClient` (the global object exposed by the UMD bundle).
-   Generating a new RSA key pair within the client.
-   Generating a "genesis" slip (a slip without a previous server state).
-   The output will show the client's public key, the generated nonce, PoW score, and the client token.
-   This example only runs the client-side operations. In a real application, the generated token would be sent to a server for validation and to receive a new state.

This provides a basic demonstration of how `SlipkeyClient` can be used in a vanilla JavaScript browser environment without Node.js or complex build systems for the consuming application.
