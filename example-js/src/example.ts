import { SlipkeyClient, SlipkeyServer } from 'slipkey-sdk';

async function main() {
  console.log("--- Slipkey Example (Node.js) ---");

  const server = await SlipkeyServer.create({ serverName: "TestSlipkeyServer" });
  console.log("Server initialized.");

  const client = await SlipkeyClient.create({
    defaultTargetScore: 1,
    defaultBlockSizeMs: 3000 // Shortened for faster example
  });
  console.log("Client initialized. Public Key (PEM):", client.getPublicKey().substring(0, 50) + "...");

  console.log("\n--- Generating Genesis Slip ---");
  const genesisSlipResult = await client.generateSlip();

  if (!genesisSlipResult) {
    console.error("CLIENT: Failed to generate genesis slip.");
    return;
  }
  console.log(`CLIENT: Genesis slip generated. Nonce: ${genesisSlipResult.nonce}, Score: ${genesisSlipResult.actualScore}`);
  console.log(`CLIENT: Token for server: ${genesisSlipResult.token.substring(0, 60)}...`);

  const serverResponse1 = await server.processClientToken(genesisSlipResult.token);

  if (serverResponse1.error) {
    console.error(`SERVER: Error processing genesis slip: ${serverResponse1.error}`);
    return;
  }
  console.log(`SERVER: Genesis slip processed. Len: ${serverResponse1.chainLength}, Credit Earned: ${serverResponse1.creditEarned}, New State: ${serverResponse1.newServerStateToken.substring(0,60)}...`);

  client.processServerResponse({ state: serverResponse1.newServerStateToken });
  console.log("CLIENT: State updated.");

  console.log("\n--- Generating Subsequent Slip ---");
  const subsequentSlipResult = await client.generateSlip(2000); // 2s block

  if (!subsequentSlipResult) {
    console.error("CLIENT: Failed to generate subsequent slip.");
    return;
  }
  console.log(`CLIENT: Subsequent slip. Nonce: ${subsequentSlipResult.nonce}, Score: ${subsequentSlipResult.actualScore}`);
  console.log(`CLIENT: Token for server: ${subsequentSlipResult.token.substring(0, 60)}...`);

  const serverResponse2 = await server.processClientToken(subsequentSlipResult.token);

  if (serverResponse2.error) {
    console.error(`SERVER: Error processing subsequent slip: ${serverResponse2.error}`);
    return;
  }
  console.log(`SERVER: Subsequent slip processed. Len: ${serverResponse2.chainLength}, Credit Earned: ${serverResponse2.creditEarned}, New State: ${serverResponse2.newServerStateToken.substring(0,60)}...`);

  client.processServerResponse({ state: serverResponse2.newServerStateToken });
  console.log(`CLIENT: State updated. Final state token: ${client.state ? client.state.substring(0, 60) + "..." : "null"}`);
  console.log("\n--- Example Complete ---");
}

main().catch(e => {
    console.error("TOP LEVEL ERROR:", e);
    process.exit(1);
});
