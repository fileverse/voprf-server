import { Oprf, VOPRFClient } from "@cloudflare/voprf-ts";

/**
 * Example VOPRF client that demonstrates the protocol flow
 */
async function voprfClientExample() {
  try {
    console.log("🔐 VOPRF Client Example");
    console.log("======================");

    // Step 1: Get server's public key
    console.log("\n1. Fetching server's public key...");
    const response = await fetch("http://localhost:8001/voprf/public-key");
    const { publicKey: publicKeyBase64, suite } = await response.json();

    console.log(`   Suite: ${suite}`);
    console.log(`   Public Key: ${publicKeyBase64}`);

    // Convert base64 public key to Uint8Array
    const publicKey = new Uint8Array(Buffer.from(publicKeyBase64, "base64"));

    // Step 2: Create VOPRF client
    console.log("\n2. Creating VOPRF client...");
    const client = new VOPRFClient(suite, publicKey);

    // Step 3: Prepare input for VOPRF evaluation
    console.log("\n3. Preparing input...");
    const input = new TextEncoder().encode("Hello, VOPRF!");
    const batch = [input];
    console.log(`   Input: "${new TextDecoder().decode(input)}"`);

    // Step 4: Create blinded evaluation request
    console.log("\n4. Creating blinded evaluation request...");
    const [finData, evalReq] = await client.blind(batch);

    // Serialize evaluation request for transmission
    const evalReqSerialized = evalReq.serialize();
    const evalReqBase64 = Buffer.from(evalReqSerialized).toString("base64");

    console.log(
      `   Evaluation Request (base64): ${evalReqBase64.substring(0, 50)}...`
    );

    // Step 5: Send evaluation request to server
    console.log("\n5. Sending evaluation request to server...");
    const evalResponse = await fetch("http://localhost:8001/voprf/evaluate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        evaluationRequest: evalReqBase64,
      }),
    });

    if (!evalResponse.ok) {
      const error = await evalResponse.json();
      throw new Error(`Server error: ${error.message}`);
    }

    const { evaluation: evaluationBase64 } = await evalResponse.json();
    console.log(
      `   Server Response (base64): ${evaluationBase64.substring(0, 50)}...`
    );

    // Step 6: Deserialize server's evaluation
    console.log("\n6. Processing server's evaluation...");
    const evaluationData = new Uint8Array(
      Buffer.from(evaluationBase64, "base64")
    );

    // Note: In the current simplified implementation, we get a placeholder response
    // In a full implementation, you would deserialize the evaluation and finalize
    console.log(`   Evaluation data length: ${evaluationData.length} bytes`);

    // TODO: Complete the finalization step when proper VOPRF evaluation is implemented
    // const evaluation = client.deserializeEvaluation(evaluationData);
    // const [output] = await client.finalize(finData, evaluation);

    console.log("\n✅ VOPRF protocol completed successfully!");
    console.log(
      "\n📝 Note: This is a simplified implementation for demonstration."
    );
    console.log(
      "   A full implementation would include proper evaluation and finalization."
    );
  } catch (error) {
    console.error("\n❌ Error in VOPRF client example:", error);
  }
}

// Run the example if this file is executed directly
if (require.main === module) {
  voprfClientExample();
}

export { voprfClientExample };
