import { IssuerService } from "./issuer";
import { AgeVerifier } from "./verifier";
import { UserWallet } from "./wallet";

async function main() {
  console.log("=".repeat(60));
  console.log("DID Age Verification Demo");
  console.log("=".repeat(60));

  // 1. Init
  const issuer = new IssuerService();
  const verifier = new AgeVerifier();

  // The verifier needs to trust the issuer's public key.
  // In production this comes from a DID registry / blockchain.
  const issuerPublicKey = issuer.getIssuerPublicKey("did:example:gov")!;
  verifier.registerTrustedIssuer("did:example:gov", issuerPublicKey);

  // The wallet gets a public key resolver so the ZK generator can verify
  // the credential signature before proving.
  const wallet = new UserWallet((id) => issuer.getIssuerPublicKey(id));

  // 2. Issue credential
  console.log("\nStep 1: Issuing Verifiable Credential");
  const credential = issuer.issueCredential("did:user:123", {
    birthDate: "1989-07-24",
    name: "Dmitrii Tarasov",
  });

  wallet.storeCredential(credential);
  wallet.listCredentials();

  // 3. Verifier requests proof of age
  console.log("\nStep 2: Age Verification Request");
  const request = verifier.createAgeProofRequest(18);
  console.log(
    "Nonce: " +
      request.nonce.substring(0, 16) +
      "... (" +
      request.nonce.length / 2 +
      " bytes)",
  );

  // 4. Wallet generates ZK proof
  console.log("\nStep 3: Generating ZK Proof");
  const proof = await wallet.generateAgeProof(request);

  if (!proof) {
    console.log("Failed to generate proof");
    process.exit(1);
  }

  // 5. Verifier checks the proof
  console.log("\nStep 4: Verifying Proof");
  const isValid = await verifier.verifyProof(proof, request);

  console.log("\n" + "=".repeat(60));
  if (isValid) {
    console.log("Access GRANTED: User is over 18 (no personal data revealed)");
  } else {
    console.log("Access DENIED");
  }
  console.log("=".repeat(60));

  // 6. Demonstrate replay protection: reusing the same proof should fail
  console.log("\nStep 5: Replay Attack Test — reusing the same nonce");
  const replayValid = await verifier.verifyProof(proof, {
    ...request,
  });
  console.log(
    replayValid ? "FAIL: replay was accepted" : "PASS: replay rejected",
  );

  // 7. Demonstrate that a minor's legitimate proof is rejected
  console.log(
    "\nStep 6: Minor Test — user born in 2015 (age 11) requesting access",
  );
  const minorWallet = new UserWallet((id) => issuer.getIssuerPublicKey(id));
  const minorCredential = issuer.issueCredential("did:user:456", {
    birthDate: "2015-01-01",
    name: "Young User",
  });
  minorWallet.storeCredential(minorCredential);

  const minorRequest = verifier.createAgeProofRequest(18);
  const minorProof = await minorWallet.generateAgeProof(minorRequest);
  if (minorProof) {
    const minorValid = await verifier.verifyProof(minorProof, minorRequest);
    console.log(
      minorValid
        ? "FAIL: minor was granted access"
        : "PASS: minor correctly denied",
    );
  }

  // NOTE: in a real Groth16 ZK proof, pi_a/pi_b/pi_c are elliptic-curve points
  // mathematically derived from both the private witness AND public signals.
  // Tampering with any public signal would make snarkjs.groth16.verify() return false.
  // This binding cannot be simulated without actual ZK circuit math.
}

main().catch(console.error);
