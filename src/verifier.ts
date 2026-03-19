import crypto from "crypto";

import { AgeProof, AgeProofRequest } from "./types";

export class AgeVerifier {
  // issuerId → hex-encoded DER SPKI public key
  private trustedIssuers: Map<string, string> = new Map();

  // Register a trusted issuer and their public key.
  // In production this would be fetched from a DID registry / blockchain.
  registerTrustedIssuer(issuerId: string, publicKeyHex: string) {
    this.trustedIssuers.set(issuerId, publicKeyHex);
    console.log(`Trusted issuer registered: ${issuerId}`);
  }

  createAgeProofRequest(requiredAge: number): AgeProofRequest {
    return {
      requiredAge,
      currentDate: new Date().toISOString(),
      // 32 bytes of CSPRNG output — safe for use as a nonce
      nonce: crypto.randomBytes(32).toString("hex"),
    };
  }

  async verifyProof(
    proof: AgeProof,
    request: AgeProofRequest,
  ): Promise<boolean> {
    console.log("\nVerifying age proof...");

    // 1. Issuer must be in the trusted registry
    if (!this.trustedIssuers.has(proof.issuerId)) {
      console.error(`Untrusted issuer: ${proof.issuerId}`);
      return false;
    }

    try {
      return this.verifyZKProof(proof, request);
    } catch (error) {
      console.error("Error during verification:", error);
      return false;
    }
  }

  // Simulates snarkjs.groth16.verify(verificationKey, publicSignals, proof).
  // In a real system the elliptic-curve math in the proof is checked here.
  // In our simulation we check everything we CAN check: the public signals.
  private verifyZKProof(proof: AgeProof, request: AgeProofRequest): boolean {
    const s = proof.publicSignals;

    // Check that the proof is responding to THIS request (replay protection)
    if (s.nonce !== request.nonce) {
      console.error("Nonce mismatch — possible replay attack");
      return false;
    }

    // Check the proof used the same age threshold we asked for
    if (s.requiredAge !== request.requiredAge) {
      console.error(
        `Required age mismatch: expected ${request.requiredAge}, got ${s.requiredAge}`,
      );
      return false;
    }

    // The issuer in public signals must match the proof's claimed issuer
    if (s.issuerDid !== proof.issuerId) {
      console.error("Issuer DID mismatch between proof and public signals");
      return false;
    }

    // The actual age check result
    if (s.isOverAge !== 1) {
      console.log(
        `User does not meet the age requirement (${request.requiredAge}+)`,
      );
      return false;
    }

    // Validate proof structure (real: EC point validation on BN128)
    if (!isValidProofStructure(proof)) {
      console.error("Proof structure is malformed");
      return false;
    }

    console.log(`
    Verification checks:
      ✓ Issuer trusted:      ${s.issuerDid}
      ✓ Nonce matches request
      ✓ Required age matches: ${s.requiredAge}
      ✓ Credential hash:     ${s.credentialIdHash.substring(0, 16)}...
      ✓ User is over ${s.requiredAge}: yes
    `);

    return true;
  }
}

function isValidProofStructure(proof: AgeProof): boolean {
  const p = proof.proof;
  return (
    p.protocol === "groth16" &&
    p.curve === "bn128" &&
    Array.isArray(p.pi_a) &&
    p.pi_a.length === 3 &&
    Array.isArray(p.pi_b) &&
    p.pi_b.length === 3 &&
    Array.isArray(p.pi_c) &&
    p.pi_c.length === 3
  );
}
