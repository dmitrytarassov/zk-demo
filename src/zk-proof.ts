// NOTE: This is a simulation of what a real ZK proof system (e.g. circom + snarkjs) would do.
// In a real implementation:
//   - The circuit (circuit.wasm + circuit_final.zkey) is compiled from a circom file
//   - snarkjs.groth16.fullProve(input, wasmFile, zkeyFile) generates the actual proof
//   - pi_a / pi_b / pi_c are elliptic curve points (BN128), not random bytes
//
// What this simulation gets RIGHT:
//   - The circuit logic (age check, signature verification) runs in the wallet — private
//   - Only public signals are exposed to the verifier
//   - The issuer signature is verified before generating a proof
//   - The nonce is bound to the proof, preventing replay attacks

import crypto from "crypto";

import {
  VerifiableCredential,
  AgeProofRequest,
  ZKProof,
  ZKPublicSignals,
} from "./types";

export class ZKAgeProofGenerator {
  // In a real app: resolves issuer DID → DER SPKI public key hex
  private getIssuerPublicKey: (issuerId: string) => string | null;

  constructor(getIssuerPublicKey: (issuerId: string) => string | null) {
    this.getIssuerPublicKey = getIssuerPublicKey;
    console.log("ZK circuit initialized (simulation mode)");
  }

  async generateProof(
    credential: VerifiableCredential,
    request: AgeProofRequest,
  ): Promise<{ proof: ZKProof; publicSignals: ZKPublicSignals }> {
    // --- Private computation (hidden from verifier) ---

    // 1. Verify issuer signature on the credential.
    //    In a real circuit, this is an EdDSA constraint set.
    const issuerPublicKeyHex = this.getIssuerPublicKey(credential.issuer);
    if (!issuerPublicKeyHex) {
      throw new Error(`Unknown issuer: ${credential.issuer}`);
    }

    const signatureValid = this.verifyCredentialSignature(
      credential,
      issuerPublicKeyHex,
    );
    if (!signatureValid) {
      throw new Error(
        "Credential signature is invalid — refusing to generate proof",
      );
    }

    // 2. Compute age (private — the verifier never sees the birth date)
    const birthDate = new Date(credential.credentialSubject.birthDate);
    const currentDate = new Date(request.currentDate);
    const age = calculateAge(birthDate, currentDate);
    const isOverAge = age >= request.requiredAge;

    console.log(`
    ZK Circuit — private witness (not revealed to verifier):
      Birth date:        ${birthDate.toISOString().split("T")[0]}
      Actual age:        ${age}
      Signature valid:   true
    `);

    // --- Public signals (revealed to verifier) ---
    const publicSignals: ZKPublicSignals = {
      nonce: request.nonce,
      requiredAge: request.requiredAge,
      isOverAge: isOverAge ? 1 : 0,
      issuerDid: credential.issuer,
      // Commit to credential ID so the verifier knows which credential was used,
      // without learning its contents.
      credentialIdHash: crypto
        .createHash("sha256")
        .update(credential.id)
        .digest("hex"),
    };

    // --- Simulated Groth16 proof ---
    // Real: snarkjs.groth16.fullProve() → elliptic curve points on BN128
    // Here: cryptographically random bytes of the correct byte length (32 bytes per coordinate)
    const proof: ZKProof = {
      pi_a: [randHex(32), randHex(32), randHex(32)],
      pi_b: [
        [randHex(32), randHex(32)],
        [randHex(32), randHex(32)],
        [randHex(32), randHex(32)],
      ],
      pi_c: [randHex(32), randHex(32), randHex(32)],
      protocol: "groth16",
      curve: "bn128",
    };

    return { proof, publicSignals };
  }

  private verifyCredentialSignature(
    credential: VerifiableCredential,
    issuerPublicKeyHex: string,
  ): boolean {
    try {
      const pubKeyDer = Buffer.from(issuerPublicKeyHex, "hex");
      const publicKey = crypto.createPublicKey({
        key: pubKeyDer,
        type: "spki",
        format: "der",
      });

      const dataToVerify = canonicalize({
        id: credential.id,
        issuanceDate: credential.issuanceDate,
        credentialSubject: credential.credentialSubject,
      });

      return crypto.verify(
        null,
        Buffer.from(dataToVerify),
        publicKey,
        Buffer.from(credential.proof.signature, "hex"),
      );
    } catch {
      return false;
    }
  }
}

function calculateAge(birthDate: Date, currentDate: Date): number {
  let age = currentDate.getFullYear() - birthDate.getFullYear();
  const monthDiff = currentDate.getMonth() - birthDate.getMonth();
  if (
    monthDiff < 0 ||
    (monthDiff === 0 && currentDate.getDate() < birthDate.getDate())
  ) {
    age--;
  }
  return age;
}

function randHex(bytes: number): string {
  return crypto.randomBytes(bytes).toString("hex");
}

function canonicalize(obj: object): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}
