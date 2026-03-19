import { VerifiableCredential, AgeProofRequest, AgeProof } from "./types";
import { ZKAgeProofGenerator } from "./zk-proof";

export class UserWallet {
  private credentials: Map<string, VerifiableCredential> = new Map();
  private zkGenerator: ZKAgeProofGenerator;

  constructor(getIssuerPublicKey: (issuerId: string) => string | null) {
    this.zkGenerator = new ZKAgeProofGenerator(getIssuerPublicKey);
  }

  storeCredential(credential: VerifiableCredential) {
    this.credentials.set(credential.id, credential);
    console.log(`Credential stored: ${credential.id}`);
  }

  async generateAgeProof(request: AgeProofRequest): Promise<AgeProof | null> {
    const credential = Array.from(this.credentials.values()).find(
      (cred) => cred.credentialSubject.birthDate,
    );

    if (!credential) {
      console.error("No suitable credential found");
      return null;
    }

    console.log("Generating ZK proof for age verification...");

    try {
      const { proof, publicSignals } = await this.zkGenerator.generateProof(
        credential,
        request,
      );

      console.log("ZK proof generated successfully");

      return {
        proof,
        publicSignals,
        issuerId: credential.issuer,
      };
    } catch (error) {
      console.error("Failed to generate proof:", error);
      return null;
    }
  }

  listCredentials() {
    console.log("\nStored Credentials:");
    this.credentials.forEach((cred, id) => {
      console.log(`  - ${id}: ${cred.credentialSubject.name}`);
    });
  }
}
