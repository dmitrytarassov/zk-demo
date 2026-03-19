import crypto from "crypto";

import { VerifiableCredential, Issuer } from "./types";

export class IssuerService {
  private issuers: Map<string, Issuer> = new Map();
  private privateKeys: Map<string, crypto.KeyObject> = new Map();

  constructor() {
    const issuerId = "did:example:gov";

    // Generate a real Ed25519 key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyHex = publicKey
      .export({ type: "spki", format: "der" })
      .toString("hex");

    this.privateKeys.set(issuerId, privateKey);
    this.registerIssuer({
      id: issuerId,
      publicKey: publicKeyHex,
      name: "Government Identity Agency",
      isActive: true,
    });
  }

  registerIssuer(issuer: Issuer) {
    this.issuers.set(issuer.id, issuer);
    console.log(`Issuer registered: ${issuer.name} (${issuer.id})`);
  }

  issueCredential(
    userId: string,
    userData: { birthDate: string; name: string },
  ): VerifiableCredential {
    const issuer = Array.from(this.issuers.values())[0];
    const privateKey = this.privateKeys.get(issuer.id);
    if (!privateKey) throw new Error(`No private key for issuer ${issuer.id}`);

    const id = `urn:uuid:${crypto.randomUUID()}`;
    const issuanceDate = new Date().toISOString();
    const credentialSubject = {
      id: userId,
      birthDate: userData.birthDate,
      name: userData.name,
    };

    // Sign the canonical representation of the credential data
    const dataToSign = canonicalize({ id, issuanceDate, credentialSubject });
    const signature = crypto
      .sign(null, Buffer.from(dataToSign), privateKey)
      .toString("hex");

    const credential: VerifiableCredential = {
      id,
      issuer: issuer.id,
      issuanceDate,
      type: ["VerifiableCredential", "IdentityCredential"],
      credentialSubject,
      proof: {
        type: "Ed25519Signature2020",
        created: issuanceDate,
        proofPurpose: "assertionMethod",
        verificationMethod: `${issuer.id}#keys-1`,
        signature,
      },
    };

    console.log(`Credential issued for ${userData.name}`);
    return credential;
  }

  getIssuerPublicKey(issuerId: string): string | null {
    return this.issuers.get(issuerId)?.publicKey ?? null;
  }
}

// Deterministic JSON serialization (key order matters for signatures)
function canonicalize(obj: object): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}
