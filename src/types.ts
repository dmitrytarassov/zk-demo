export interface VerifiableCredential {
  id: string;
  issuer: string;
  issuanceDate: string;
  type: string[];
  credentialSubject: {
    id: string;
    birthDate: string;
    [key: string]: string;
  };
  proof: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    // hex-encoded Ed25519 signature over (id + issuanceDate + credentialSubject)
    signature: string;
  };
}

export interface AgeProofRequest {
  requiredAge: number;
  currentDate: string;
  // 32 cryptographically random bytes, hex-encoded
  nonce: string;
}

// Public signals exposed by the ZK proof — visible to the verifier
export interface ZKPublicSignals {
  nonce: string;
  requiredAge: number;
  isOverAge: 0 | 1;
  issuerDid: string;
  // SHA-256 of the credential ID — proves the proof is bound to a specific credential
  // without revealing its contents
  credentialIdHash: string;
}

// Simulated Groth16 proof structure (real: elliptic curve points as big integers)
export interface ZKProof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: "groth16";
  curve: "bn128";
}

export interface AgeProof {
  proof: ZKProof;
  publicSignals: ZKPublicSignals;
  issuerId: string;
}

export interface Issuer {
  id: string;
  // hex-encoded DER SPKI Ed25519 public key
  publicKey: string;
  name: string;
  isActive: boolean;
}
