import crypto from "crypto";
import cbor from "cbor";
import coseToJwk from "cose-to-jwk";
import jwkToPem from "jwk-to-pem";

export const generateChallenge = (): string =>
  crypto.randomBytes(32).toString("base64");

// Convert to URL-encoded base64
export const toUrlEncodedBase64 = (standardBase64: string): string =>
  standardBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const decodeAttestationObject = async <T = any>(
  attestationObjectBase64: string
): Promise<T> => {
  const attestationObjectBuffer = Buffer.from(
    attestationObjectBase64,
    "base64"
  );

  return cbor.decodeFirst(attestationObjectBuffer);
};

const parseAuthData = (
  authDataBuffer: Buffer
): {
  rpIdHash: Buffer;
  flags: number;
  counter: number;
  aaguid: Buffer;
  credId: Buffer;
  coseKeyBuffer: Buffer;
} => {
  const rpIdHash = authDataBuffer.subarray(0, 32);
  const flagsBuf = authDataBuffer.subarray(32, 33);
  const flags = flagsBuf[0];
  const counterBuf = authDataBuffer.subarray(33, 37);
  const counter = counterBuf.readUInt32BE(0);
  const aaguid = authDataBuffer.subarray(37, 53);
  const credIdLenBuf = authDataBuffer.subarray(53, 55);
  const credIdLen = credIdLenBuf.readUInt16BE(0);
  const credId = authDataBuffer.subarray(55, 55 + credIdLen);

  // The rest is the COSE key
  const coseKeyBuffer = authDataBuffer.subarray(55 + credIdLen);

  return {
    rpIdHash,
    flags,
    counter,
    aaguid,
    credId,
    coseKeyBuffer,
  };
};

const verifySignature = (
  authData: Buffer,
  clientDataJSON: string,
  signature: Buffer,
  pemPublicKey: string
): boolean => {
  console.log("verifySignature called");
  
  try {
    // Hash the clientDataJSON
    console.log("Hashing clientDataJSON...");
    const clientDataHash = crypto
      .createHash("SHA256")
      .update(Buffer.from(clientDataJSON, "base64"))
      .digest();

    // Prepare data for verification
    console.log("Preparing signed data...");
    const signedData = Buffer.concat([authData, clientDataHash]);

    // Verify the signature using the public key
    console.log("Creating verifier...");
    const verifier = crypto.createVerify("SHA256");
    verifier.update(signedData);
    
    console.log("Verifying signature...");
    const result = verifier.verify(pemPublicKey, signature);
    console.log("Signature verification result:", result);
    
    return result;
  } catch (error) {
    console.error("verifySignature error:", error);
    throw error;
  }
};

export const verify = async (
  attestationObject: string,
  clientDataJSON: string
): Promise<{ challenge: string; isValidSignature: boolean; pem: string }> => {
  const { fmt, attStmt, authData } = await decodeAttestationObject<{
    fmt: "packed" | "fido-u2f" | "none" | string;
    attStmt: { sig?: Buffer };
    authData: Buffer;
  }>(attestationObject);

  console.log("WebAuthn format detected:", fmt);
  console.log("AttStmt:", attStmt);
  
  if (fmt !== "packed" && fmt !== "fido-u2f" && fmt !== "none") {
    throw Error(`Unsupported WebAuthn format: ${fmt}. Supported formats: packed, fido-u2f, none`);
  }

  // get signature based on format
  let signature: Buffer;
  
  if (fmt === "packed") {
    signature = attStmt.sig || Buffer.alloc(0); // For packed format, the signature is directly under 'sig'
  } else if (fmt === "fido-u2f") {
    signature = attStmt.sig || Buffer.alloc(0); // FIDO U2F also uses 'sig'
  } else if (fmt === "none") {
    // "none" format doesn't have a signature for verification
    signature = Buffer.alloc(0);
  } else {
    throw Error(`Unknown format handling for: ${fmt}`);
  }

  //console.log(signature);

  // get public key
  const { coseKeyBuffer } = parseAuthData(authData);
  const jwk = coseToJwk(coseKeyBuffer);
  const pem = jwkToPem(jwk);

  // For "none" format, we skip signature verification
  const isValidSignature = fmt === "none" ? true : verifySignature(
    authData,
    clientDataJSON,
    signature,
    pem
  );

  // Decode clientDataJSON from base64url and parse it
  // The challenge in clientDataJSON is also base64url-encoded, decode it for comparison
  const { challenge }: { challenge: string } = JSON.parse(
    Buffer.from(clientDataJSON, "base64").toString("utf8")
  );

  return { isValidSignature, challenge, pem };
};

export const verifyLogin = async (
  authenticatorData: string,
  clientDataJSON: string,
  signature: string,
  userPublicKey: string
): Promise<boolean> => {
  console.log("verifyLogin called with:", {
    authenticatorData: authenticatorData.substring(0, 50) + "...",
    clientDataJSON: clientDataJSON.substring(0, 50) + "...",
    signature: signature.substring(0, 50) + "...",
    userPublicKey: userPublicKey.substring(0, 50) + "...",
  });

  try {
    const authenticatorDataBuffer = Buffer.from(authenticatorData, "base64");
    const signatureBuffer = Buffer.from(signature, "base64");

    console.log("About to call verifySignature...");
    const result = verifySignature(
      authenticatorDataBuffer,
      clientDataJSON,
      signatureBuffer,
      userPublicKey
    );
    console.log("verifySignature result:", result);
    
    return result;
  } catch (error) {
    console.error("verifyLogin error:", error);
    throw error;
  }
};
