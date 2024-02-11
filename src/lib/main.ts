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
  // Hash the clientDataJSON
  const clientDataHash = crypto
    .createHash("SHA256")
    .update(Buffer.from(clientDataJSON, "base64"))
    .digest();

  // Prepare data for verification
  const signedData = Buffer.concat([authData, clientDataHash]);

  // Verify the signature using the public key
  const verifier = crypto.createVerify("SHA256");
  verifier.update(signedData);
  return verifier.verify(pemPublicKey, signature);
};

export const verify = async (
  attestationObject: string,
  clientDataJSON: string
): Promise<{ challenge: string; isValidSignature: boolean; pem: string }> => {
  const { fmt, attStmt, authData } = await decodeAttestationObject<{
    fmt: "packed" | "fido-u2f";
    attStmt: { sig: Buffer };
    authData: Buffer;
  }>(attestationObject);

  if (fmt !== "packed") {
    throw Error("fmt is wrong");
  }

  // get signature
  const { sig: signature } = attStmt; // For packed format, the signature is directly under 'sig'

  //console.log(signature);

  // get public key
  const { coseKeyBuffer } = parseAuthData(authData);
  const jwk = coseToJwk(coseKeyBuffer);
  const pem = jwkToPem(jwk);

  const isValidSignature = verifySignature(
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
  const authenticatorDataBuffer = Buffer.from(authenticatorData, "base64");
  const signatureBuffer = Buffer.from(signature, "base64");

  return verifySignature(
    authenticatorDataBuffer,
    clientDataJSON,
    signatureBuffer,
    userPublicKey
  );
};
