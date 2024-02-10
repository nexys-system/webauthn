import { test } from "node:test";
import assert from "assert";
import {
  generateChallenge,
  toUrlEncodedBase64,
  verify,
  verifyLogin,
} from "./main.js";

test("verify function test", async () => {
  // Sample attestationObject and clientDataJSON
  const attestationObject =
    "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhALYmOgR9yfua4Yv1ZFRsXeyvKdwtUBs52EmDq79uKlZUAiBe7XHJ83mgzR5SQgCQeOh8orBKNNy9kvBWLGO9FmI-n2hhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAII8jSvx0MJAeHnFYS-2meP1RVNbKPDzb456ySey0IAmspQECAyYgASFYILWA3ZTkdGv5NwBVbLgCQrUWqxK0cJbVemFblc0EfEYjIlgggDjjOw4PVtuk-LOVnjN3f7xRIikYF6PMiUW3FT_rvNs";
  const clientDataJSON =
    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaktBV0xqekt3anRMSXZlazFlbFh1eWpFS0trRXJhcUFTS2ZwS3ZFZVVDVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";

  // Call the verify function
  const { pem: returnedPem, ...result } = await verify(
    attestationObject,
    clientDataJSON
  );

  // Expected result object
  const expectedResult = {
    isValidSignature: true,
    challenge: "jKAWLjzKwjtLIvek1elXuyjEKKkEraqASKfpKvEeUCU",
  };

  assert.deepStrictEqual(
    result,
    expectedResult,
    "The verify function should return the expected result"
  );

  assert.equal(typeof returnedPem, "string");
  assert.equal(returnedPem.startsWith("-----BEGIN PUBLIC KEY-----"), true);
  assert.equal(returnedPem.endsWith("-----END PUBLIC KEY-----\n"), true);
});

test("should return a base64 string", () => {
  const challenge = generateChallenge();
  assert.ok(challenge, "Challenge should not be empty");

  // Base64 string validation
  const base64Pattern =
    /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
  assert.match(
    challenge,
    base64Pattern,
    "Challenge should be a valid base64 string"
  );

  // Length check - 32 bytes = 24 characters in base64
  assert.equal(
    challenge.length,
    44,
    "Challenge should be 44 characters long in base64"
  );
});

test("Converts standard Base64 to Base64 URL encoding", () => {
  const standardBase64 = "Wid/+jy0bYwg8hgEwiJa16BIepoF8N5sPcc2bixLMcs=";
  const expected = "Wid_-jy0bYwg8hgEwiJa16BIepoF8N5sPcc2bixLMcs";
  const result = toUrlEncodedBase64(standardBase64);
  assert.equal(result, expected);
});

test("login", async () => {
  const pem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2l4mnoqHyLccVaU1WnHzvGgdNSzz
mvAk3i3vMRU/SwqkdC9owo2R/vqzIwlabyANkBwKASc6wvuCZVccn8MYsw==
-----END PUBLIC KEY-----`;
  const authenticatorData =
    "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA";
  const clientDataJSON =
    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZ1JvQUh2SmFRa1B3NUd0UUpYTjFhbGJINF9Lcjl0elRfZlpma203cE5yUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
  //credentialId: "J0mAjH8ey5_iUgtLfDXQl9LqPtQqHJ22-RjO09pZPxc";
  const signature =
    "MEUCIQDbNbNPZKgrkk_1FMLO-6DuCaMfAu0rcTiW0J1HYJxR8QIgJaULp7iGjOuNncWCbMUrAOLj2lsV0awg3HYI0oHPOGM";

  const v = await verifyLogin(
    authenticatorData,
    clientDataJSON,
    signature,
    pem
  );

  assert.equal(v, true);
});
