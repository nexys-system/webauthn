import fs from "fs";
import http from "http";
import {
  generateChallenge,
  toUrlEncodedBase64,
  verify,
  verifyLogin,
} from "./lib/main.js";

// challenge storage
const challenges: Map<string, string> = new Map(); //  challenge => userId
const credentials: Map<string, { credentialId: string; pemPublicKey: string }> =
  new Map(); //  userId => credentials

const server = http.createServer((req, res) => {
  if (req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html" });
    fs.createReadStream("./assets/index.html").pipe(res);
  } else if (req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      const data = JSON.parse(body);

      // pre register
      if (req.url === "/preregister") {
        // get userid
        const userId = data.userId;

        // create user object
        const user = { id: userId, name: "John Doe", displayName: "John Doe" };
        // reyling party
        const rp = {
          name: "Example Corp",
        };

        const challenge = generateChallenge();
        challenges.set(toUrlEncodedBase64(challenge), userId); // Store challenge for later verification (in url encoded because this is what we will retrieve)
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ user, rp, challenge }));
        return;
      }

      // pre register
      if (req.url === "/prelogin") {
        // get userid
        const { userId } = data;

        const credential = credentials.get(userId);

        if (!credential) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "credential not found" }));
          return;
        }

        const { credentialId } = credential;

        const challenge = generateChallenge();
        challenges.set(toUrlEncodedBase64(challenge), userId); // Store challenge for later verification (in url encoded because this is what we will retrieve)
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ credentialId, challenge }));
        return;
      }

      // register
      if (req.url === "/register") {
        const { credentialId, attestationObject, clientDataJSON } = data;

        verify(attestationObject, clientDataJSON)
          .then(({ challenge, isValidSignature, pem }) => {
            res.writeHead(200, { "Content-Type": "application/json" });

            const userId = challenges.get(challenge);

            if (!userId) {
              res.writeHead(401, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "did not find the challenge" }));
              return;
            }

            challenges.delete(challenge);

            //save credentialId
            credentials.set(userId, { credentialId, pemPublicKey: pem });

            if (isValidSignature) {
              res.end(JSON.stringify({ userId }));
              return;
            }
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                isValidSignature,
                error: "could not authenticate you",
              })
            );
          })
          .catch((err) => {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "something went wrong", err }));
          });

        // Respond with the challenge

        return;
        // login
      }
      if (req.url === "/login") {
        const { authenticatorData, clientDataJSON, signature } = data;

        const clientDataJSONBuffer = Buffer.from(clientDataJSON, "base64");
        const clientData = JSON.parse(clientDataJSONBuffer.toString("utf8"));

        const userId = challenges.get(clientData.challenge);

        if (!userId) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "no user id from challenge" }));
          return;
        }

        const credential = credentials.get(userId);

        if (!credential) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({ error: "no credential for user " + userId })
          );
          return;
        }

        verifyLogin(
          authenticatorData,
          clientDataJSON,
          signature,
          credential.pemPublicKey
        )
          .then((x) => {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "logged in" }));
          })
          .catch((e) => {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "login failed", e }));
          })
          .finally(() => {
            return;
          });

        return;
      }
    });
  } else {
    res.writeHead(405);
    res.end();
  }
});

const port = process.env.PORT || 8000;
server.listen(port, () =>
  console.log(`Server running at http://localhost:${port}/`)
);
