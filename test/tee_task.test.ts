import { expect } from "chai";
import * as ecies from "../src/ecies";
import * as elliptic from "elliptic"
const EC = elliptic.ec;
const ec = new EC("p256");
import * as crypto from "crypto";


const TEE_TASK = require("bindings")("tee_task");

require("dotenv").config();

const require_env_variables = (envVars) => {
  for (const envVar of envVars) {
    if (process.env[envVar] === undefined) {
      throw new Error(`Error: set your '${envVar}' environmental variable `);
    }
    console.log(`${envVar}: ${process.env[envVar]}`);
  }
  console.log("Environmental variables properly set 👍");
};

require_env_variables([
  "TEESDK_AUDITOR_BASE_DIR",
  "TEESDK_AUDITOR_NAME",
  "TEESDK_ENCLAVE_INFO_PATH",
]);

const AUDITOR_BASE_DIR = process.env["TEESDK_AUDITOR_BASE_DIR"];
// auditor_name, e.g., "godzilla"
const AUDITOR_NAME = process.env["TEESDK_AUDITOR_NAME"];
const ENCLAVE_INFO_PATH = process.env["TEESDK_ENCLAVE_INFO_PATH"];
const PUB = `${AUDITOR_BASE_DIR}/${AUDITOR_NAME}/${AUDITOR_NAME}.public.der`;
const SIG = `${AUDITOR_BASE_DIR}/${AUDITOR_NAME}/${AUDITOR_NAME}.sign.sha256`;

describe("Tee Task", () => {
  expect(TEE_TASK.init(PUB, SIG, ENCLAVE_INFO_PATH, "localhost", 8082)).to.eq(0);

  // read relay public key
  let relayPubKey = TEE_TASK.submit_task("EigenTEERegister", "", "uid", "token")
  console.log(relayPubKey)

  const options = {
      hashName: 'sha512',
      hashLength: 64,
      macName: 'sha256',
      macLength: 32,
      curveName: 'prime256v1',
      symmetricCypherName: 'aes-256-gcm',
      keyFormat: 'uncompressed',
      s1: null, // optional shared information1
      s2: null // optional shared information2
  }
  const keyPair = ec.keyFromPublic(relayPubKey, "hex");
  const publicKey = keyPair.getPublic();

  // generate c1
  let privateKey = crypto.randomBytes(32).toString("base64");
  console.log("msg", privateKey)
  const c1 = ecies.encrypt(publicKey, privateKey, options).toString("hex");

  // generate cc1
  let password = crypto.randomBytes(16).toString("base64");
  console.log("Password", password)
  let cc1 = ecies.encrypt(publicKey, password, options).toString("hex");

  // encrypt by kms
  let encryptMsg = `encrypt|${c1}|${cc1}|`
  let c2 = TEE_TASK.submit_task("relay", encryptMsg, "uid", "token")
  console.log(c2)

  // decrypt
  let aesKey = crypto.randomBytes(32)
  console.log(aesKey)
  let cr1 = ecies.encrypt(publicKey, aesKey, options).toString("hex")
  let cc2 = c2.toString("hex")

  encryptMsg = `decrypt|${cc2}|${cc1}|${cr1}`
  let decryptedPrivateKey = TEE_TASK.submit_task("relay", encryptMsg, "uid", "token")

  let privateKey2 = ecies.aes_dec('aes-256-gcm', aesKey, Buffer.from(decryptedPrivateKey, "base64"))
  console.log("msg", privateKey2)

  expect(privateKey).to.eq(privateKey2)
  expect(TEE_TASK.release()).to.eq(0);
});
