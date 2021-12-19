import { expect } from "chai";

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
const PRI = `${AUDITOR_BASE_DIR}/${AUDITOR_NAME}/${AUDITOR_NAME}.sign.sha256`;

describe("Tee Task", () => {
  expect(TEE_TASK.init(PUB, PRI, ENCLAVE_INFO_PATH, 8082)).to.eq(0);
  expect(TEE_TASK.submit_task("echo", "Hello", "uid", "token")).to.eq(
    "Hello, Eigen"
  );
  expect(TEE_TASK.release()).to.eq(0);
});
