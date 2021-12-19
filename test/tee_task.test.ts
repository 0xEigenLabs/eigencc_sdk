import { expect } from "chai";
require("./src/util");

const tee_task = require("bindings")("tee_task");

require("dotenv").config();

describe("Tee Task", () => {
  expect(tee_task.init()).to.eq(0);
});
