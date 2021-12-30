import * as util from "./util";

require("dotenv").config();
import * as ecies from "./ecies";
import * as elliptic from "elliptic"
const EC = elliptic.ec;
const ec = new EC("p256");
import * as crypto from "crypto";

