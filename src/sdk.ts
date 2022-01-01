import { createSecureContext, SecureContext, ConnectionOptions, connect, getCiphers, DEFAULT_ECDH_CURVE, createServer, TLSSocket } from "tls";
import * as fs from "fs";
import { v4 as uuidv4 } from 'uuid';
const struct = require('python-struct');
const toml = require('toml');
import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

function wait(ms) {
    return new Promise((resolve) => setTimeout(() => resolve, ms));
};

class Task {
    task_id: string
    function_name: string
    task_token: string
    payload?: string

    constructor(function_name: string, payload: string) {
        this.task_id = uuidv4()
        this.function_name = function_name
        this.task_token = ""
        this.payload = payload
    }
}

export class EigenRelayClient {
    cert: string
    signature: string
    enclave_info_path: string
    hostname: string
    port: number
    as_root_ca_cert_path: string
    context: SecureContext
    socket: TLSSocket
    name: string

    constructor(name: string, pub: string,
                sig: string,
                root_ca_path: string,
                enclave_conf_path: string,
                hostname:string,
                port: number) {
        this.name = name
        this.cert = pub
        this.signature = sig
        this.as_root_ca_cert_path = root_ca_path
        this.enclave_info_path = enclave_conf_path;

        this.hostname = hostname
        this.port = port
    }

    submit_task(method: string, payload: string, callback: any) {
        const options = {
            // Necessary only if the server requires client certificate authentication.
            // key: fs.readFileSync(this.private_key),
            // cert: fs.readFileSync(this.cert),

            // Necessary only if the server uses a self-signed certificate.
            // ca: [ fs.readFileSync(this.as_root_ca_cert_path) ],

            // Necessary only if the server's cert isn't for "localhost".
            // checkServerIdentity: () => { return null; },
            rejectUnauthorized: false,
        };
        const socket = connect(this.port, this.hostname, options, async() => {
            console.log('client connected',
                        socket.authorized ? 'authorized' : 'unauthorized');

            const peerCert = socket.getPeerCertificate(true)

            let verifyResult = false
            try {
                verifyResult = await this._verify_report(peerCert.raw.toString("base64"))
            } catch (e) {
                console.log("Verify report failed", e)
                verifyResult = false
            }
            if (verifyResult != true) {
                //TODO throw exception
                console.log("Skip verifying")
            }

            const task: Task = new Task(
                method,
                payload
            )
            this._write_message(socket, task)
        })

        let data
        socket.on('data', (chunk) => {
            console.log("Read ", typeof(chunk), chunk)
            data = chunk
            socket.destroy();
        }).on('end', function() {
            console.log("Read end,")
        }).on('error', function () {
            // How kill all processes of the current socket ???
            console.log("error!")
        }).on("close", () => {
            callback(this._read_message(data))
            console.log("Close")
        })
    }

    _read_message(data: Buffer): string {
        const raw = "";
        const response_len = struct.unpack("<Q", data.slice(0, 8))
        const len = Number(response_len[0])
        if (data.length != (8 + len)) {
            throw new Error("Read not complete")
        }
        const res = JSON.parse(data.slice(8).toString());
        if (res.Ok == undefined) {
            throw new Error("Read invalid response")
        }
        return res.Ok.result
    }

    _write_message(socket: any, message: any) {
        const message_json = JSON.stringify(message)
        const msg_format = "<Q" + message_json.length + "s"
        const res = socket.write(struct.pack(msg_format, message_json.length, message_json), "utf8",  () => {
            console.log("write len done")
        } )
    }

    async _verify_report(certDer): Promise<boolean> {
        if (process.env.SGX_MODE == "SW")
            return true

        let peerCert = new x509.X509Certificate(certDer)
        let value = peerCert.extensions[0].value
        let ext = new TextDecoder().decode(value).split("|")
        console.log(ext)

        const report = JSON.parse(ext[0])
        const signature = Buffer.from(ext[1],"base64")

        const signing_cert = new x509.X509Certificate(ext[2]);

        //verify signing cert with AS root cert
        let as_root_ca_cert_str = fs.readFileSync(this.as_root_ca_cert_path)
        const root_cert = new x509.X509Certificate(as_root_ca_cert_str);

        let signingVerify = await signing_cert.verify({publicKey: root_cert})
        if (signingVerify != true) {
            throw new Error("Invalid signing certificate")
        }

        // verify report's signature
        let publicKey = await signing_cert.publicKey.export();
        let verifySig = await crypto.subtle.verify(
            publicKey.algorithm.name,
            publicKey,
            signature,
            Buffer.from(ext[0]))
        console.log("verifySig", verifySig)
        if (verifySig != true) {
            throw new Error("Verify report signature failed")
        }

        let quote = Buffer.from(report.isvEnclaveQuoteBody, "base64").toString("hex")

        // get mr_enclave and mr_signer from the quote
        const mr_enclave = quote.substring(224, 224 + 64)
        const mr_signer = quote.substring(352, 352 + 64)

        // get enclave_info
        const enclave_info = toml.parse(fs.readFileSync(this.enclave_info_path))

        // verify mr_enclave and mr_signer
        const enclave_name = this.name
        if (mr_enclave != enclave_info[enclave_name].mr_enclave)
            throw new Error("mr_enclave error")

        if (mr_signer != enclave_info[enclave_name].mr_signer)
            throw new Error("mr_signer error")

        return true;
    }
}
