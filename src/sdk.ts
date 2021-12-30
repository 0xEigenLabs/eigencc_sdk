import { createSecureContext, SecureContext, ConnectionOptions, connect, getCiphers, DEFAULT_ECDH_CURVE, createServer, TLSSocket } from "tls";
import * as fs from "fs";

import { v4 as uuidv4 } from 'uuid';

const struct = require('python-struct');

// const tls = require("tls");
const forge = require('node-forge');
const pki = forge.pki;
const toml = require('toml');
// const { X509Certificate } = await import('crypto');
// const { Certificate } = await import('crypto');
import { verify } from "crypto"

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
        const socket = connect(this.port, this.hostname, options, () => {
            console.log('client connected',
                        socket.authorized ? 'authorized' : 'unauthorized');

            const peerCert = socket.getPeerCertificate(true)
            //console.log(peerCert)

            this._verify_report(peerCert.raw)
            const task: Task = new Task(
                method,
                payload
            )
            this._write_message(socket, task)
            console.log("Remote address", socket.remoteAddress)
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
        console.log("len: ", len)
        if (data.length != (8 + len)) {
            throw new Error("Read not complete")
        }
        const res = JSON.parse(data.slice(8).toString());
        console.log(res)
        if (res.Ok == undefined) {
            throw new Error("Read invalid response")
        }
        return res.Ok.result
    }

    _write_message(socket: any, message: any) {
        const message_json = JSON.stringify(message)
        const msg_format = "<Q" + message_json.length + "s"
        console.log(msg_format)
        const res = socket.write(struct.pack(msg_format, message_json.length, message_json), "utf8",  () => {
            console.log("write len done")
        } )
    }

    _verify_report(peerCert): boolean{
        if (process.env.SGX_MODE == "SW")
            return true
        const ext = JSON.parse(peerCert.extensions[0].value.value)
        const report = ext.report
        const signature = Buffer.from(ext.signature)
        const signing_cert = Buffer.from(ext.signing_cert)
        const cert = pki.certificateFromAsn1(signing_cert);

        let as_root_ca_cert = fs.readFileSync(this.as_root_ca_cert_path)
        as_root_ca_cert = pki.certificateFromAsn1(as_root_ca_cert)
        // store = X509Store()
        const store = pki.createCaStore([]);
        store.addCertificate(as_root_ca_cert)
        store.addCertificate(signing_cert)

        pki.verifyCertificateChain(store, [signing_cert], (verified, depth, chain) => {
            console.log("IAS Root ca verify success")
            return true;
        });

        // verify report's signature
        verify('sha256', Buffer.from(ext.report), signing_cert, signature)

        const report2 = JSON.parse(report)
        let quote = report2.isvEnclaveQuoteBody
        quote = quote.toString("base64")

        // get mr_enclave and mr_signer from the quote
        const mr_enclave = quote.substring(112, 112 + 32).toString("hex")
        const mr_signer = quote.substring(176, 176 + 32).toString("hex")

        // get enclave_info
        const enclave_info = toml.parse(this.enclave_info_path)

        // verify mr_enclave and mr_signer
        const enclave_name = "teaclave_" + this.name + "_service"
        if (mr_enclave != enclave_info[enclave_name].mr_enclave)
            throw new Error("mr_enclave error")

        if (mr_signer != enclave_info[enclave_name].mr_signer)
            throw new Error("mr_signer error")

        return true;
    }
}
