# Eigen Relay SDK

[EigenCC](https://github.com/ieigen/ieigen/tree/main/cc) Javascript SDK.

## Usage

### How to setup sdk

```
# Set TEESDK related parameters here
TEESDK_AUDITOR_BASE_DIR="deps/examples/auditors"
TEESDK_AUDITOR_NAME="godzilla"
TEESDK_ENCLAVE_INFO_PATH="deps/examples/enclave_info.toml"
SGX_MODE=SW
RELAY_ADDRESS=192.168.0.23
RELAY_PORT=8082
```
SGX_MODE: SW or HW, specify the verification mode of EigenCC/Eigen Relay
RELAY_ADDRESS/RELAY_PORT: the EigenCC/Relay endpoint information
TEESDK_ENCLAVE_INFO_PATH: the mrsigner and mrenclave of EigenCC/Relay

### Compile

```sh
yarn && yarn build
yarn test
```
