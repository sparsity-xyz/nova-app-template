# Tutorial: Nova App Template (KMS + S3 Encryption + Dual Chain)

This tutorial walks through the template defaults and the minimum edits needed to run it correctly.

## 1. Topology you are deploying

The template intentionally splits responsibilities:

- Auth chain (registry / KMS authz): Base Sepolia (`chain_id=84532`)
- Business chain (app logic): Ethereum Mainnet (`chain_id=1`)

Why:
- App-wallet proof and KMS authorization rely on `NovaAppRegistry` on the auth chain.
- Business contract writes/read flows stay independent on mainnet.

## 2. Prerequisites

- Python 3.10+
- Node.js 18+
- Foundry (for contract deployment)

## 3. Build and run locally

```bash
# in app-template/
make build-frontend
make dev-backend
```

Open:
- `http://localhost:8000/frontend/`

For enclave packaging (uses `sources.app: "nova-app-template:latest"` in `enclaver.yaml`):

```bash
make build-docker
make build-enclave
```

## 4. Configure enclave runtime (`enclaver.yaml`)

Required edits before real deployment:

1. `kms_integration.kms_app_id`
2. `kms_integration.nova_app_registry`
3. `storage.s3.bucket`
4. `storage.s3.prefix`
5. `helios_rpc.chains[*].execution_rpc`

The template already sets:
- `kms_integration.enabled: true`
- `kms_integration.use_app_wallet: true`
- `storage.s3.encryption.mode: kms`
- `helios_rpc.enabled: true`
- `helios_rpc.chains[0]` = Base Sepolia (`local_rpc_port=18545`) for auth-chain registry discovery
- `helios_rpc.chains[1]` = Ethereum Mainnet (`local_rpc_port=18546`) for business logic

## 5. Configure app constants (`enclave/config.py`)

Set these values:

```python
CONTRACT_ADDRESS = "0xYourBusinessContract"
APP_ID = 123
APP_VERSION_ID = 1
BROADCAST_TX = False  # set True only after wallet funding and dry-run verification
```

Keep these defaults unless you know you need to change them:

```python
AUTH_CHAIN_RPC_URL = "https://sepolia.base.org"
NOVA_APP_REGISTRY_ADDRESS = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
BUSINESS_CHAIN_ID = 1
```

Runtime signer behavior for business transactions:
- app-wallet signer is attempted first
- if unavailable, backend falls back to TEE wallet signer automatically

## 6. Deploy your contract (business chain)

Example (Ethereum mainnet):

```bash
cd contracts
forge install foundry-rs/forge-std
forge build

export RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
export PRIVATE_KEY=<your_private_key>
forge script script/Deploy.s.sol:DeployScript --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
```

If you verify the contract, use mainnet chain id:

```bash
forge verify-contract --chain-id 1 --watch --etherscan-api-key "$ETHERSCAN_API_KEY" "$APP_CONTRACT" src/ETHPriceOracleApp.sol:ETHPriceOracleApp
```

## 7. Set registry on your app contract

`NovaAppRegistry` is on Base Sepolia by default in this template.

```bash
export AUTH_RPC_URL=https://sepolia.base.org
export NOVA_REGISTRY=0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8

cast send "$APP_CONTRACT" "setNovaRegistry(address)" "$NOVA_REGISTRY" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
```

If you want business writes to use app-wallet as intended by this template, set it on contract:

```bash
export APP_WALLET=<address_from_/api/app-wallet/address>

cast send "$APP_CONTRACT" "setAppWalletAddress(address)" "$APP_WALLET" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
```

## 8. Validate from frontend

In `Enclaver Features` tab:

1. Run `Check Chain Topology` (`/api/chains`) and confirm:
   - auth chain = Base Sepolia
   - business chain = Ethereum mainnet
2. Run `Check S3 Encryption Config` (`/api/storage/config`) and confirm mode is `kms`.
3. Test `KMS Derive` and `KV Put/Get/Delete`.
4. Run `Get Address` and `Build Default Proof` for app wallet.
5. Run `Run Full Enclaver Demo` for end-to-end smoke verification across all four capabilities.

If proof fails with missing app metadata, set `APP_ID` and `APP_VERSION_ID` in `enclave/config.py`.

## 9. Common issues

- `KMS integration not configured`
  - Check `kms_integration.enabled=true`, `kms_app_id`, and `nova_app_registry`.
- `KMS registry mode validation failed at startup`
  - Ensure `helios_rpc.enabled=true` and one chain has `local_rpc_port: 18545`.
- `storage.s3.encryption.mode=kms` startup failure
  - Ensure KMS integration is enabled.
- `app_wallet proof` failure
  - `APP_ID/APP_VERSION_ID` not set, or registry metadata mismatch.
- Transaction signing works but no on-chain update
  - `BROADCAST_TX=false` returns signed tx only; it does not broadcast.
