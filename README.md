# Nova App Template

A production-oriented starter for Nova TEE apps with:

1. KMS integration and app-wallet support
2. Encrypted S3 persistence
3. Dual-chain topology

Default chain topology:
- Auth chain (registry / KMS authorization): Base Sepolia (`84532`)
- Business chain (application logic): Ethereum Mainnet (`1`)

## What this template already includes

- Verifiable enclave identity (Nitro attestation + enclave wallet)
- End-to-end encrypted client ↔ enclave calls (ECDH + AES-GCM)
- KMS APIs exposed via app backend:
  - `/api/kms/derive`
  - `/api/kms/kv/get|put|delete`
- App-wallet APIs exposed via app backend:
  - `/api/app-wallet/address`
  - `/api/app-wallet/sign`
  - `/api/app-wallet/proof`
  - `/api/app-wallet/proof/default`
  - `/api/app-wallet/sign-tx`
- Business transaction signing policy:
  - app-wallet signer first
  - automatic fallback to TEE wallet signer if app-wallet endpoint is unavailable
- S3 storage demo with encryption mode visibility and state anchoring hooks
- Frontend panel for KMS/App Wallet quick validation

## Key files

- `enclaver.yaml`: runtime wiring (KMS integration, S3 encryption, Helios)
- `enclave/config.py`: static app config (dual chain + app-wallet defaults)
- `enclave/routes.py`: API surface (KMS, app-wallet, storage, oracle)
- `enclave/kms_client.py`: wrapper for Odyn internal KMS/app-wallet endpoints
- `enclave/chain.py`: business/auth chain status helpers
- `frontend/src/app/page.tsx`: demo UI
- `frontend/src/lib/registry.ts`: default registry address + RPC

## Configuration checklist

### 1) Enclaver manifest (`enclaver.yaml`)

The template is preconfigured for:
- `kms_integration.enabled: true`
- `storage.s3.encryption.mode: kms`
- `helios_rpc.kind: ethereum`
- `helios_rpc.network: mainnet`

You must update at least:
- `kms_integration.kms_app_id`
- `kms_integration.base_urls`
- `storage.s3.bucket`
- `storage.s3.prefix`
- `helios_rpc.execution_rpc` (your mainnet execution RPC)

### 2) App config (`enclave/config.py`)

Update:
- `CONTRACT_ADDRESS`
- `APP_ID`
- `APP_VERSION_ID`
- `BROADCAST_TX` (default is `False` for safety)

Defaults:
- `AUTH_CHAIN_RPC_URL = "https://sepolia.base.org"`
- `BUSINESS_CHAIN_DIRECT_RPC_URL = "https://eth.llamarpc.com"`
- `NOVA_APP_REGISTRY_ADDRESS = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"`

## Quick start

```bash
# 1) Frontend dev server
make dev-frontend

# 2) Build frontend assets into enclave bundle
make build-frontend

# 3) Start backend in local/mock mode
make dev-backend
```

Endpoints:
- API: `http://localhost:8000`
- UI: `http://localhost:8000/frontend/`
- Public attestation: `http://localhost:8000/.well-known/attestation`

## API overview

### Identity & encryption
- `GET /status`
- `GET /api/attestation`
- `POST /.well-known/attestation`
- `POST /api/sign`
- `GET /api/encryption/public_key`
- `POST /api/encrypt`
- `POST /api/decrypt`

### Chain, KMS, app wallet
- `GET /api/chains`
- `GET /api/storage/config`
- `POST /api/kms/derive`
- `POST /api/kms/kv/get`
- `POST /api/kms/kv/put`
- `POST /api/kms/kv/delete`
- `GET /api/app-wallet/address`
- `POST /api/app-wallet/sign`
- `POST /api/app-wallet/proof`
- `POST /api/app-wallet/proof/default`
- `POST /api/app-wallet/sign-tx`

### Storage + contract + oracle
- `POST /api/storage`
- `GET /api/storage`
- `GET /api/storage/{key}`
- `DELETE /api/storage/{key}`
- `GET /api/contract`
- `POST /api/contract/update-state`
- `POST /api/oracle/update-now`
- `GET /api/events/oracle`
- `GET /api/events/monitor`

## Security notes

- `storage.s3.encryption.mode=kms` requires `kms_integration.enabled=true`.
- Keep `BROADCAST_TX=false` until wallet funding + contract wiring is verified.
- `app-wallet/proof/default` requires valid `APP_ID` and `APP_VERSION_ID` in `enclave/config.py`.

## Deployment flow (summary)

1. Deploy app contract (typically on Ethereum mainnet for business logic).
2. Configure registry address on the contract via `setNovaRegistry`.
3. Configure app wallet on the contract via `setAppWalletAddress` (recommended for app-wallet signing mode).
4. Configure template files (`enclaver.yaml` + `enclave/config.py`).
5. Deploy on Nova platform.
6. Use frontend `KMS & App Wallet` tab to validate end-to-end behavior.
