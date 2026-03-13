# Nova App Template

## 1. Introduction
This repository is a Nova app example with:
- FastAPI backend in [`enclave/`](./enclave)
- Next.js frontend panel in [`frontend/`](./frontend)
- Example contracts in [`contracts/`](./contracts)
- Repo `enclaver.yaml` template (portal can parse listening port and file-proxy mount config from it)

The backend includes public endpoints (`/health`, `/status`, `/.well-known/attestation`) and `/api/*` demo endpoints for KMS, app-wallet, S3 storage, mounted directory access, encryption, oracle, and event monitoring.

## 2. Features Included
- **Attestation + Identity**: Fetch Nitro attestation and TEE wallet identity.
- **E2E Encryption Demo**: ECDH + AES-GCM request/response flow.
- **Dual-Chain Defaults**: Auth chain Base Sepolia (`84532`) and business chain Ethereum mainnet (`1`) in template config.
- **KMS + KV APIs**: `/api/kms/derive`, `/api/kms/kv/get|put|delete`.
- **App Wallet APIs**: `/api/app-wallet/address|sign|sign-tx`.
- **S3 Storage APIs**: `/api/storage*` plus `/api/storage/config`.
- **Mounted Directory APIs**: `/api/filesystem/config|write|read|list`.
- **Frontend Test Panel**: One-page UI to exercise all demo APIs.

## 3. Deploy on Nova Platform (Current Flow)

### 3.1 Create App
1. Open **Apps** in Nova portal and click **Create App**.
2. Fill basic fields (`name`, `repo_url`, optional `description`, `metadata_uri`, `app_contract_addr`).
3. Configure advanced options in the form (for example app listening port, KMS/App Wallet/S3/Mounted Directory/Helios toggles, chain selection).
4. Submit. The platform creates an app and assigns `sqid`.

### 3.2 Create Version (Build)
1. Open the app detail page, then open **Versions**.
2. Click **+ New Version**.
3. Submit `git_ref` and semantic `version` (for example `main` and `1.0.0`).
4. Wait for build status to become `success`.

Notes aligned with control-plane implementation:
- Repository URL is taken from the app record created in step 3.1.
- Build input is `git_ref + version`; there is no extra repository field in the build form.
- Control-plane generates `nova-build.yaml` and `enclaver.yaml` in app-hub from app settings before triggering workflow.

### 3.3 Deploy Version
1. In **Versions**, choose a successful version and click **Deploy this version**.
2. In deploy modal, choose `region` and `tier` (`standard` or `performance`).
3. Submit deployment and track state transitions in **Deployments**.

Notes aligned with portal/API:
- Deploy request fields are `build_id`, `region`, optional `tier`, optional `app_contract_addr`.
- Current deploy UI has no environment-variable input section.

## 4. Local Development Quick Start
```bash
# 1) Start frontend dev server
make dev-frontend

# 2) Build frontend static assets for backend serving
make build-frontend

# 3) Start backend locally (IN_ENCLAVE=false)
make dev-backend
```
Backend serves:
- **API Endpoint:** `http://localhost:8000`
- **UI Dashboard:** `http://localhost:8000/frontend/`

Default local chain behavior:
- Auth chain reads prefer mockup Helios at `http://odyn.sparsity.cloud:18545`
- Business chain reads prefer mockup Helios at `http://odyn.sparsity.cloud:18546`
- When `IN_ENCLAVE=true`, the same logic switches to enclave-local Helios on `127.0.0.1:18545` and `127.0.0.1:18546`

Startup note:
- On boot, the backend tries to restore `app_state.json` through Odyn S3. In local mockup mode this may return no state or fail transiently; the app logs `Starting fresh...` and continues with an empty in-memory state.

Platform-managed deploy note:
- Actual platform builds/deployments use control-plane generated app-hub `enclaver.yaml` from app settings.

## 5. Using `nova_python_sdk`

The canonical backend SDK lives in [`enclave/nova_python_sdk/`](./enclave/nova_python_sdk). Because the Docker image copies `enclave/` into the runtime image, backend modules inside [`enclave/`](./enclave) can import it directly:

```python
from nova_python_sdk.odyn import Odyn
from nova_python_sdk.kms_client import NovaKmsClient
from nova_python_sdk.rpc import ChainRpc

odyn = Odyn()
kms = NovaKmsClient(endpoint=odyn.endpoint)
```

Use each SDK module for one responsibility:
- [`enclave/nova_python_sdk/odyn.py`](./enclave/nova_python_sdk/odyn.py): identity, attestation, encryption, S3, and convenience wrappers around `/v1/kms/*` and `/v1/app-wallet/*`
- [`enclave/nova_python_sdk/kms_client.py`](./enclave/nova_python_sdk/kms_client.py): preferred thin client for KMS and app-wallet flows in request/response handlers
- [`enclave/nova_python_sdk/rpc.py`](./enclave/nova_python_sdk/rpc.py): shared RPC transport and environment switching; keep app-specific contract logic in [`enclave/chain.py`](./enclave/chain.py)
- [`enclave/nova_python_sdk/env.py`](./enclave/nova_python_sdk/env.py): shared `IN_ENCLAVE` and endpoint resolution helpers

Runtime endpoint precedence:
- Odyn API: `ODYN_API_BASE_URL` -> `ODYN_ENDPOINT` -> `http://127.0.0.1:18000` when `IN_ENCLAVE=true` -> `http://odyn.sparsity.cloud:18000` otherwise
- Business chain RPC: `ETHEREUM_MAINNET_RPC_URL` -> `BUSINESS_CHAIN_RPC_URL` -> `http://127.0.0.1:18546` when `IN_ENCLAVE=true` -> `http://odyn.sparsity.cloud:18546` otherwise
- Auth chain RPC: `NOVA_AUTH_CHAIN_RPC_URL` -> `AUTH_CHAIN_RPC_URL` -> `http://127.0.0.1:18545` when `IN_ENCLAVE=true` -> `http://odyn.sparsity.cloud:18545` otherwise

Recommended template pattern:
1. Create one shared `Odyn()` instance in [`enclave/app.py`](./enclave/app.py).
2. In route modules, build `NovaKmsClient(endpoint=odyn.endpoint)` when you need `/v1/kms/*` or `/v1/app-wallet/*`.
3. In [`enclave/chain.py`](./enclave/chain.py), build shared chain clients with `ChainRpc` and keep ABI selectors, contract read helpers, and transaction builders there.

## 6. Module Learning Map (Functionality + APIs + Implementation)

This section is intended for developers who want to **learn and reuse** each module.

### 6.1 Identify & Attestation
- **What it demonstrates**
  - Connecting to an enclave (via registry or direct URL)
  - Fetching and decoding AWS Nitro attestation
  - Displaying enclave identity (wallet + TEE pubkey)
- **App APIs used**
  - `GET /status`
  - `POST /.well-known/attestation`
  - `GET /api/encryption/public_key`
- **Enclaver/sidecar APIs involved**
  - `GET /v1/eth/address`
  - `POST /v1/attestation`
  - `GET /v1/encryption/public_key`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`identity` tab + connection panel)
  - Frontend crypto transport: [`frontend/src/lib/crypto.ts`](./frontend/src/lib/crypto.ts)
  - Registry integration: [`frontend/src/lib/registry.ts`](./frontend/src/lib/registry.ts)
  - Backend routes: [`enclave/routes.py`](./enclave/routes.py)

### 6.2 Hardware Entropy
- **What it demonstrates**
  - Hardware-backed random source from Nitro Secure Module
- **App APIs used**
  - `GET /api/random`
- **Enclaver/sidecar APIs involved**
  - `GET /v1/random`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`hardware-entropy` tab)
  - Backend handler: [`enclave/routes.py`](./enclave/routes.py) (`/api/random`)

### 6.3 Secure Echo (End-to-End Encrypted Request)
- **What it demonstrates**
  - Client-side request encryption and enclave-side decryption
  - Encrypted response return path
- **App APIs used**
  - `POST /api/echo`
- **Enclaver/sidecar APIs involved**
  - `POST /v1/encryption/encrypt`
  - `POST /v1/encryption/decrypt`
  - `GET /v1/encryption/public_key`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`secure-echo` tab)
  - Crypto helper: [`frontend/src/lib/crypto.ts`](./frontend/src/lib/crypto.ts)
  - Backend handler: [`enclave/routes.py`](./enclave/routes.py) (`/api/echo`)

### 6.4 S3 Storage (single module, encryption-aware)
- **What it demonstrates**
  - Put/Get/List/Delete object-style app data
  - Runtime inspection of current S3 encryption mode
- **App APIs used**
  - `POST /api/storage`
  - `GET /api/storage/{key}`
  - `GET /api/storage`
  - `DELETE /api/storage/{key}`
  - `GET /api/storage/config`
- **Enclaver/sidecar APIs involved**
  - `POST /v1/s3/put`
  - `POST /v1/s3/get`
  - `POST /v1/s3/list`
  - `POST /v1/s3/delete`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`storage` tab)
  - Backend handlers: [`enclave/routes.py`](./enclave/routes.py) (`/api/storage*` and `/api/storage/config`)
  - Runtime config: [`enclaver.yaml`](./enclaver.yaml) (`storage.s3.*`, `storage.s3.encryption.mode`)

### 6.5 Mounted Directory
- **What it demonstrates**
  - Mounting a host-backed loopback image into the enclave
  - Reading and writing regular files with normal filesystem APIs
  - Inspecting mount status and available capacity
- **App APIs used**
  - `GET /api/filesystem/config`
  - `POST /api/filesystem/write`
  - `GET /api/filesystem/read`
  - `GET /api/filesystem/list`
- **Enclaver/sidecar APIs involved**
  - Hostfs mount defined under `storage.mounts[]`
  - Runtime binding via `enclaver run --mount <name>=<host_state_dir>`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`filesystem` tab)
  - Backend handlers: [`enclave/routes.py`](./enclave/routes.py) (`/api/filesystem/*`)
  - Runtime config: [`enclaver.yaml`](./enclaver.yaml) (`storage.mounts`)

### 6.6 KMS Demo
- **What it demonstrates**
  - Deterministic key derivation
  - KMS-backed key/value operations (put/get/delete + TTL)
- **App APIs used**
  - `POST /api/kms/derive`
  - `POST /api/kms/kv/put`
  - `POST /api/kms/kv/get`
  - `POST /api/kms/kv/delete`
- **Enclaver/sidecar APIs involved**
  - `POST /v1/kms/derive`
  - `POST /v1/kms/kv/put`
  - `POST /v1/kms/kv/get`
  - `POST /v1/kms/kv/delete`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`kms-demo` tab)
  - Backend handlers: [`enclave/routes.py`](./enclave/routes.py) (`/api/kms/*`)
  - Canonical SDK: [`enclave/nova_python_sdk/kms_client.py`](./enclave/nova_python_sdk/kms_client.py)

### 6.7 App Wallet Sign
- **What it demonstrates**
  - Querying app-specific wallet address
  - EIP-191 message signing via app wallet
- **App APIs used**
  - `GET /api/app-wallet/address`
  - `POST /api/app-wallet/sign`
  - `POST /api/app-wallet/sign-tx` (backend supports tx signing)
- **Enclaver/sidecar APIs involved**
  - `GET /v1/app-wallet/address`
  - `POST /v1/app-wallet/sign`
  - `POST /v1/app-wallet/sign-tx`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`app-wallet` tab)
  - Backend handlers: [`enclave/routes.py`](./enclave/routes.py) (`/api/app-wallet/*`)
  - Wallet SDK: [`enclave/nova_python_sdk/kms_client.py`](./enclave/nova_python_sdk/kms_client.py)

### 6.8 Oracle Demo (Internet → Chain)
- **What it demonstrates**
  - Fetching external market data in enclave
  - Building/signing/submitting chain updates
  - Periodic scheduler + API trigger
- **App APIs used**
  - `POST /api/oracle/update-now`
  - `GET /status` (for cron counters)
  - `GET /api/events/oracle` and related event monitoring routes
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`oracle` tab)
  - Backend routes: [`enclave/routes.py`](./enclave/routes.py) (`/api/oracle/*`, `/api/events/*`)
  - Scheduler tasks: [`enclave/tasks.py`](./enclave/tasks.py)
  - App-specific chain logic: [`enclave/chain.py`](./enclave/chain.py)
  - Shared RPC SDK: [`enclave/nova_python_sdk/rpc.py`](./enclave/nova_python_sdk/rpc.py)

## 7. Reuse Guide (How to build your own module)

For any new feature, follow this template pattern:

1. **Add backend endpoint** in [`enclave/routes.py`](./enclave/routes.py).
2. **Reuse the canonical SDK first** from [`enclave/nova_python_sdk/`](./enclave/nova_python_sdk) for Odyn, KMS, app-wallet, and shared RPC logic.
3. **Keep app-specific blockchain logic** in [`enclave/chain.py`](./enclave/chain.py) instead of pushing business helpers into the shared SDK.
4. **Expose a frontend card/tab** in [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx).
5. **Document required runtime config** in [`enclaver.yaml`](./enclaver.yaml) and constants in [`enclave/config.py`](./enclave/config.py).
6. **Optionally add periodic execution** in [`enclave/tasks.py`](./enclave/tasks.py) if the feature needs background jobs.

This keeps every capability consistent: UI demo → app API → sidecar/platform API → reproducible config.
