# Nova App Template

## 1. Introduction
This repository is a Nova app example with:
- FastAPI backend in [`enclave/`](./enclave)
- Next.js frontend panel in [`frontend/`](./frontend)
- Example contracts in [`contracts/`](./contracts)
- Repo `enclaver.yaml` template (portal can parse listening port from it)

The backend includes public endpoints (`/health`, `/status`, `/.well-known/attestation`) and `/api/*` demo endpoints for KMS, app-wallet, storage, encryption, oracle, and event monitoring.

## 2. Features Included
- **Attestation + Identity**: Fetch Nitro attestation and TEE wallet identity.
- **E2E Encryption Demo**: ECDH + AES-GCM request/response flow.
- **Dual-Chain Defaults**: Auth chain Base Sepolia (`84532`) and business chain Ethereum mainnet (`1`) in template config.
- **KMS + KV APIs**: `/api/kms/derive`, `/api/kms/kv/get|put|delete`.
- **App Wallet APIs**: `/api/app-wallet/address|sign|sign-tx`.
- **S3 Storage APIs**: `/api/storage*` plus `/api/storage/config`.
- **Frontend Test Panel**: One-page UI to exercise all demo APIs.

## 3. Deploy on Nova Platform (Current Flow)

### 3.1 Create App
1. Open **Apps** in Nova portal and click **Create App**.
2. Fill basic fields (`name`, `repo_url`, optional `description`, `metadata_uri`, `app_contract_addr`).
3. Configure advanced options in the form (for example app listening port, KMS/App Wallet/S3/Helios toggles, chain selection).
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

Platform-managed deploy note:
- Actual platform builds/deployments use control-plane generated app-hub `enclaver.yaml` from app settings.

## 5. Module Learning Map (Functionality + APIs + Implementation)

This section is intended for developers who want to **learn and reuse** each module.

### 5.1 Identify & Attestation
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

### 5.2 Hardware Entropy
- **What it demonstrates**
  - Hardware-backed random source from Nitro Secure Module
- **App APIs used**
  - `GET /api/random`
- **Enclaver/sidecar APIs involved**
  - `GET /v1/random`
- **Implementation entry points**
  - Frontend: [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx) (`hardware-entropy` tab)
  - Backend handler: [`enclave/routes.py`](./enclave/routes.py) (`/api/random`)

### 5.3 Secure Echo (End-to-End Encrypted Request)
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

### 5.4 S3 Storage (single module, encryption-aware)
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

### 5.5 KMS Demo
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
  - KMS SDK wrapper: [`enclave/kms_client.py`](./enclave/kms_client.py)

### 5.6 App Wallet Sign
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
  - Wallet logic: [`enclave/kms_client.py`](./enclave/kms_client.py)

### 5.7 Oracle Demo (Internet → Chain)
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
  - Chain adapters: [`enclave/chain.py`](./enclave/chain.py)

## 6. Reuse Guide (How to build your own module)

For any new feature, follow this template pattern:

1. **Add backend endpoint** in [`enclave/routes.py`](./enclave/routes.py).
2. **Encapsulate platform calls** (KMS/S3/App Wallet/Chain) in helper module(s) such as [`enclave/kms_client.py`](./enclave/kms_client.py) or [`enclave/chain.py`](./enclave/chain.py).
3. **Expose a frontend card/tab** in [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx).
4. **Document required runtime config** in [`enclaver.yaml`](./enclaver.yaml) and constants in [`enclave/config.py`](./enclave/config.py).
5. **Optionally add periodic execution** in [`enclave/tasks.py`](./enclave/tasks.py) if the feature needs background jobs.

This keeps every capability consistent: UI demo → app API → sidecar/platform API → reproducible config.
