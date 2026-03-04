# Nova App Template

## 1. Introduction
The **Nova App Template** is a production-ready starter kit designed to help developers quickly build and deploy applications on the Nova TEE (Trusted Execution Environment) Platform. It serves as the perfect starting point for your app development, showcasing the core capabilities of the Nova platform, including KMS integration, secure storage, cross-chain interactions, and remote attestation.

## 2. Features Included
This template comes pre-configured with several key features to demonstrate Nova's capabilities:
- **Verifiable Enclave Identity**: Out-of-the-box AWS Nitro attestation and TEE enclave wallet.
- **End-to-End Encryption**: Secure client-to-enclave communication using ECDH and AES-GCM.
- **Dual-Chain Topology**: Support for interacting with multiple networks simultaneously. By default, it uses Base Sepolia (`84532`) for KMS authorization/registry and Ethereum Mainnet (`1`) for business logic.
- **KMS Integration**: Easily derive keys and securely store/retrieve key-value pairs via the App Backend (`/api/kms/derive`, `/api/kms/kv/*`).
- **App Wallet Application**: Application-specific wallets with API endpoints for address retrieval, message signing, and transaction signing (`/api/app-wallet/*`). Includes a smart fallback to the TEE wallet signer if the app-wallet endpoint is unavailable.
- **Encrypted S3 Persistence**: State anchoring and transparently encrypted S3 storage (`storage.s3.encryption.mode: kms`).
- **Built-in Frontend**: A React-based UI panel to quickly validate KMS, App Wallet, E2E encryption, and other enclave features.

## 3. Deployment on Nova Platform
To deploy this template to the Nova platform, you will use the Nova Platform interface. Here is how to prepare and deploy your app:

### 3.1 Pre-deployment Configuration
Before building, ensure you have updated the necessary configuration files in your repository fork:
- **`enclaver.yaml`**: Update `kms_integration.kms_app_id`, `kms_integration.nova_app_registry`, `storage.s3.bucket`, `storage.s3.prefix`, and `helios_rpc.chains[*].execution_rpc`.
- **`enclave/config.py`**: Update `CONTRACT_ADDRESS`, `APP_ID`, `APP_VERSION_ID`, and set `BROADCAST_TX` as needed.

### 3.2 Create App
1. Go to the Nova Platform portal and navigate to the **Apps** section.
2. Click **Create App**.
3. **App Name**: Provide a name for your application (e.g., `My Nova App`).
4. **Description**: Briefly describe your application.
5. After creation, you will receive an **App ID**. Update your `enclave/config.py` and `enclaver.yaml` with this ID and push the changes to your repository.

### 3.3 Build Version
1. Navigate to your App's detail page and go to the **Builds** or **Versions** tab.
2. Click **Create Build**.
3. **Version Tag**: Set a version identifier (e.g., `v1.0.0`).
4. **Git Repository**: Provide the Git URL to your fork of this `app-template`.
5. **Git Branch/Commit**: Specify the branch name (e.g., `main`) or commit hash.
6. Submit the build. The system will build your Docker image, wrap it into an enclave (`make build-enclave`), and generate the enclave measurements (PCRs).

### 3.4 Deploy Version
1. Go to the **Deployments** section for your App.
2. Click **Create Deployment**.
3. **Select Version**: Choose the version you successfully built in the previous step.
4. **Environment Variables**: Inject any secure environment variables required at runtime (e.g., AWS S3 credentials like `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`).
5. **Deploy**: Start your application. Your app will securely boot within a Nova TEE node.

## 4. Using the App-Template Frontend
The template includes a built-in frontend for testing APIs and validating enclave behaviors locally or after deployment.

### Local Development Quick Start
```bash
# 1) Start the frontend development server
make dev-frontend

# 2) Build frontend static assets into the enclave bundle
make build-frontend

# 3) Start the Python backend locally (mocking TEE features)
make dev-backend
```
Once the backend is running, it will serve:
- **API Endpoint:** `http://localhost:8000`
- **UI Dashboard:** `http://localhost:8000/frontend/`

The frontend dashboard provides tabs for:
- **KMS & App Wallet**: Quickly test KMS key derivation and App Wallet signatures.
- **Enclaver Features**: Run one-click end-to-end checks across multi-chain RPCs, S3 encryption, and app-wallet availability.
- **Storage**: Test state anchoring and encrypted KV operations.

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
  - Periodic scheduler + manual trigger
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
