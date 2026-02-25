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

## 5. Implementation Details
For developers looking to understand or modify the underlying logic, here are the core files for each feature:

- **Enclaver Runtime Setup:** [`enclaver.yaml`](./enclaver.yaml)
  - Configures KMS integration, S3 transparent encryption, and dual-chain Helios RPC endpoints.
- **API Surface:** [`enclave/routes.py`](./enclave/routes.py)
  - Exposes the REST API for KMS, App Wallet, storage, oracle, and attestation.
- **KMS & App Wallet Client:** [`enclave/kms_client.py`](./enclave/kms_client.py)
  - Python wrapper interacting with internal `odyn` daemon endpoints.
- **Chain Integration:** [`enclave/chain.py`](./enclave/chain.py)
  - On-chain helpers and business/auth chain status checks.
- **App Configuration:** [`enclave/config.py`](./enclave/config.py)
  - Static configuration, including RPC URLs, App Wallet defaults, and contract addresses.
- **Frontend UI:** [`frontend/src/app/page.tsx`](./frontend/src/app/page.tsx)
  - Main React dashboard demonstrating all feature integrations.
- **Frontend Config:** [`frontend/src/lib/registry.ts`](./frontend/src/lib/registry.ts)
  - Default registry address and RPC configuration for the UI.
