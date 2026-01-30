# Nova App Template

This repository provides a template for building and deploying verifiable TEE applications on the [NovaStack](https://github.com/sparsity-xyz/nova-stack) (or [Nova platform](https://sparsity.cloud/), if you prefer a managed infrastructure). Its primary goal is to demonstrate NovaStack's core features and provide developers with a ready-to-use foundation.

The template covers:

1. **Verifiable TEE Runtime**: Secure execution within AWS Nitro Enclaves with automated attestation and hardware-sealed identity.
2. **Isolated S3 Storage**: Encrypted key-value storage with on-chain state hash anchoring for verifiable persistence.
3. **Trustless RPC (Helios)**: Built-in support for the Helios light client, enabling verifiable blockchain interactions.
4. **Automated Oracle & Event Tasks**: Periodic background tasks for fetching external data and responding to on-chain events.
5. **End-to-End Encryption**: Public Attestation endpoints and ECDH-based encrypted communication channels.
6. **Modern Developer Stack**: A complete Next.js frontend and a local mockup environment (`odyn.py`) for seamless development.

---

## Structure

```
|-- enclave/               # Application backend in TEE (FastAPI)
|   |-- app.py             # App entry
|   |-- routes.py          # API routes for business logic
|   |-- tasks.py           # Scheduler tasks & event polling
|   |-- odyn.py            # Odyn SDK (internal API)
|   |-- chain.py           # On-chain helpers & Web3 integration
|   |-- requirements.txt   # Backend dependencies
|   |-- frontend/          # Built frontend assets for bundling
|-- contracts/             # Solidity contracts
|-- frontend/              # Next.js frontend 
|-- enclaver.yaml          # Enclaver build configuration
|-- Dockerfile             # Multi-stage TEE build for backend and frontend
|-- Makefile               # Dev & Build commands
```

---

## Core Capabilities

### 1) Verifiable TEE Runtime
Nova provides a secure environment using **AWS Nitro Enclaves**.
- **Hardware-Sealed Identity**: The TEE generates its own Ethereum wallet (`odyn.eth_address()`) derived from enclave-local secrets.
- **Remote Attestation**: Cryptographic proof of the enclave's state and measurements (PCRs), verifiable by anyone.
- **Related Code**: [enclave/app.py](enclave/app.py), [enclave/odyn.py](enclave/odyn.py)

### 2) Isolated S3 Storage
The platform provides persistent storage isolated to your specific app.
- **S3 read/write**: Use `odyn.s3_put` and `odyn.s3_get` for persistence.
- **State Hash Anchoring**: After writing data, the app computes a Keccak256 state hash and updates it on-chain via `updateStateHash(bytes32)`.
- **Related Code**: [enclave/routes.py](enclave/routes.py), [contracts/src/NovaAppBase.sol](contracts/src/NovaAppBase.sol)

### 3) Trustless RPC (Helios)
Eliminate intermediate trust by using a built-in light client.
- **Helios Integration**: The enclave runs a Helios instance that syncs with **Base Sepolia**.
- **Verifiable State**: `chain.py` uses Helios (port 8545) for all blockchain reads, ensuring data integrity.
- **Related Code**: [enclave/chain.py](enclave/chain.py), [enclaver.yaml](enclaver.yaml)

### 4) Automated Oracle & Event Tasks
Background workers handle time-gated or event-driven business logic.
- **Periodic Oracle**: `tasks.background_task()` fetches external data (e.g., ETH price) every 15 minutes.
- **Event Listener**: `poll_contract_events()` watches for on-chain requests (e.g., `StateUpdateRequested`) to trigger TEE responses.
- **Related Code**: [enclave/tasks.py](enclave/tasks.py)

### 5) End-to-End Encryption
Secure communication directly between the user's browser and the TEE.

The frontend supports two connection methods:

#### 5.1 Via Nova Registry (Recommended)
Connect using an App ID from the Nova App Registry. This is the recommended approach because:
- **On-chain Trust Anchor**: The registry stores verified `codeMeasurement`, `teePubkey`, and `appUrl` on-chain
- **ZKP Verification**: Apps registered via ZKP have cryptographic proof of their attestation
- **Public Key Pinning**: The frontend verifies the enclave's public key matches the registry value

**How it works:**
1. User enters the App ID in the frontend
2. Frontend queries the Nova App Registry contract to fetch app info
3. Frontend connects to `appUrl` and establishes ECDH key exchange
4. Frontend verifies the enclave's public key matches `teePubkey` from registry
5. All subsequent communication is encrypted with AES-GCM

**Registry Contract (Base Sepolia):** `0x58e41D71606410E43BDA23C348B68F5A93245461`

#### 5.2 Direct URL
Connect directly to an enclave URL without registry verification. Use this for:
- Development and testing with unregistered enclaves
- Self-hosted deployments where you manage your own trust

**How it works:**
1. User enters the enclave URL directly
2. Frontend fetches attestation from `/.well-known/attestation`
3. User should independently verify PCR values (PCR0, PCR1, PCR2)
4. ECDH key exchange establishes encrypted channel

> **Security Note**: When using Direct URL, you are responsible for verifying the PCR values against a trusted source. For production use, we recommend the Registry-based approach.

- **Related Code**: [enclave/routes.py](enclave/routes.py), [frontend/src/lib/crypto.ts](frontend/src/lib/crypto.ts), [frontend/src/lib/registry.ts](frontend/src/lib/registry.ts)

### 6) Modern Developer Stack
A complete foundation for rapid development.
- **Next.js Frontend**: A modern UI for interacting with storage, oracles, and encrypted APIs.
- **Mock Environment**: Develop locally without a TEE using `IN_ENCLAVE=false` and `odyn.py` (Mock mode).
- **Related Code**: [/frontend](/frontend), [enclave/odyn.py](enclave/odyn.py)

---

## Quick Start

### Local Development (Mock)
```bash
# Start frontend dev server (port 3000)
make dev-frontend

# Build & Copy frontend to enclave
make build-frontend

# Start backend locally (port 8000, mock mode)
make dev-backend
```

Default endpoints:
- API: http://localhost:8000
- Attestation: http://localhost:8000/.well-known/attestation
- UI: http://localhost:8000/frontend/ (trailing slash required)

### Build & Run (Docker)
```bash
# Build a standard Docker image
make build-docker

# Run the container locally (mock mode)
docker run -p 8000:8000 -e IN_ENCLAVE=false nova-app-template:latest
```


### Deploy to Nova
1. Create an App in the Nova Console
2. Set App Listening Port = 8000
3. Configure the contract address (NovaAppBase/ETHPriceOracleApp or your custom contract)
4. The platform injects S3 / Egress / TLS configuration at runtime

For this template, the app contract address is configured in [enclave/config.py](enclave/config.py).

---

## Environment Variables

Note: Per template configuration, on-chain settings are read from [enclave/config.py](enclave/config.py) (static constants), not from environment variables.

| Variable | Default | Description |
|------|--------|------|
| `IN_ENCLAVE` | false | Run inside a real enclave |

| `CORS_ORIGINS` | * | Allowed CORS origins (comma-separated or *) |
| `CORS_ALLOW_CREDENTIALS` | true | Allow cross-origin credentials |

---

## API Reference

### Identity & Encryption (Pillar 1 & 5)
| Endpoint | Method | Description |
|----------|--------|------|
| `/.well-known/attestation` | POST | Public Attestation (raw CBOR) |
| `/api/attestation` | GET | Base64-encoded attestation document |
| `/api/echo` | POST | Supports both encrypted and plain payloads |
| `/api/encryption/public-key` | GET | Enclave's P-384 public key |

### Storage & State (Pillar 2)
| Endpoint | Method | Description |
|----------|--------|------|
| `/api/storage` | POST/GET | S3 read/write + optional on-chain anchoring |
| `/api/storage/{key}` | GET/DELETE | Direct access to S3 keys |
| `/api/contract/update-state` | POST | Manually sign a state hash update transaction |

### Oracle & Events (Pillar 4)
| Endpoint | Method | Description |
|----------|--------|------|
| `/api/oracle/update-now` | POST | Manual trigger for ETH/USD fetch and on-chain update |
| `/api/events/oracle` | GET | View logs of contract events handled by the enclave |
| `/api/event-monitor/status` | GET | Status of the background polling tasks |

### System
| Endpoint | Method | Description |
|----------|--------|------|
| `/status` | GET | TEE health and basic environment info |
| `/api/random` | GET | Generate random bytes using NSM hardware RNG |

---

## Contracts

`NovaAppBase` provides:
- `setNovaRegistry(address)`
- `registerTEEWallet(address)`

`ETHPriceOracleApp` provides:
- `stateHash` (public getter for off-chain verification)
- `updateStateHash(bytes32)` (TEE updates after S3 save)
- `ETHUsdPrice` (public getter)
- `requestETHPriceUpdate()` (manual trigger)
- `ETHPriceUpdated` (event)

`registerTEEWallet` is called by the Nova Registry after `setNovaRegistry` is configured.

If you need custom logic:
- Inherit from `NovaAppBase`
- Add your own events and functions

This template also includes `ETHPriceOracleApp`, which adds an on-chain ETH/USD price and request/update events consumed by the enclave oracle endpoints.

### Nova App Contract Deployment Flow
1. Deploy the app contract (must extend [contracts/src/ISparsityApp.sol](contracts/src/ISparsityApp.sol))
2. Verify the contract on Base Sepolia
3. Call `setNovaRegistry` to set the Nova Registry contract address
4. Create the app on the Nova platform with the contract address
5. ZKP Registration Service generates proofs and registers/verifies the app in the Nova Registry
6. Nova Registry calls `registerTEEWallet` on your app contract

---

## FAQ

**Q: How is the enclave connection verified?**
A: The frontend parses the attestation document and verifies PCRs/public key.

**Q: How are transaction nonces fetched?**
A: The template reads nonce and gas via JSON-RPC.

**Q: What do I need for cross-origin frontend access?**
A: The default allows any origin (`CORS_ORIGINS=*`). If you need credentials (cookie/Authorization), set `CORS_ORIGINS` to an explicit allowlist and keep `CORS_ALLOW_CREDENTIALS=true`. See [enclave/app.py](enclave/app.py).

---

## References
- Helios Trustless RPC: https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/helios_rpc.md
- Odyn Internal API: https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/odyn.md
- Internal API Reference: https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api.md
- Mockup Service: https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api_mockup.md
