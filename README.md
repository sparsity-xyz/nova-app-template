# Nova App Template (Odyn Internal API)

This template targets the Nova platform for verifiable TEE applications and is aligned with the latest Odyn Internal API. It covers:

1. S3 read/write with state hash anchoring on-chain
2. Scheduled external data fetch and on-chain updates
3. On-chain event polling and response
4. Public APIs with RA-TLS encrypted communication
5. Frontend located in /frontend
6. A lightweight Odyn Mockup client (odyn.py)

---

## Structure

```
|-- enclave/               # FastAPI (TEE)
|   |-- app.py             # App entry
|   |-- routes.py          # API routes (business logic)
|   |-- tasks.py           # Scheduler tasks & event polling
|   |-- odyn.py            # Odyn SDK (latest internal API)
|   |-- chain.py           # On-chain helpers & tx signing
|   |-- requirements.txt
|-- contracts/             # Solidity contracts
|   |-- src/NovaAppBase.sol
|   |-- src/ETHPriceOracleApp.sol
|-- frontend/              # Next.js frontend
|-- enclaver.yaml          # Enclave config
|-- Makefile
```

---

## Core Capabilities

### 1) S3 Storage + Hash Anchoring
After writing to `/api/storage`, the app will:
- Update in-memory state
- Compute the full state hash (keccak256)
- Sign `updateStateHash(bytes32)` and optionally broadcast

Related code:
- [enclave/routes.py](enclave/routes.py)
- [enclave/chain.py](enclave/chain.py)
- [contracts/src/NovaAppBase.sol](contracts/src/NovaAppBase.sol)

### 2) Scheduled External Data → On-chain Update
`tasks.background_task()` runs every 5 minutes:
- Fetches external data (default example: ETH price)
- Saves to S3
- Computes state hash
- Signs `updateStateHash`

Related code:
- [enclave/tasks.py](enclave/tasks.py)

### 3) On-chain Event Listener → Response
The contract emits:
```
StateUpdateRequested(bytes32 requestedHash, address requester)
```
The enclave polls and responds by:
- Watching `StateUpdateRequested`
- Computing local state hash
- Signing `updateStateHash` (optional broadcast)

Related code:
- [enclave/tasks.py](enclave/tasks.py)
- [contracts/src/NovaAppBase.sol](contracts/src/NovaAppBase.sol)

### 4) Public APIs + RA-TLS
- `/.well-known/attestation`: public attestation endpoint (CBOR)
- `/api/echo`: encrypted payloads (ECDH + AES-GCM)
- `/api/encryption/*`: encrypt/decrypt helpers

RA-TLS flow in the frontend:
1. Fetch attestation
2. Verify PCR / public key
3. Derive ECDH shared secret
4. Send encrypted payloads

Related code:
- [enclave/routes.py](enclave/routes.py)
- [frontend/src/lib/crypto.ts](frontend/src/lib/crypto.ts)
- [frontend/src/lib/attestation.ts](frontend/src/lib/attestation.ts)

### 5) Frontend
Located in `/frontend`, includes:
- RA-TLS demo
- S3 storage demo
- Oracle demo
- Event polling status

### 6) Odyn Mockup Service
`odyn.py` switches endpoints based on `IN_ENCLAVE`:
- `IN_ENCLAVE=true` → http://localhost:18000
- `IN_ENCLAVE=false` → http://odyn.sparsity.cloud:18000

Mockup supports the latest Internal API:
- /v1/eth/address
- /v1/eth/sign / sign-tx
- /v1/attestation
- /v1/encryption/*
- /v1/s3/*

---

## Quick Start

### Local Development (Mock)
```bash
cd nova-app-template
make install-enclave
make install-frontend
make build-frontend

# Run FastAPI (mock mode)
cd enclave
python app.py
```

Default endpoints:
- API: http://localhost:8000
- Attestation: http://localhost:8000/.well-known/attestation
- UI: http://localhost:8000/frontend

### Deploy to Nova
1. Create an App in the Nova Console
2. Set App Listening Port = 8000
3. Configure the contract address (NovaAppBase/ETHPriceOracleApp or your custom contract)
4. The platform injects S3 / Egress / RA-TLS configuration at runtime

For this template, the app contract address is configured in [enclave/config.py](enclave/config.py).

---

## Environment Variables

Note: Per template configuration, on-chain settings are read from [enclave/config.py](enclave/config.py) (static constants), not from environment variables.

| Variable | Default | Description |
|------|--------|------|
| `IN_ENCLAVE` | false | Run inside a real enclave |
| `RPC_URL` | https://sepolia.base.org | Legacy (not read by enclave; use `enclave/config.py`) |
| `CHAIN_ID` | 84532 | Legacy (not read by enclave; use `enclave/config.py`) |
| `CONTRACT_ADDRESS` | (empty) | Legacy (not read by enclave; use `enclave/config.py`) |
| `APP_CONTRACT_ADDRESS` | (empty) | Legacy alias (not read by enclave; use `enclave/config.py`) |
| `BROADCAST_TX` | false | Legacy (not read by enclave; use `enclave/config.py`) |
| `ANCHOR_ON_WRITE` | true | Legacy (not read by enclave; use `enclave/config.py`) |
| `CORS_ORIGINS` | * | Allowed CORS origins (comma-separated or *) |
| `CORS_ALLOW_CREDENTIALS` | true | Allow cross-origin credentials |

---

## APIs

| Endpoint | Method | Description |
|----------|--------|------|
| `/.well-known/attestation` | POST | Raw CBOR attestation |
| `/api/attestation` | GET | Base64-encoded attestation |
| `/api/echo` | POST | Encrypted/plain echo |
| `/api/storage` | POST/GET | S3 read/write + hash anchoring |
| `/api/storage/{key}` | GET/DELETE | Single key access |
| `/api/oracle/update-now` | POST | Fetch ETH/USD and update on-chain price |
| `/api/events/oracle` | GET | Fetch oracle-related contract events (lookback) |
| `/api/oracle/price` | GET | Legacy alias of update-now |
| `/api/contract/update-state` | POST | Manual state hash update |
| `/status` | GET | TEE status |

---

## Contracts

`NovaAppBase` provides:
- `setNovaRegistry(address)`
- `registerTEEWallet(address)`

`ETHPriceOracleApp` provides:
- `stateHash` (public getter for off-chain verification)
- `updateStateHash(bytes32)` (TEE updates after S3 save)

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

**Q: Why does local S3 write fail?**
A: The mock service is not guaranteed to be persistent. On-chain signing is testable, but S3 requires a real enclave.

**Q: How is RA-TLS verified?**
A: The frontend parses the attestation document and verifies PCRs/public key.

**Q: How are transaction nonces fetched?**
A: The template reads nonce and gas via JSON-RPC.

**Q: What do I need for cross-origin frontend access?**
A: The default allows any origin (`CORS_ORIGINS=*`). If you need credentials (cookie/Authorization), set `CORS_ORIGINS` to an explicit allowlist and keep `CORS_ALLOW_CREDENTIALS=true`. See [enclave/app.py](enclave/app.py).

---

## References
- Odyn Internal API: https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/odyn.md
- Internal API Reference: https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api.md
- Mockup Service: https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api_mockup.md
