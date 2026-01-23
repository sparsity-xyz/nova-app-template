## Nova App Contract Deployment Flow

To work with the Nova Registry, your app contract must implement
`ISparsityApp` and expose `setNovaRegistry(address)` and `registerTEEWallet(address)`.

Recommended flow (Foundry-based):

1. **Deploy the app contract** (must extend [src/ISparsityApp.sol](src/ISparsityApp.sol)).
2. **Verify the contract** on Base Sepolia (or your target chain).
3. **Set the Nova Registry address** by calling `setNovaRegistry(address)` on your app contract.
4. **Create the app on Nova Platform** and provide the app contract address.
5. **ZKP Registration Service** generates proofs and registers/verifies the app in the Nova Registry.
6. **Nova Registry** calls `registerTEEWallet` on your app contract.

Notes:
- `registerTEEWallet` is **registry-only** in the template base contract.
- Registry address must be set before registration can succeed.

This template now includes an oracle demo contract:
- `ETHPriceOracleApp` ([src/ETHPriceOracleApp.sol](src/ETHPriceOracleApp.sol))
	- Stores `ethUsdPrice` and emits request/update events
	- The enclave updates the price on-chain periodically, via API, or when it sees a request event

### Step 1: Deploy the App Contract

Install dependencies and run a quick sanity check before deploying (you must install `forge-std` explicitly):

```shell
cd nova-app-template/contracts
forge install foundry-rs/forge-std
forge build
forge test
```

Then deploy using the included Foundry script:

```shell
export RPC_URL=https://sepolia.base.org
export PRIVATE_KEY=<your_private_key>

# Deploy ETHPriceOracleApp (recommended)
forge script script/Deploy.s.sol:DeployScript \
	--rpc-url "$RPC_URL" \
	--private-key "$PRIVATE_KEY" \
	--broadcast
```

Save the deployed contract address from the output as `APP_CONTRACT` for the next steps.

### Step 2: Verify the Contract (Base Sepolia)

If you use Base Sepolia, you can verify with Etherscan-style APIs.
You will need an API key and the deployed address:

```shell
export APP_CONTRACT=<deployed_contract_address>
export ETHERSCAN_API_KEY=<your_etherscan_or_basescan_key>

# Example for Base Sepolia (chain-id 84532)
forge verify-contract \
	--chain-id 84532 \
	--watch \
	--etherscan-api-key "$ETHERSCAN_API_KEY" \
	"$APP_CONTRACT" \
	src/ETHPriceOracleApp.sol:ETHPriceOracleApp
```

If your chain uses a different explorer, pass `--verifier-url` and `--verifier` as needed.

### Step 3: Set the Nova Registry Address

Call `setNovaRegistry(address)` on the deployed contract:

```shell
export NOVA_REGISTRY=<nova_registry_contract_address>

cast send "$APP_CONTRACT" \
	"setNovaRegistry(address)" \
	"$NOVA_REGISTRY" \
	--rpc-url "$RPC_URL" \
	--private-key "$PRIVATE_KEY"

---

## Wire the Contract into the Enclave

The enclave uses a static config file (no environment variables). After deploying, set the address here:

- [../enclave/config.py](../enclave/config.py)
  - `CONTRACT_ADDRESS = "0x..."`
  - Optionally adjust `RPC_URL`, `CHAIN_ID`, `BROADCAST_TX`

If `BROADCAST_TX = False`, the enclave will return raw signed transactions.
If `BROADCAST_TX = True`, the enclave will attempt to broadcast transactions via `RPC_URL`.

---

## Trigger an On-Chain Update Request (Manual)

Anyone can request a price update by emitting an event on-chain:

```shell
cast send "$APP_CONTRACT" \
	"requestEthPriceUpdate()" \
	--rpc-url "$RPC_URL" \
	--private-key "$PRIVATE_KEY"
```

The enclave's event monitor will detect `EthPriceUpdateRequested` and respond by submitting `updateEthPrice(...)`.
```
