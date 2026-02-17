# Contracts Guide (Nova App Template)

This folder contains example contracts for the template backend.

- `NovaAppBase.sol`: base app contract with registry wiring (`setNovaRegistry`, `registerTEEWallet`)
- `ETHPriceOracleApp.sol`: demo app with state hash + ETH price update workflow

## Quick build

```bash
cd app-template/contracts
forge install foundry-rs/forge-std
forge build
forge test
```

## Deploy example contract

```bash
export RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
export PRIVATE_KEY=<your_private_key>

forge script script/Deploy.s.sol:DeployScript \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --broadcast
```

## Verify (Ethereum mainnet)

```bash
export APP_CONTRACT=<deployed_contract_address>
export ETHERSCAN_API_KEY=<your_etherscan_api_key>

forge verify-contract \
  --chain-id 1 \
  --watch \
  --etherscan-api-key "$ETHERSCAN_API_KEY" \
  "$APP_CONTRACT" \
  src/ETHPriceOracleApp.sol:ETHPriceOracleApp
```

## Registry wiring note (dual-chain template)

Template defaults use:
- Auth chain (registry/KMS): Base Sepolia
- Business chain (contract logic): Ethereum mainnet

If your business contract enforces registry callbacks on the same chain, adjust deployment strategy accordingly.
At minimum, set the registry address your contract should trust:

```bash
export NOVA_REGISTRY=0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8

cast send "$APP_CONTRACT" \
  "setNovaRegistry(address)" \
  "$NOVA_REGISTRY" \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY"
```

Optional but recommended for app-wallet mode:

```bash
export APP_WALLET=<address_from_/api/app-wallet/address>

cast send "$APP_CONTRACT" \
  "setAppWalletAddress(address)" \
  "$APP_WALLET" \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY"
```

## Wire into template backend

Update `app-template/enclave/config.py`:

```python
CONTRACT_ADDRESS = "0x..."
BROADCAST_TX = False  # set True when you're ready to broadcast from enclave
```

The backend now prefers app-wallet signing for business transactions and falls back to TEE wallet signing when app-wallet is unavailable.
`ETHPriceOracleApp` accepts both signers (`onlyTEEOrAppWallet`) once app wallet is set.
