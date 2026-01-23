// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {NovaAppBase} from "./NovaAppBase.sol";

/**
 * @title ETHPriceOracleApp
 * @dev Example Nova app that stores an ETH/USD price updated by the TEE.
 *
 * Flow:
 *  - Any account can call requestEthPriceUpdate() to emit an on-chain request event.
 *  - The enclave listens for the request event and responds by submitting updateEthPrice(...).
 *  - The enclave may also update periodically or via an API-triggered update.
 */
contract ETHPriceOracleApp is NovaAppBase {
    /// @notice The keccak256 hash of the current encrypted state blob
    bytes32 public stateHash;

    /// @notice Block number when state was last updated
    uint256 public lastUpdatedBlock;

    /// @notice Latest ETH/USD price (integer USD, no decimals) written by the TEE
    uint256 public ethUsdPrice;

    /// @notice Timestamp (unix seconds) for the latest update
    uint256 public lastPriceUpdatedAt;

    /// @notice Monotonic request id counter
    uint256 public nextRequestId;

    /// @notice Emitted when a price update is requested
    event EthPriceUpdateRequested(uint256 indexed requestId, address indexed requester);

    /// @notice Emitted when the price is updated
    event EthPriceUpdated(
        uint256 indexed requestId,
        uint256 priceUsd,
        uint256 updatedAt,
        uint256 blockNumber
    );

    /// @notice Emitted when state hash is updated
    event StateUpdated(bytes32 indexed newHash, uint256 blockNumber);

    /**
     * @notice Emit an on-chain request for the enclave to update ETH/USD price.
     * @return requestId The request id for correlation.
     */
    function requestEthPriceUpdate() external returns (uint256 requestId) {
        requestId = ++nextRequestId;
        emit EthPriceUpdateRequested(requestId, msg.sender);
    }

    /**
     * @notice Update ETH/USD price (called by the registered TEE wallet).
     * @param requestId Correlation id (0 allowed for periodic/API-triggered updates).
     * @param priceUsd ETH/USD as integer USD.
     * @param updatedAt Unix seconds timestamp.
     */
    function updateEthPrice(uint256 requestId, uint256 priceUsd, uint256 updatedAt) external onlyTEE {
        require(priceUsd > 0, "ETHPriceOracleApp: invalid price");

        ethUsdPrice = priceUsd;
        lastPriceUpdatedAt = updatedAt;

        emit EthPriceUpdated(requestId, priceUsd, updatedAt, block.number);
    }

    /**
     * @notice Update the state hash (called by TEE after state save)
     * @param _newHash The keccak256 hash returned by Odyn's /v1/state/save
     */
    function updateStateHash(bytes32 _newHash) external onlyTEE {
        require(_newHash != bytes32(0), "ETHPriceOracleApp: invalid hash");

        stateHash = _newHash;
        lastUpdatedBlock = block.number;

        emit StateUpdated(_newHash, block.number);
    }

}
