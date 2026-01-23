// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./ISparsityApp.sol";

/**
 * @title NovaAppBase
 * @dev Base contract for Nova TEE applications with registry and TEE wallet wiring.
 *
 * It implements ISparsityApp so the Nova Registry can register the TEE wallet.
 * App-specific logic (e.g., state hashing) lives in derived contracts.
 */
contract NovaAppBase is ISparsityApp {
    /// @notice The TEE wallet address (from Odyn /v1/eth/address)
    address public teeWalletAddress;

    /// @notice Nova Registry contract authorized to register the TEE wallet
    address public novaRegistry;

    /// @notice Contract owner for administrative functions
    address public owner;

    /// @notice Emitted when TEE wallet is registered
    event TEEWalletRegistered(address indexed wallet);

    /// @notice Emitted when Nova Registry is set
    event NovaRegistrySet(address indexed registry);

    /// @notice Emitted when ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "NovaAppBase: caller is not the owner");
        _;
    }

    modifier onlyTEE() {
        require(
            msg.sender == teeWalletAddress,
            "NovaAppBase: caller is not the TEE"
        );
        _;
    }

    modifier onlyRegistry() {
        require(msg.sender == novaRegistry, "NovaAppBase: caller is not registry");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Set the Nova Registry contract address
     * @param _registry The Nova Registry contract address
     * @dev Can only be set once
     */
    function setNovaRegistry(address _registry) external override onlyOwner {
        require(_registry != address(0), "NovaAppBase: invalid registry");
        require(novaRegistry == address(0), "NovaAppBase: registry already set");
        novaRegistry = _registry;
        emit NovaRegistrySet(_registry);
    }

    /**
     * @notice Register the TEE wallet address
     * @param teeWalletAddress_ The Ethereum address from the TEE's Odyn API
     * @dev Can only be called once by the Nova Registry
     */
    function registerTEEWallet(address teeWalletAddress_) external override onlyRegistry {
        require(
            teeWalletAddress == address(0),
            "NovaAppBase: TEE wallet already registered"
        );
        require(teeWalletAddress_ != address(0), "NovaAppBase: invalid TEE wallet");

        teeWalletAddress = teeWalletAddress_;
        emit TEEWalletRegistered(teeWalletAddress_);
    }

    /**
     * @notice Transfer ownership to a new address
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "NovaAppBase: new owner is zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
