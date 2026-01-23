// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface ISparsityApp {
    function setNovaRegistry(address registry) external;
    function registerTEEWallet(address teeWalletAddress) external;
}
