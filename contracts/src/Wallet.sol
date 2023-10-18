// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol"; //BaseAccount: This represents the basic account implementation for a smart contract wallet
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol"; //UserOperation:  This is a struct for representing a UserOperation
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol"; //ECDSA: This is used to validate signatures through the ECDSA library
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol"; //This contract provides us with modifiers like initializer that ensure certain initialization functions only run once.
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol"; //The UUPSUpgradeable contract allows for upgradeability
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol"; //TokenCallbackHandler enables handling of various token types.

contract Wallet is
    BaseAccount,
    Initializable,
    UUPSUpgradeable,
    TokenCallbackHandler
{
    using ECDSA for bytes32; //this would allow all bytes32 variables to use the functions in ECDSA - which we can then use to validate signatures as they're passed in as bytes32 values.
    address[] public owners;

    address public immutable walletFactory;
    IEntryPoint private immutable _entryPoint;

    event WalletInitialized(IEntryPoint indexed entryPoint, address[] owners);

    modifier _requireFromEntryPointOrFactory() {
        require(
            msg.sender == address(_entryPoint) || msg.sender == walletFactory,
            "only entry point or wallet factory can call"
        );
        _;
    }

    constructor(IEntryPoint anEntryPoint, address ourWalletFactory) {
        _entryPoint = anEntryPoint;
        walletFactory = ourWalletFactory;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _validateSignature(
        UserOperation calldata userOp, // UserOperation data structure passed as input
        bytes32 userOpHash // Hash of the UserOperation without the signatures
    ) internal view override returns (uint256) {
        // Convert the userOpHash to an Ethereum Signed Message Hash
        bytes32 hash = userOpHash.toEthSignedMessageHash();

        // Decode the signatures from the userOp and store them in a bytes array in memory
        bytes[] memory signatures = abi.decode(userOp.signature, (bytes[]));

        // Loop through all the owners of the wallet
        for (uint256 i = 0; i < owners.length; i++) {
            // Recover the signer's address from each signature
            // If the recovered address doesn't match the owner's address, return SIG_VALIDATION_FAILED
            if (owners[i] != hash.recover(signatures[i])) {
                return SIG_VALIDATION_FAILED;
            }
        }
        // If all signatures are valid (i.e., they all belong to the owners), return 0
        return 0;
    }

    function initialize(address[] memory initialOwners) public initializer {
        _initialize(initialOwners);
    }

    function _initialize(address[] memory initialOwners) internal {
        require(initialOwners.length > 0, "no owners");
        owners = initialOwners;
        emit WalletInitialized(_entryPoint, initialOwners);
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                // The assembly code here skips the first 32 bytes of the result, which contains the length of data.
                // It then loads the actual error message using mload and calls revert with this error message.
                revert(add(result, 32), mload(result))
            }
        }
    }

    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external _requireFromEntryPointOrFactory {
        _call(dest, value, func);
    }

    //The main difference between execute and executeBatch is that execute can only run one transaction, but executeBatch can run multiple transactions.
    function executeBatch(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external _requireFromEntryPointOrFactory {
        require(dests.length == funcs.length, "wrong dests lengths");
        require(values.length == funcs.length, "wrong values lengths");
        for (uint256 i = 0; i < dests.length; i++) {
            _call(dests[i], values[i], funcs[i]);
        }
    }

    function _authorizeUpgrade(
        address
    ) internal view override _requireFromEntryPointOrFactory {}
}
