// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Wallet} from "./Wallet.sol";

contract WalletFactory {
    Wallet public immutable walletImplementation;

    constructor(IEntryPoint entryPoint) {
        walletImplementation = new Wallet(entryPoint, address(this));
    }
}