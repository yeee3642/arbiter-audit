# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary recipient code during `transfer`, `send`, or `operatorSend`. If a contract performs sensitive state updates (accounting, flow limits, rental cleanup, command execution marking) *after* an external call that can transfer ERC777 tokens, a malicious recipient can re-enter the same or a related function and observe stale state. This violates the Checks-Effects-Interactions pattern. The vulnerability manifests in three ways: (1) Accounting updates like `_addFlowIn` occur after `_giveToken`/`_transferFromExecutor`/`safeTransferFrom`, letting the callback manipulate balances before the ledger records them. (2) External calls such as `_executeWithToken`, `ESCRW.settlePayment`, or hook invocations (`IHook.onStop`) happen before critical cleanup (`STORE.removeRentals`, `_setExpressExecutorWithToken`), so a revert in the callback permanently locks assets or allows double-execution. (3) Missing `nonReentrant` guards on virtual/external entry points (`expressExecuteWithToken`, `_executeWithToken`) enable cross-function reentrancy where the callback re-enters a payout function and drains funds. Auditors must trace every external call that can move ERC777 tokens (including `safeTransferFrom`, `_safeTransfer`, low-level `call`, and virtual functions) and verify all state mutations precede them.

### Detection Checks

1. External call that can transfer ERC777 tokens (safeTransferFrom, _safeTransfer, _giveToken, _transferFromExecutor, contractCallWithTokenValue, IHook.onStop, settlePayment) appears before state updates that record the transfer (accounting, flow limits, rental removal, command execution marking).
2. State variable or storage mapping updated after an external call that may trigger tokensReceived/tokensToSend (e.g., _addFlowIn, STORE.removeRentals, _setExpressExecutorWithToken, gateway.isCommandExecuted write).
3. Virtual or external function lacking nonReentrant modifier that performs token transfers before internal accounting (_executeWithToken called after transfers but before executor recording).
4. Revert in external callback (tokensReceived, onStop) can prevent subsequent cleanup/state finalization (STORE.removeRentals, _emitRentalOrderStopped) because the cleanup is placed after the external call.
5. Hook enablement check (STORE.hookOnStop) reads mutable state that can change between rental creation and stop, causing revert on cleanup path; no immutable hook registry or disable-after-use pattern.
6. Cross-function reentrancy: token transfer from executor to contract (safeTransferFrom) occurs before marking command executed (_setExpressExecutorWithToken), allowing callback to re-enter expressExecuteWithToken for same commandId.
7. Use of try/catch on external hook calls (IHook.onStop) without guaranteeing post-hook state finalization; catch block reverts but cleanup (removeRentals) is after the hook loop.
8. Flow limit or balance accounting (_addFlowIn) uses return value of external transfer (_giveToken) that can be manipulated by reentrant callback before accounting runs.

### Examples

#### Example 1: Incorrect Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService returns (uint256) {
    amount = _giveToken(destinationAddress, amount); // may trigger ERC777 tokensReceived
    _addFlowIn(amount); // accounting after external call
    return amount;
}

function expressExecuteWithToken(bytes32 commandId, string calldata sourceChain, string calldata sourceAddress, bytes calldata payload, string calldata symbol, uint256 amount) external payable virtual {
    if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();
    address expressExecutor = msg.sender;
    (address tokenAddress, uint256 value) = contractCallWithTokenValue(sourceChain, sourceAddress, payload, symbol, amount);
    _transferFromExecutor(expressExecutor, tokenAddress, value); // external transfer
    address gatewayToken = gateway.tokenAddresses(symbol);
    IERC20(gatewayToken).safeTransferFrom(expressExecutor, address(this), amount); // another external transfer
    _setExpressExecutorWithToken(commandId, sourceChain, sourceAddress, keccak256(payload), symbol, amount, expressExecutor); // marking after transfers
    _executeWithToken(sourceChain, sourceAddress, payload, symbol, amount); // virtual call after transfers
    emit ExpressExecutedWithToken(commandId, sourceChain, sourceAddress, keccak256(payload), symbol, amount, expressExecutor);
}

function stopRent(RentalOrder calldata order) external {
    _validateRentalCanBeStoped(order.orderType, order.endTimestamp, order.lender);
    bytes memory rentalAssetUpdates = new bytes(0);
    for (uint256 i; i < order.items.length; ++i) {
        if (order.items[i].isRental()) {
            _insert(rentalAssetUpdates, order.items[i].toRentalId(order.rentalWallet), order.items[i].amount);
        }
    }
    if (order.hooks.length > 0) {
        _removeHooks(order.hooks, order.items, order.rentalWallet); // external hook calls
    }
    _reclaimRentedItems(order);
    ESCRW.settlePayment(order); // ERC777 transfer before cleanup
    STORE.removeRentals(_deriveRentalOrderHash(order), _convertToStatic(rentalAssetUpdates)); // cleanup after external call
    _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
}
```

All three functions violate CEI: giveToken updates flow accounting after _giveToken; expressExecuteWithToken transfers tokens before marking command executed and calls unprotected virtual _executeWithToken; stopRent calls ESCRW.settlePayment (ERC777 transfer) and hooks before STORE.removeRentals, allowing callback revert to lock assets.

#### Example 2: Correct Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService nonReentrant returns (uint256) {
    _addFlowIn(amount); // accounting first
    amount = _giveToken(destinationAddress, amount); // then external transfer
    return amount;
}

expressExecuteWithToken(bytes32 commandId, string calldata sourceChain, string calldata sourceAddress, bytes calldata payload, string calldata symbol, uint256 amount) external payable nonReentrant {
    if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();
    address expressExecutor = msg.sender;
    _setExpressExecutorWithToken(commandId, sourceChain, sourceAddress, keccak256(payload), symbol, amount, expressExecutor); // mark executed first
    (address tokenAddress, uint256 value) = contractCallWithTokenValue(sourceChain, sourceAddress, payload, symbol, amount);
    _transferFromExecutor(expressExecutor, tokenAddress, value);
    address gatewayToken = gateway.tokenAddresses(symbol);
    IERC20(gatewayToken).safeTransferFrom(expressExecutor, address(this), amount);
    _executeWithToken(sourceChain, sourceAddress, payload, symbol, amount);
    emit ExpressExecutedWithToken(commandId, sourceChain, sourceAddress, keccak256(payload), symbol, amount, expressExecutor);
}

function stopRent(RentalOrder calldata order) external nonReentrant {
    _validateRentalCanBeStoped(order.orderType, order.endTimestamp, order.lender);
    bytes memory rentalAssetUpdates = new bytes(0);
    for (uint256 i; i < order.items.length; ++i) {
        if (order.items[i].isRental()) {
            _insert(rentalAssetUpdates, order.items[i].toRentalId(order.rentalWallet), order.items[i].amount);
        }
    }
    STORE.removeRentals(_deriveRentalOrderHash(order), _convertToStatic(rentalAssetUpdates)); // cleanup first
    if (order.hooks.length > 0) {
        _removeHooks(order.hooks, order.items, order.rentalWallet);
    }
    _reclaimRentedItems(order);
    ESCRW.settlePayment(order); // transfers after cleanup
    _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
}
```

Reordered to follow CEI: state updates (accounting, command marking, rental removal) occur before any external call that can trigger ERC777 hooks. Added nonReentrant to entry points. Cleanup (removeRentals) now precedes ESCRW.settlePayment and hook calls.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
