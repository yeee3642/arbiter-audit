# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary recipient code during `transfer`, `send`, or `operatorSend` calls. If a contract performs sensitive state updates (accounting, flow limits, rental cleanup, command execution markers) *after* the external token transfer, a malicious recipient can re-enter the same or a related function and observe stale state. This violates the Checks-Effects-Interactions pattern. Common manifestations: (1) transferring tokens before recording the transfer in internal accounting (`_addFlowIn`, `removeRentals`, `isCommandExecuted` flag), enabling double-spend or double-payout; (2) calling an unprotected virtual/external function after token transfers, allowing reentrant execution that repeats payouts; (3) settling payments via `safeTransfer`/`_safeTransfer` before removing rental records, letting a renter revert in `tokensReceived` and permanently lock lender assets; (4) validating hook enablement (`hookOnStop`) at call time rather than at registration, so a governance disable after rental creation causes `stopRent` to revert and lock funds. The fix is to complete all state changes (effects) before any external call (interaction), guard reentrant entry points with `nonReentrant`, and ensure hook enablement is immutable for the lifetime of the rental/command.

### Detection Checks

1. Token transfer (ERC20 `transfer`/`safeTransfer`, ERC777 `send`/`operatorSend`, or internal `_giveToken`/`_transferFromExecutor`/`_reclaimRentedItems`/`settlePayment`) occurs before critical state updates such as flow accounting (`_addFlowIn`), rental removal (`STORE.removeRentals`), command execution marking (`_setExpressExecutorWithToken`/`isCommandExecuted`), or hook deregistration.
2. An unprotected `virtual`/`external` function (`_executeWithToken`, `onStop`, arbitrary hook call) is invoked after token transfers without a `nonReentrant` modifier on the entry point, allowing cross-function reentrancy that repeats payouts or logic.
3. External calls to hook targets (`IHook(target).onStop`, `tokensReceived`/`tokensToSend` via ERC777 transfer) are made while mutable state (rental records, command execution flags, flow limits) still reflects the pre-transfer condition, enabling the callee to re-enter and exploit stale state.
4. Hook enablement (`STORE.hookOnStop`) is checked at execution time rather than at registration time, so a post-creation governance disable causes the cleanup function (`stopRent`/`_removeHooks`) to revert and lock assets.
5. Reentrancy guard (`nonReentrant` from `ReentrancyGuard` or equivalent) is missing on the public/external entry function that performs token transfers followed by state changes or external calls.
6. The function uses `try/catch` around hook calls but does not guarantee state cleanup (e.g., `removeRentals`) occurs even if the hook reverts, allowing a malicious hook to block cleanup permanently.
7. Token transfers are performed inside a scoped block `{ ... }` but the subsequent state update is outside that block, visually separating the interaction from the effect and violating CEI ordering.
8. The contract calls `safeTransferFrom`/`_safeTransfer` on a token address that may implement ERC777 (detected via `IERC777`/`IERC777Sender`/`IERC777Recipient` imports or `tokensReceived`/`tokensToSend` interface usage) before updating the corresponding storage slots.

### Examples

#### Example 1: Incorrect Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService returns (uint256) {
    amount = _giveToken(destinationAddress, amount); // ERC777 send -> tokensReceived callback
    _addFlowIn(amount); // accounting after transfer
    return amount;
}

function expressExecuteWithToken(bytes32 commandId, string calldata sourceChain, string calldata sourceAddress, bytes calldata payload, string calldata symbol, uint256 amount) external payable virtual {
    if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();
    address expressExecutor = msg.sender;
    (address tokenAddress, uint256 value) = contractCallWithTokenValue(sourceChain, sourceAddress, payload, symbol, amount);
    _transferFromExecutor(expressExecutor, tokenAddress, value); // transfer before effects
    address gatewayToken = gateway.tokenAddresses(symbol);
    IERC20(gatewayToken).safeTransferFrom(expressExecutor, address(this), amount); // second transfer
    _setExpressExecutorWithToken(commandId, sourceChain, sourceAddress, keccak256(payload), symbol, amount, expressExecutor);
    _executeWithToken(sourceChain, sourceAddress, payload, symbol, amount); // unprotected virtual call
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
        _removeHooks(order.hooks, order.items, order.rentalWallet);
    }
    _reclaimRentedItems(order);
    ESCRW.settlePayment(order); // ERC777 transfer before rental removal
    STORE.removeRentals(_deriveRentalOrderHash(order), _convertToStatic(rentalAssetUpdates));
    _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
}

function _removeHooks(Hook[] calldata hooks, Item[] calldata rentalItems, address rentalWallet) internal {
    for (uint256 i = 0; i < hooks.length; ++i) {
        address target = hooks[i].target;
        if (!STORE.hookOnStop(target)) revert Errors.Shared_DisabledHook(target); // runtime check
        uint256 itemIndex = hooks[i].itemIndex;
        Item memory item = rentalItems[itemIndex];
        if (!item.isRental()) revert Errors.Shared_NonRentalHookItem(itemIndex);
        try IHook(target).onStop(rentalWallet, item.token, item.identifier, item.amount, hooks[i].extraData) {} catch Error(string memory r) { revert Errors.Shared_HookFailString(r); } catch Panic(uint256 c) { revert Errors.Shared_HookFailString(string.concat("Hook reverted: Panic code ", LibString.toString(c))); } catch (bytes memory d) { revert Errors.Shared_HookFailBytes(d); }
    }
}
```

Transfers tokens via `_giveToken`/`_transferFromExecutor`/`safeTransferFrom`/`settlePayment` before updating accounting (`_addFlowIn`), marking commands executed (`_setExpressExecutorWithToken`), or removing rentals (`STORE.removeRentals`). Calls unprotected virtual `_executeWithToken` after transfers. Checks hook enablement at runtime (`STORE.hookOnStop`) instead of registration time. No `nonReentrant` guard on entry points.

#### Example 2: Correct Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService nonReentrant returns (uint256) {
    _addFlowIn(amount); // effect first
    amount = _giveToken(destinationAddress, amount); // interaction last
    return amount;
}

function expressExecuteWithToken(bytes32 commandId, string calldata sourceChain, string calldata sourceAddress, bytes calldata payload, string calldata symbol, uint256 amount) external payable nonReentrant {
    if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();
    address expressExecutor = msg.sender;
    (address tokenAddress, uint256 value) = contractCallWithTokenValue(sourceChain, sourceAddress, payload, symbol, amount);
    _transferFromExecutor(expressExecutor, tokenAddress, value);
    address gatewayToken = gateway.tokenAddresses(symbol);
    IERC20(gatewayToken).safeTransferFrom(expressExecutor, address(this), amount);
    _setExpressExecutorWithToken(commandId, sourceChain, sourceAddress, keccak256(payload), symbol, amount, expressExecutor);
    // command marked executed before external call
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
    // remove rentals BEFORE any external transfers/hook calls
    STORE.removeRentals(_deriveRentalOrderHash(order), _convertToStatic(rentalAssetUpdates));
    if (order.hooks.length > 0) {
        _removeHooks(order.hooks, order.items, order.rentalWallet);
    }
    _reclaimRentedItems(order);
    ESCRW.settlePayment(order);
    _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
}

function _removeHooks(Hook[] calldata hooks, Item[] calldata rentalItems, address rentalWallet) internal {
    for (uint256 i = 0; i < hooks.length; ++i) {
        address target = hooks[i].target;
        // hook enablement verified at registration; no runtime check needed
        uint256 itemIndex = hooks[i].itemIndex;
        Item memory item = rentalItems[itemIndex];
        if (!item.isRental()) revert Errors.Shared_NonRentalHookItem(itemIndex);
        try IHook(target).onStop(rentalWallet, item.token, item.identifier, item.amount, hooks[i].extraData) {} catch Error(string memory r) { revert Errors.Shared_HookFailString(r); } catch Panic(uint256 c) { revert Errors.Shared_HookFailString(string.concat("Hook reverted: Panic code ", LibString.toString(c))); } catch (bytes memory d) { revert Errors.Shared_HookFailBytes(d); }
    }
}
```

All state updates (`_addFlowIn`, `_setExpressExecutorWithToken`, `STORE.removeRentals`) occur before any external token transfer or hook call. Entry points protected with `nonReentrant`. Hook enablement assumed immutable after registration; runtime check removed. Cleanup (`removeRentals`) precedes `settlePayment` and hook calls.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
