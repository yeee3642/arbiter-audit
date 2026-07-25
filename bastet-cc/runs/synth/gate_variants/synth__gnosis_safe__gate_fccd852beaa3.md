# Gnosis Safe Extension Missing Authorization Checks

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Gnosis Safe Extension Missing Authorization Checks**
Gnosis Safe extensions (Guards, Modules, and Fallback Handlers) integrate with the Safe core contract through well-defined interfaces. A Guard implements `IGuard.checkTransaction(address to, uint256 value, bytes data, Enum.Operation operation) returns (bool)` and is consulted before every transaction execution; if it returns `false` the transaction reverts. A Module implements `IModule.execTransactionFromModule(address to, uint256 value, bytes data, Enum.Operation operation) returns (bool)` and is called via `Safe.execTransactionFromModule`. A Fallback Handler implements `IFallbackHandler.handlePayment(address from, uint256 value, bytes data) returns (bool)` and receives ether or arbitrary calldata when the Safe receives a call that matches no other function. Vulnerabilities arise when these extension contracts omit authorization checks (e.g., only allowing the Safe itself or authorized signers to call configuration functions), fail to validate state transitions (e.g., enabling a guard without checking it is not already enabled, or disabling without ensuring the caller is the Safe), or mishandle reentrancy during callbacks. Because the Safe core trusts the extension's return value, a missing check can let an attacker bypass the multi-sig policy, drain funds, or permanently lock the Safe.

### Detection Checks

1. Guard.checkTransaction does not verify `msg.sender == address(safe)` before enforcing policy, allowing arbitrary callers to influence the return value.
2. Module.execTransactionFromModule lacks a `require(msg.sender == address(safe))` guard, so external callers can execute arbitrary transactions through the module.
3. FallbackHandler.handlePayment does not confirm `msg.sender == address(safe)` or validate `value`/`data`, enabling spoofed payment notifications.
4. Enable/disable module functions (e.g., `enableModule`, `disableModule` wrappers) miss `onlyOwner` or `onlySafe` modifiers, letting anyone add or remove extensions.
5. Guard configuration setters (e.g., `setGuard`, `configureGuard`) omit validation that the new guard address implements `IGuard` and is not the zero address.
6. State-changing functions in the extension do not follow checks-effects-interactions pattern, creating reentrancy risk when the Safe calls back into the extension.
7. Extension uses `delegatecall` or `call` to untrusted targets without restricting the calldata or verifying the target is an allowed contract.
8. Events for critical lifecycle changes (GuardChanged, ModuleEnabled, ModuleDisabled, FallbackHandlerChanged) are not emitted, breaking off-chain monitoring and invariant verification.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGuard {
    function checkTransaction(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bool);
}

contract VulnerableGuard is IGuard {
    address public immutable safe;
    bool public enabled;
    mapping(bytes4 => bool) public allowedSelectors;

    constructor(address _safe) { safe = _safe; }

    // @audit missing msg.sender == safe check
    function checkTransaction(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bool) {
        if (!enabled) return true;
        return allowedSelectors[bytes4(data[:4])];
    }

    // @audit no authorization, anyone can toggle the guard
    function setEnabled(bool _enabled) external {
        enabled = _enabled;
    }

    // @audit no validation of selector or zero address
    function allowSelector(bytes4 selector) external {
        allowedSelectors[selector] = true;
    }
}
```

The guard lacks `msg.sender == safe` checks in `checkTransaction`, `setEnabled`, and `allowSelector`, allowing any caller to bypass policy enforcement or reconfigure the guard.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGuard {
    function checkTransaction(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bool);
}

contract FixedGuard is IGuard {
    address public immutable safe;
    bool public enabled;
    mapping(bytes4 => bool) public allowedSelectors;

    constructor(address _safe) { safe = _safe; }

    modifier onlySafe() {
        require(msg.sender == safe, "GS01");
        _;
    }

    function checkTransaction(address to, uint256 value, bytes calldata data, uint8 operation) external onlySafe returns (bool) {
        if (!enabled) return true;
        return allowedSelectors[bytes4(data[:4])];
    }

    function setEnabled(bool _enabled) external onlySafe {
        enabled = _enabled;
    }

    function allowSelector(bytes4 selector) external onlySafe {
        require(selector != bytes4(0), "zero selector");
        allowedSelectors[selector] = true;
    }
}
```

All external entry points are protected with `onlySafe` modifier ensuring only the Safe contract can invoke them, and input validation prevents zero selectors.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
