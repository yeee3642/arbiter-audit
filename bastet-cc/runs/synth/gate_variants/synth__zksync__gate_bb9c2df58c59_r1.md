# Zksync-ReentrancyViaPayableFallback

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Zksync-ReentrancyViaPayableFallback**
On ZKsync Era, the EVM compatibility layer does not enforce the 2,300 gas stipend for `transfer`/`send` or for plain `call{value: ...}` when the recipient is an EOA or a contract without a payable fallback. A malicious contract can implement a payable `fallback()` or `receive()` that consumes arbitrary gas and re-enters the caller. This breaks the common Ethereum assumption that a simple value transfer cannot trigger reentrancy. Vulnerable patterns include payable functions that forward `msg.value` via low-level `call` or `delegatecall` to untrusted targets without a reentrancy guard, and contracts that rely on `address.send`/`transfer` for access control or state changes after the transfer. The fix is to use a reentrancy guard (e.g., OpenZeppelin `ReentrancyGuard`) on any payable entry point that performs external calls with value, or to pull payments instead of pushing them.

### Detection Checks

1. Payable function executes a low-level `call{value: ...}` or `delegatecall` to a user-supplied or variable target address.
2. No reentrancy guard (e.g., `nonReentrant` modifier or manual lock) protects the external call.
3. State changes (balances, mappings, flags) occur after the external call instead of before (checks-effects-interactions violation).
4. Contract uses `address.send`/`transfer` to push ether and assumes the call cannot re-enter.
5. External call target is not validated against an allowlist or is derived from untrusted calldata.
6. Function lacks a `deadline`/`expiration` parameter for the action, allowing delayed execution that widens the reentrancy window.
7. Contract does not snapshot critical storage slots (e.g., slot 0) before a `delegatecall` to detect malicious storage writes.
8. Fallback/receive functions contain logic that modifies state or calls back into the contract.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableWallet {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // @audit payable function forwards value via low-level call without reentrancy guard
    function execute(address target, bytes calldata data) external payable {
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "call failed");
        // state change after external call
        balances[msg.sender] -= msg.value;
    }
    
    // @audit fallback allows reentrancy
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
```

The `execute` function is payable, forwards `msg.value` to an untrusted target via low-level `call`, and updates `balances` after the call. On ZKsync, the recipient's payable fallback can re-enter `execute` or `deposit` because no reentrancy guard exists and the 2,300 gas stipend is not enforced.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureWallet is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // @audit protected by nonReentrant; state updated before external call
    function execute(address target, bytes calldata data) external payable nonReentrant {
        uint256 amount = msg.value;
        balances[msg.sender] -= amount; // effects before interactions
        (bool success, ) = target.call{value: amount}(data);
        require(success, "call failed");
    }
    
    // @audit receive only updates state, no external calls
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
```

The `execute` function inherits `ReentrancyGuard`, applies the `nonReentrant` modifier, and updates `balances` before the external call (checks-effects-interactions). The `receive` hook only performs internal accounting.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
