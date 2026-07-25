# Upgradeable

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Upgradeable**
Upgradeable contracts introduce a class of vulnerabilities centered on the transition between implementations. In proxy-based systems (Transparent, UUPS, Beacon, Diamond), the storage layout must remain identical across upgrades; adding, removing, or reordering state variables shifts slots and corrupts data. Initializers replace constructors and must be idempotent (guarded by `initializer` or `reinitializer` modifiers) and must invoke parent initializers via the `_unchained` variants (e.g., `__Ownable_init_unchained`) so that each base contract initializes its own storage exactly once. Diamond upgrades (`diamondCut`) require that the executed calldata matches the previously proposed and time-locked payload; verifying only the hash of the proposal without binding the calldata allows a privileged key to swap in arbitrary facet cuts after the notice period. External calls (hook removals, token transfers, settlement) must follow the Checks-Effects-Interactions pattern: state updates (`removeRentals`, slot writes) must precede low-level calls to prevent reentrancy into mutable functions. Finally, fallback/entry-point functions that validate calldata must accept zero-length data for native value transfers, otherwise plain ETH sends revert and break expected payable behavior.

### Detection Checks

1. Verify that every upgradeable contract uses a storage gap (e.g., `uint256[50] __gap;`) in base contracts and never reorders, deletes, or changes types of existing state variables.
2. Confirm that `initialize`/`reinitialize` functions are guarded by `initializer`/`reinitializer` modifiers and call parent initializers using `__<Base>_init_unchained()` rather than `__<Base>_init()`.
3. In Diamond `executeDiamondCutProposal` or equivalent, ensure the function compares the full `_diamondCut` calldata (or its hash) against the stored proposal, not just a partial hash of facet cuts and init address.
4. Check that any function performing external calls (hook removal, `safeTransfer`, `call`, `delegatecall`) updates all relevant storage (e.g., `removeRentals`, balance decrements, role revocations) before the external call.
5. Validate that fallback/receive/`checkTransaction` entry points do not revert on `data.length < 4`; they must allow empty calldata for plain ETH transfers.
6. Ensure upgrade authorization uses a timelock or multisig with a notice period, and that the timelock cannot be bypassed by a single compromised key (e.g., `onlyGovernor` without secondary approval).
7. Confirm that `diamondCut`/`upgradeToAndCall`/`setImplementation` functions are protected by `onlyOwner`/`onlyGovernor`/`onlyAdmin` and that the access control itself is initialized in the constructor/initializer (not left zero).
8. Verify that no `delegatecall` is forwarded to an untrusted or user-supplied implementation address without a whitelist or governance check.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract VulnerableUpgradeable is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public value;
    // Missing storage gap

    function initialize(uint256 _value) external initializer {
        __Ownable_init(); // Should be __Ownable_init_unchained()
        value = _value;
    }

    function upgrade(address newImpl, bytes calldata data) external onlyOwner {
        _upgradeToAndCallUUPS(newImpl, data, false);
    }

    // Diamond-style execute without calldata binding
    bytes32 public proposedHash;
    uint256 public proposedTime;
    function executeProposal(bytes calldata _data) external onlyOwner {
        require(block.timestamp >= proposedTime + 2 days, "notice");
        require(keccak256(_data) == proposedHash, "hash mismatch");
        // Missing: verify _data matches the originally proposed payload structure
        (bool ok, ) = address(this).delegatecall(_data);
        require(ok, "exec failed");
    }

    function unsafeExternalCall(address to, uint256 amount) external {
        // State update AFTER external call (CEI violation)
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "send failed");
        value -= amount; // Should be before the call
    }

    function checkTx(bytes calldata data) external {
        if (data.length < 4) revert("selector required"); // Reverts on plain ETH transfer
    }
}
```

The contract misses a storage gap, calls `__Ownable_init()` instead of `__Ownable_init_unchained()`, executes a diamond-style proposal without binding the full calldata, violates CEI by updating state after an external call, and rejects zero-length calldata breaking native ETH transfers.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract SecureUpgradeable is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public value;
    uint256[50] private __gap; // Storage gap for future upgrades

    function initialize(uint256 _value) external initializer {
        __Ownable_init_unchained(); // Correct unchained initializer
        value = _value;
    }

    function upgrade(address newImpl, bytes calldata data) external onlyOwner {
        _upgradeToAndCallUUPS(newImpl, data, false);
    }

    // Diamond-style execute with full calldata binding
    bytes32 public proposedHash;
    bytes public proposedCalldata;
    uint256 public proposedTime;
    function executeProposal(bytes calldata _data) external onlyOwner {
        require(block.timestamp >= proposedTime + 2 days, "notice");
        require(keccak256(_data) == proposedHash, "hash mismatch");
        require(_data == proposedCalldata, "calldata mismatch"); // Bind exact payload
        (bool ok, ) = address(this).delegatecall(_data);
        require(ok, "exec failed");
    }

    function safeExternalCall(address payable to, uint256 amount) external {
        value -= amount; // State update BEFORE external call (CEI)
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "send failed");
    }

    function checkTx(bytes calldata data) external {
        if (data.length >= 4) {
            // selector validation logic here
        }
        // Allows empty calldata for native transfers
    }
}
```

Adds a storage gap, uses `__Ownable_init_unchained()`, binds the exact proposed calldata in executeProposal, follows Checks-Effects-Interactions by updating state before the external call, and permits zero-length calldata for plain ETH transfers.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
