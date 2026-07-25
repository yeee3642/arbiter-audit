# Upgradeable

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Upgradeable**
Upgradeable contracts introduce a class of vulnerabilities centered on the transition between implementations. In proxy patterns (EIP-1967, UUPS, Diamond), the proxy delegates calls to an implementation contract while retaining storage. If the new implementation's storage layout diverges (missing storage gaps, reordered variables, or changed types), state corruption occurs silently. Initialization is another critical vector: upgradeable contracts must use `initializer` modifiers instead of constructors, and parent initializers must be called with the `_unchained` suffix (e.g., `__Ownable_init_unchained()`) to avoid resetting state like `owner`. Diamond upgrades (EIP-2535) require validating that the executed `diamondCut` calldata exactly matches the previously proposed and time-locked payload; comparing only a hash of selected fields allows a privileged key holder to swap in arbitrary facet cuts after the notice period. Finally, any external calls (hook removals, token transfers, settlement) performed before updating storage violate the Checks-Effects-Interactions pattern and enable reentrancy into upgrade-sensitive functions.

### Detection Checks

1. Verify that every upgradeable contract uses `initializer`/`reinitializer` modifiers on initialization functions and never uses constructors for state setup.
2. Confirm that parent contract initializers are invoked with the `_unchained` suffix (e.g., `__Ownable_init_unchained()`) to prevent overwriting inherited state such as `owner`.
3. Ensure storage layout compatibility across upgrades: new state variables are only appended, storage gaps (`uint256[50] __gap`) are present in base contracts, and no variable is reordered, resized, or retyped.
4. In Diamond `executeDiamondCutProposal` or equivalent, check that the full `_diamondCut` calldata (including `facetCuts`, `initAddress`, and `initCalldata`) is hashed and compared against the stored proposal hash, not a partial hash of selected fields.
5. Validate that upgrade authorization enforces timelocks or multi-sig approvals and that the timelock cannot be bypassed by a single compromised key (e.g., `onlyGovernor` without delay).
6. Confirm that proxy admin / ownership transfer functions are protected by timelocks or require multi-step confirmation to prevent accidental or malicious transfer.
7. Check that all external calls (hook removals, `safeTransfer`, `settlePayment`, low-level `call`) occur *after* storage updates (e.g., `removeRentals`, state flag flips) to uphold Checks-Effects-Interactions.
8. Ensure fallback/receive functions in proxies do not inadvertently allow unauthorized delegatecalls or state mutations before the implementation is set.

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

    function initialize(uint256 _value) public initializer {
        __Ownable_init(); // BUG: should be __Ownable_init_unchained()
        value = _value;
    }

    function upgradeToAndCall(address newImplementation, bytes calldata data)
        external
        onlyOwner
    {
        _upgradeToAndCallUUPS(newImplementation, data, false);
    }

    // Diamond-style cut execution with partial hash validation
    bytes32 public proposedHash;
    uint256 public proposedTimestamp;
    
    function proposeCut(bytes32 _hash) external onlyOwner {
        proposedHash = _hash;
        proposedTimestamp = block.timestamp;
    }

    function executeCut(bytes calldata _cutData) external onlyOwner {
        require(block.timestamp >= proposedTimestamp + 2 days, "timelock");
        // BUG: only hashes _cutData, not the full structured payload
        require(keccak256(_cutData) == proposedHash, "hash mismatch");
        // delegatecall to diamondCut facet would go here
    }

    // CEI violation: external call before state update
    function withdraw() external {
        (bool sent, ) = payable(msg.sender).call{value: address(this).balance}("");
        // BUG: state update after external call
        value = 0;
    }
}
```

The contract uses `__Ownable_init()` instead of `__Ownable_init_unchained()`, leaving `owner` unset; lacks a storage gap risking layout collision on upgrade; validates only a raw bytes hash for diamond cuts instead of the full structured payload; and performs an external call before clearing `value`, enabling reentrancy.

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

    function initialize(uint256 _value) public initializer {
        __Ownable_init_unchained(); // Correct: preserves owner across upgrades
        value = _value;
    }

    function upgradeToAndCall(address newImplementation, bytes calldata data)
        external
        onlyOwner
    {
        _upgradeToAndCallUUPS(newImplementation, data, false);
    }

    // Diamond cut with full payload validation
    struct DiamondCutPayload {
        bytes32 facetCutsHash;
        address initAddress;
        bytes initCalldata;
    }
    DiamondCutPayload public proposedCut;
    uint256 public proposedTimestamp;
    
    function proposeCut(DiamondCutPayload calldata _payload) external onlyOwner {
        proposedCut = _payload;
        proposedTimestamp = block.timestamp;
    }

    function executeCut(DiamondCutPayload calldata _payload) external onlyOwner {
        require(block.timestamp >= proposedTimestamp + 2 days, "timelock");
        // Full structured hash validation
        require(keccak256(abi.encode(_payload)) == keccak256(abi.encode(proposedCut)), "payload mismatch");
        // diamondCut(_payload) would be called here
    }

    // CEI compliant: state update before external call
    function withdraw() external {
        uint256 amount = value;
        value = 0; // State update first
        (bool sent, ) = payable(msg.sender).call{value: amount}("");
        require(sent, "transfer failed");
    }
}
```

Uses `__Ownable_init_unchained()` to preserve ownership, includes a storage gap, validates the full diamond cut payload via structured encoding, and updates `value` to zero before the external call to prevent reentrancy.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
