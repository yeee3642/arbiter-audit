---
id: synth__upgradeable
name: "Upgradeable"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Upgradeable"]
routing_hints: ["initializer", "_authorizeUpgrade", "upgradeTo", "UUPSUpgradeable", "data.length", "diamondCut", "removeRentals"]
required_hints: []
prompt_chars: 7418
synthesized: true
gated: false
synth_provenance: {"train_findings": ["235", "480", "45", "477"], "localization_rate": 0.667, "mode": "s2", "hint_candidates": 30, "hints_rejected": 30, "hint_coverage": 1.0, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 0.6, "fp": 0.5, "folds": 5, "repaired": false}}
---

# Upgradeable

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Upgradeable**
Upgradeable contracts using proxy patterns (EIP-1967, EIP-2535 Diamond, UUPS, Transparent) introduce distinct failure modes. First, initialization must run exactly once on the implementation and never on the proxy; using chained initializers like `__Ownable_init()` instead of `__Ownable_init_unchained()` leaves storage slots (e.g., `owner`) uninitialized, causing `onlyOwner` checks to fail or default to address(0). Second, Diamond upgrades (`diamondCut`) require the executed calldata to match the previously proposed and timelocked payload; verifying only the hash of `facetCuts` and `initAddress` without binding the full calldata allows a privileged key to swap in arbitrary facet replacements after the notice period. Third, upgradeable contracts that forward calls to hooks or modules must follow checks-effects-interactions: external calls (hook removal, asset transfers, settlement) before state updates (`removeRentals`) enable reentrancy into the same or related functions. Fourth, guard policies that validate calldata must accept zero-length data for native ETH transfers; rejecting `data.length < 4` breaks payable fallback/receive paths and locks value in the contract.

### Detection Checks

1. In any `initialize` function marked with `initializer`, verify that all inherited upgradeable base contracts (OwnableUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable, etc.) are initialized via their `_unchained` variants (e.g., `__Ownable_init_unchained()`), not the chained `__Ownable_init()`.
2. In `executeDiamondCutProposal` or equivalent Diamond upgrade execution functions, confirm that the full `_diamondCut` calldata (including `facetCuts`, `initAddress`, and `initCalldata`) is hashed and compared against the stored proposal hash, not just a subset of fields.
3. In Diamond upgrade logic, ensure the proposal hash covers `initCalldata` in addition to `facetCuts` and `initAddress`; missing `initCalldata` in the hash permits malicious initialization logic injection.
4. In functions performing external calls to untrusted contracts (hooks, settlement, asset transfers), verify that all storage mutations (e.g., `removeRentals`, balance updates, state flags) occur before the external calls, adhering to checks-effects-interactions.
5. In guard/policy `checkTransaction` functions, ensure `data.length < 4` does not revert for payable paths; native ETH transfers have empty calldata and must be allowed when `value > 0`.
6. In upgrade authorization logic, confirm that only the designated admin/governor/timelock can invoke upgrade functions; look for missing `onlyOwner`, `onlyGovernor`, or role-based access control on `upgradeTo`, `upgradeToAndCall`, `diamondCut`, or `executeDiamondCutProposal`.
7. In UUPS/Transparent proxy implementations, verify that `proxiableUUID` returns the correct EIP-1967 implementation slot identifier and that `upgradeTo`/`upgradeToAndCall` validate the new implementation address is a contract.
8. In Diamond `diamondCut` calls, ensure `initCalldata` length is validated and that the `initAddress` is either address(0) or a contract with a valid `init` function selector, preventing arbitrary delegatecall to attacker-controlled addresses.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract VulnerableUpgradeable is Initializable, OwnableUpgradeable {
    function initialize() external initializer {
        __Ownable_init(); // @audit leaves owner = address(0)
    }

    function executeDiamondCutProposal(
        address[] calldata facetCuts,
        address initAddress,
        bytes calldata initCalldata
    ) external onlyOwner {
        bytes32 proposedHash = keccak256(abi.encode(facetCuts, initAddress)); // @audit missing initCalldata in hash
        require(proposedHash == s.proposedHash, "hash mismatch");
        // @audit no timelock/notice period enforcement
        IDiamondCut(address(this)).diamondCut(facetCuts, initAddress, initCalldata);
    }

    function stopRental(uint256 rentalId) external {
        // @audit CEI violation: external calls before state update
        IHook(s.hook).onRentalEnd(rentalId);
        IERC20(s.token).transfer(msg.sender, s.amounts[rentalId]);
        delete s.rentals[rentalId]; // state update after external calls
    }

    function checkTransaction(bytes calldata data) external {
        if (data.length < 4) revert("selector required"); // @audit blocks native ETH transfers
    }
}
```

Multiple upgradeable flaws: chained `__Ownable_init()` leaves owner uninitialized; diamond cut hash omits `initCalldata`; no timelock/notice period; CEI violation in `stopRental` with external calls before state deletion; `checkTransaction` rejects zero-length calldata for native ETH transfers.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

contract SecureUpgradeable is Initializable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    function initialize() external initializer {
        __Ownable_init_unchained(); // @audit correct unchained initializer
        __ReentrancyGuard_init_unchained();
    }

    function executeDiamondCutProposal(
        address[] calldata facetCuts,
        address initAddress,
        bytes calldata initCalldata
    ) external onlyOwner {
        bytes32 proposedHash = keccak256(abi.encode(facetCuts, initAddress, initCalldata)); // @audit includes initCalldata
        require(proposedHash == s.proposedHash, "hash mismatch");
        require(block.timestamp >= s.proposedTimestamp + NOTICE_PERIOD, "notice period");
        IDiamondCut(address(this)).diamondCut(facetCuts, initAddress, initCalldata);
    }

    function stopRental(uint256 rentalId) external nonReentrant {
        uint256 amount = s.amounts[rentalId];
        delete s.rentals[rentalId]; // @audit state update first (effects)
        delete s.amounts[rentalId];
        IHook(s.hook).onRentalEnd(rentalId); // then external calls (interactions)
        IERC20(s.token).transfer(msg.sender, amount);
    }

    function checkTransaction(uint256 value, bytes calldata data) external {
        if (data.length < 4 && value == 0) revert("selector required"); // @audit allows native ETH transfers
    }
}
```

Fixes all flaws: uses `_unchained` initializers; diamond cut hash includes `initCalldata` and enforces notice period; `stopRental` follows CEI with state updates before external calls; `checkTransaction` permits empty calldata when value > 0.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
