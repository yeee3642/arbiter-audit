# Upgradeable

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Upgradeable**
Upgradeable contracts rely on proxy patterns (Transparent, UUPS, Diamond) where logic resides in an implementation contract while state lives in the proxy. The proxy delegates calls via `delegatecall`, so the implementation's storage layout must exactly match the proxy's; adding new state variables without reserved storage gaps shifts subsequent slots and corrupts data. Initialization replaces constructors: an `initialize()` function guarded by an `initializer` modifier (OpenZeppelin) or a manual `initialized` boolean must be called exactly once, otherwise the contract can be re-initialized by anyone. Upgrade authority is typically held by an `owner`, `admin`, or `governor` role; missing or weak access control on `upgradeTo`, `upgradeToAndCall`, or Diamond's `diamondCut` allows unauthorized logic replacement. EIP-1967 and EIP-2535 prescribe standard storage slots for implementation address and admin; deviating from them breaks tooling and audit assumptions. Finally, upgrade calldata (e.g., `initialize` arguments) must be validated before execution, otherwise a malicious governor can inject arbitrary code during the upgrade.

### Detection Checks

1. Proxy contract lacks a storage gap (e.g., `uint256[50] __gap;`) in the base implementation contract, risking storage collisions when new state variables are added in future upgrades.
2. Implementation contract uses a constructor instead of an `initialize()` function with `initializer` modifier, leaving the proxy uninitialized and vulnerable to front-running initialization.
3. Upgrade function (`upgradeTo`, `upgradeToAndCall`, `diamondCut`, `setImplementation`) missing role-based access control (`onlyOwner`, `onlyAdmin`, `onlyGovernor`) or using an incorrectly initialized `Ownable`/`AccessControl` so the owner address is zero.
4. Initializer function lacks the `initializer` modifier or a manual `initialized` flag check, allowing re-initialization after the first call.
5. Upgrade calldata is executed via `delegatecall` without validating the target function selector or arguments, enabling arbitrary code execution during upgrade.
6. Contract inherits `EIP712Upgradeable` or similar upgradeable base but never calls its `__EIP712_init` / `__ERC20_init` etc., leaving domain separator or token metadata uninitialized.
7. Storage layout uses `immutable` or `constant` variables in the implementation contract, which are not stored in proxy storage and behave differently after upgrade.
8. Diamond proxy's `diamondCut` does not enforce facet removal/addition validation (e.g., duplicate selectors, zero address facets) or lacks a timelock/multisig on the `diamondCut` caller.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract VulnerableUpgradeable is Initializable, OwnableUpgradeable {
    uint256 public value;
    // Missing storage gap

    function initialize(uint256 _value) external {
        // Missing initializer modifier
        value = _value;
        __Ownable_init(); // owner set here, but OwnableUpgradeable constructor not run
    }

    function setValue(uint256 _value) external onlyOwner {
        value = _value;
    }

    // No upgradeTo function; assume external proxy calls delegatecall on this
}
```

Missing storage gap, initialize lacks `initializer` modifier allowing re-initialization, OwnableUpgradeable not properly initialized so `onlyOwner` checks fail, and no access-controlled upgrade function.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract SecureUpgradeable is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public value;
    uint256[49] private __gap; // storage gap for future upgrades

    function initialize(uint256 _value) external initializer {
        value = _value;
        __Ownable_init(msg.sender);
    }

    function setValue(uint256 _value) external onlyOwner {
        value = _value;
    }

    // UUPSUpgradeable provides upgradeToAndCall with onlyOwner
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
```

Storage gap reserves slots, `initializer` modifier prevents re-initialization, `OwnableUpgradeable` initialized with deployer, and `UUPSUpgradeable` supplies access-controlled upgrade mechanism.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
