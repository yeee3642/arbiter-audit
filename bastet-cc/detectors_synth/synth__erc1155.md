---
id: synth__erc1155
name: "ERC1155-Standard Compliance and Callback Safety"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["ERC1155"]
routing_hints: ["onERC1155Received", "onERC1155BatchReceived", "safeBatchTransferFrom", "uri", "RentalOrder", "ItemType", "RentalAssetUpdate", "_addTokenEnumeration", "_removeTokenEnumeration", "reclaimRentalOrder", "removeRentals", "rentalId"]
required_hints: []
prompt_chars: 6661
synthesized: true
gated: true
synth_provenance: {"train_findings": ["468", "471", "247", "250", "466", "249"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 28, "hints_rejected": 5, "hint_coverage": 0.857, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 0.0, "fp": 0.0, "folds": 2, "repaired": true}}
---

# ERC1155-Standard Compliance and Callback Safety

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC1155-Standard Compliance and Callback Safety**
ERC1155 multi-token contracts must maintain strict compliance with the EIP-1155 specification to ensure interoperability and prevent asset loss. Common failure modes include: (1) enumeration arrays (_allTokens, _ownedTokens) that diverge from actual supply because tokens are added when _idTotalSupply[id] == 0 before minting but not re-added if supply was previously zeroed, or removed when checking pre-burn supply instead of post-burn supply; (2) rental or escrow state deleted before verifying all asset amounts are fully returned, allowing partial fills to orphan remaining assets; (3) external calls via safeTransferFrom or safeBatchTransferFrom executed before internal state updates, violating checks-effects-interactions and enabling reentrancy through onERC1155Received callbacks; (4) calldata decoding offsets that reference wrong function parameters (e.g., using prevModule offset for module parameter), causing authorization bypasses; (5) missing validation of token existence, approval status, or amount bounds before transfers. Auditors should trace every mint/burn/transfer path for enumeration consistency, verify CEI ordering around all external calls, confirm calldata offsets match the target function ABI, and ensure state deletions occur only after full settlement validation.

### Detection Checks

1. Enumeration addition in _addTokenEnumeration uses _idTotalSupply[id] == 0 before incrementing supply, but does not re-add tokenId to _allTokens if it was previously removed when supply hit zero and is now being minted again.
2. Enumeration removal in _removeTokenEnumeration checks _idTotalSupply[id] == 0 before decrementing supply, so the post-burn zero supply is never detected and _removeTokenFromAllTokensEnumeration is not called.
3. Duplicate tokenId entries possible in _allTokens because _addTokenToAllTokensEnumeration is called without verifying the tokenId is not already present in the array.
4. Rental order deleted from storage (delete orders[orderHash]) before verifying all rentedAssets[rentalId] amounts have been reduced to zero, allowing partial returns to remove the order and lock remaining assets.
5. ERC1155 transfers via _transferERC1155 (safeTransferFrom) executed before updating rental state (e.g., rentedAssets balances, order status), enabling reentrancy through onERC1155Received callback to manipulate rental accounting.
6. Calldata offset constants (e.g., gnosis_safe_disable_module_offset) used to decode function parameters do not match the target function's ABI parameter ordering, causing wrong values to be validated.
7. Missing validation that tokenId exists (_idTotalSupply[id] > 0) and caller has sufficient balance or approval before executing safeTransferFrom or safeBatchTransferFrom.
8. Missing nonReentrant modifier or reentrancy guard on functions that perform external ERC1155 transfers while holding mutable rental/escrow state.

### Examples

#### Example 1: Incorrect Example

```solidity
function _addTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
    if (from == address(0)) {
        if (_idTotalSupply[id] == 0) _addTokenToAllTokensEnumeration(id);
        _idTotalSupply[id] += amount;
    }
}

function _removeTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
    if (to == address(0)) {
        if (_idTotalSupply[id] == 0) _removeTokenFromAllTokensEnumeration(id);
        _idTotalSupply[id] -= amount;
    }
}

function removeRentals(bytes32 orderHash, RentalAssetUpdate[] calldata updates) external {
    delete orders[orderHash];
    for (uint i = 0; i < updates.length; i++) {
        rentedAssets[updates[i].rentalId] -= updates[i].amount;
    }
}

function reclaimRentalOrder(RentalOrder calldata order) external {
    for (uint i = 0; i < order.items.length; i++) {
        if (order.items[i].itemType == ItemType.ERC1155) {
            _transferERC1155(order.items[i], order.lender);
        }
    }
}
```

Enumeration checks pre-mint/pre-burn supply instead of post-state, rental order deleted before verifying full asset return, and ERC1155 transfer occurs before state updates enabling reentrancy.

#### Example 2: Correct Example

```solidity
function _addTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
    if (from == address(0)) {
        uint256 prevSupply = _idTotalSupply[id];
        _idTotalSupply[id] += amount;
        if (prevSupply == 0 && _idTotalSupply[id] > 0) _addTokenToAllTokensEnumeration(id);
    }
    if (to != address(0) && to != from) {
        if (balanceOf(to, id) == amount) _addTokenToOwnerEnumeration(to, id);
    }
}

function _removeTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
    if (to == address(0)) {
        _idTotalSupply[id] -= amount;
        if (_idTotalSupply[id] == 0) _removeTokenFromAllTokensEnumeration(id);
    }
    if (from != address(0) && from != to) {
        if (balanceOf(from, id) == 0) _removeTokenFromOwnerEnumeration(from, id);
    }
}

function removeRentals(bytes32 orderHash, RentalAssetUpdate[] calldata updates) external {
    for (uint i = 0; i < updates.length; i++) {
        rentedAssets[updates[i].rentalId] -= updates[i].amount;
    }
    bool fullyReturned = true;
    for (uint i = 0; i < updates.length; i++) {
        if (rentedAssets[updates[i].rentalId] > 0) fullyReturned = false;
    }
    if (fullyReturned) delete orders[orderHash];
}

function reclaimRentalOrder(RentalOrder calldata order) external nonReentrant {
    for (uint i = 0; i < order.items.length; i++) {
        if (order.items[i].itemType == ItemType.ERC1155) {
            // update rental state first
            rentedAssets[order.items[i].rentalId] = 0;
        }
    }
    for (uint i = 0; i < order.items.length; i++) {
        if (order.items[i].itemType == ItemType.ERC1155) {
            _transferERC1155(order.items[i], order.lender);
        }
    }
}
```

Enumeration uses post-state supply checks, rental deletion occurs only after verifying all assets returned, and state updates precede external transfers with reentrancy guard.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
