---
id: synth__opensea
name: "Opensea-Integration-Flaws"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Opensea"]
routing_hints: ["RentalOrder", "_deriveRentalOrderHash", "rentalWallet", "seaportOrderHash", "isRental", "rentDuration", "toRentalId", "orderType", "PREFIX_CONTRACT_CALL_APPROVED_WITH_MINT"]
required_hints: []
prompt_chars: 5123
synthesized: true
gated: true
synth_provenance: {"train_findings": ["469", "296", "464"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 29, "hints_rejected": 1, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 0.0, "fp": 0.0, "folds": 1, "repaired": true}}
---

# Opensea-Integration-Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Opensea-Integration-Flaws**
OpenSea Seaport integration vulnerabilities arise when contracts processing Seaport orders fail to validate critical order properties before executing state changes. The primary flaw patterns include: (1) Missing order existence and fulfillment verification - contracts call stop/fulfillment functions without confirming the order hash exists in storage or was previously fulfilled, allowing arbitrary order manipulation. (2) Insufficient item validation - processing offer/consideration arrays without checking for malicious ERC20 tokens that revert on transfer, enabling DoS during settlement. (3) Cross-chain address encoding errors - using 20-byte EVM address types for non-EVM chain addresses (bech32, ed25519) in approval lookups, breaking cross-chain functionality. (4) Incomplete order metadata validation - verifying only subset of order fields (orderType, timestamps, parties) while skipping cryptographic order hash verification and fulfillment status checks.

### Detection Checks

1. Function processing Seaport order calls storage removal/settlement without first verifying order hash exists in storage mapping via `STORE.rentals(orderHash)` or equivalent existence check
2. Order validation function (`_validateRentalCanBeStoped` or similar) checks only orderType, endTimestamp, and lender but omits verification of order hash existence and prior fulfillment status
3. Loop processing `seaportPayload.offer` and `seaportPayload.consideration` arrays calls `ESCRW.increaseDeposit` or token transfers without validating token safety (no reentrancy guard, no try/catch, no allowlist for ERC20s)
4. Cross-chain approval lookup encodes `contractAddress` as `address` type (20 bytes) in `abi.encode` for non-EVM `sourceAddress` formats, causing keccak256 mismatch for bech32/ed25519 sources
5. Function `_rentFromZone` or fulfillment handler processes items and updates storage before verifying all offer/consideration items match expected rental metadata and recipient
6. Missing validation that `seaportPayload.fulfiller` matches expected recipient safe owner before processing rental asset transfers
7. Order stop/fulfillment function emits event (`_emitRentalOrderStopped`) using `msg.sender` as actor without confirming `msg.sender` equals validated lender/renter from order
8. Storage removal (`STORE.removeRentals`) called with derived order hash without prior check that `STORE.rentals(orderHash).exists == true`

### Examples

#### Example 1: Incorrect Example

```solidity
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
    ESCRW.settlePayment(order);
    STORE.removeRentals(_deriveRentalOrderHash(order), _convertToStatic(rentalAssetUpdates));
    _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
}
```

Validates only orderType, endTimestamp, and lender but never checks if order hash exists in storage or was fulfilled, allowing any lender to stop arbitrary orders and drain assets.

#### Example 2: Correct Example

```solidity
function stopRent(RentalOrder calldata order) external {
    bytes32 orderHash = _deriveRentalOrderHash(order);
    require(STORE.rentals(orderHash).exists, "Order not found");
    require(STORE.rentals(orderHash).fulfilled, "Order not fulfilled");
    _validateRentalCanBeStoped(order.orderType, order.endTimestamp, order.lender);
    require(order.lender == msg.sender, "Only lender");
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
    ESCRW.settlePayment(order);
    STORE.removeRentals(orderHash, _convertToStatic(rentalAssetUpdates));
    _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
}
```

Adds order hash existence and fulfillment checks before validation, restricts caller to order lender, and derives order hash once for consistent storage access.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
