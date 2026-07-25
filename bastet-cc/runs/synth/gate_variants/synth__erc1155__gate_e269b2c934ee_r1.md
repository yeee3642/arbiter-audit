# ERC1155

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC1155**
ERC1155 multi-token contracts must strictly follow the EIP-1155 specification to maintain interoperability and prevent exploits. The standard requires that `safeTransferFrom` and `safeBatchTransferFrom` invoke the receiver's `onERC1155Received`/`onERC1155BatchReceived` hook *after* internal state updates (balances, approvals, rental records) to prevent reentrancy. Contracts that transfer tokens before updating state allow malicious receivers to re-enter and manipulate balances or rental logic. Off-chain signature verification (EIP-712) must hash structs exactly as defined, using `abi.encodePacked` for dynamic fields and including all fields; mismatches cause signature validation to accept forged orders. Calldata parsing for function selectors (e.g., Gnosis Safe `disableModule`, ERC1155 `safeTransferFrom`) must use correct parameter offsets; an off-by-one offset reads the wrong argument, bypassing authorization checks. Order lifecycle functions must validate completion (e.g., all rented amounts returned) before deleting order storage; premature deletion locks remaining assets. Supply and index tracking for ERC1155 IDs must stay consistent across mint/burn/transfer to avoid asset mismatches.

### Detection Checks

1. In `safeTransferFrom`/`safeBatchTransferFrom` implementations or wrappers, verify that all balance/approval/rental state updates occur *before* the external `onERC1155Received`/`onERC1155BatchReceived` call (Checks-Effects-Interactions).
2. In EIP-712 `_deriveOrderMetadataHash` or similar hashing functions, confirm `abi.encodePacked` is used for the outer struct hash and that every struct field (including `emittedExtraData`, `hooks`, `rentDuration`) is included exactly as in the EIP-712 domain separator.
3. In calldata-parsing logic (assembly or `_loadValueFromCalldata`), verify offsets for each selector match the function signature's parameter order (e.g., `disableModule(address,address)` second parameter is `module`, not `prevModule`).
4. In order removal functions (e.g., `removeRentals`), require a check that all associated rental amounts are zero (`rentedAssets[rentalId] == 0`) before `delete orders[orderHash]`.
5. In mint/burn/transfer hooks, ensure total supply per ID (`_totalSupply[id]` or equivalent) and token index mappings (`_idToIndex`, `_indexToId`) are updated atomically and consistently.
6. In `onERC1155Received`/`onERC1155BatchReceived` implementations, confirm the function returns the correct magic value (`bytes4(keccak256('onERC1155Received(address,address,uint256,uint256,bytes)'))`) and reverts on unexpected callers.
7. In `setApprovalForAll` handlers, verify the `operator` and `approved` arguments are indexed correctly in events and storage; watch for swapped `owner`/`operator` in `ApprovalForAll` emission.
8. In batch operations (`safeBatchTransferFrom`, `mintBatch`, `burnBatch`), confirm array lengths for `ids` and `amounts` are validated equal before iteration to prevent out-of-bounds or mismatched transfers.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract VulnerableRental is ERC1155 {
    mapping(bytes32 => bool) public orders;
    mapping(uint256 => uint256) public rentedAssets; // rentalId => amount
    
    function removeRentals(bytes32 orderHash, uint256[] calldata rentalIds) external {
        if (!orders[orderHash]) revert("Order missing");
        delete orders[orderHash]; // @audit deletes before validating returns
        for (uint256 i = 0; i < rentalIds.length; i++) {
            rentedAssets[rentalIds[i]] = 0;
        }
    }
    
    function reclaimRental(uint256 id, uint256 amount, address lender) external {
        // @audit transfers before state update -> reentrancy via onERC1155Received
        safeTransferFrom(address(this), lender, id, amount, "");
        rentedAssets[id] -= amount;
    }
    
    function _deriveOrderHash(uint256 rentDuration, bytes32[] calldata hooks) internal pure returns (bytes32) {
        // @audit uses abi.encode instead of abi.encodePacked; omits emittedExtraData
        return keccak256(abi.encode(keccak256("OrderMetadata(uint256,bytes32[])"), rentDuration, keccak256(abi.encode(hooks))));
    }
}
```

Deletes order before verifying rented assets returned; transfers ERC1155 before updating rental state enabling reentrancy; uses abi.encode instead of abi.encodePacked and omits fields in EIP-712 hash.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract FixedRental is ERC1155 {
    mapping(bytes32 => bool) public orders;
    mapping(uint256 => uint256) public rentedAssets;
    
    function removeRentals(bytes32 orderHash, uint256[] calldata rentalIds) external {
        if (!orders[orderHash]) revert("Order missing");
        for (uint256 i = 0; i < rentalIds.length; i++) {
            if (rentedAssets[rentalIds[i]] != 0) revert("Assets not fully returned");
        }
        delete orders[orderHash];
        for (uint256 i = 0; i < rentalIds.length; i++) {
            rentedAssets[rentalIds[i]] = 0;
        }
    }
    
    function reclaimRental(uint256 id, uint256 amount, address lender) external {
        rentedAssets[id] -= amount; // @audit state update before external call
        safeTransferFrom(address(this), lender, id, amount, "");
    }
    
    function _deriveOrderHash(uint256 rentDuration, bytes32[] calldata hooks, bytes calldata emittedExtraData) internal pure returns (bytes32) {
        // @audit abi.encodePacked for outer, includes all fields
        return keccak256(abi.encodePacked(keccak256("OrderMetadata(uint256,bytes32[],bytes)"), rentDuration, keccak256(abi.encodePacked(hooks)), keccak256(emittedExtraData)));
    }
}
```

Validates all rented amounts zero before deleting order; updates rental state before safeTransferFrom to prevent reentrancy; uses abi.encodePacked with all fields for correct EIP-712 hashing.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
