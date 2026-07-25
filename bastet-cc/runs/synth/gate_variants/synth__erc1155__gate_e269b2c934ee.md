# ERC1155-Standard Compliance and Callback Safety

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC1155-Standard Compliance and Callback Safety**
ERC-1155 contracts must strictly follow the EIP-1155 specification for transfer functions, approval handling, and the onERC1155Received/onERC1155BatchReceived callbacks. A compliant safeTransferFrom or safeBatchTransferFrom must invoke the receiver hook after updating balances but before emitting the TransferSingle/TransferBatch event, and must revert if the receiver does not return the magic value bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")) or bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)")). Skipping the callback, calling it at the wrong time (e.g., before state changes), or ignoring its return value enables reentrancy and breaks composability with wallets and marketplaces. Total supply tracking for each token ID must stay consistent with mint/burn operations; using abi.encode instead of abi.encodePacked (or vice-versa) when hashing structs for EIP-712 signatures or order identifiers produces mismatched digests, causing signature verification failures or order-cancellation logic to delete the wrong order. When deleting orders or rental records, the contract must verify that all associated asset amounts have been fully settled before removing the storage entry; otherwise a partial fill can erase the order while tokens remain locked, making them unrecoverable. Finally, calldata decoding for ERC-1155 selectors (safeTransferFrom, safeBatchTransferFrom, setApprovalForAll) must use the correct byte offsets for each parameter; an off-by-one offset reads the wrong argument (e.g., token ID vs. amount vs. data), leading to incorrect authorization checks or asset theft.

### Detection Checks

1. Verify that safeTransferFrom and safeBatchTransferFrom call IERC1155Receiver(to).onERC1155Received / onERC1155BatchReceived after balance updates and before event emission, and revert if the returned bytes4 != the expected magic value.
2. Confirm that setApprovalForAll emits the ApprovalForAll event with correct owner, operator, and approved arguments and does not allow approval to be set for the zero address unless explicitly intended.
3. Check that _mint, _burn, _mintBatch, _burnBatch update the totalSupply[id] (or equivalent tracking) atomically with balance changes; no path should modify balances without updating supply.
4. Ensure EIP-712 domain separators and struct hashes use abi.encodePacked for dynamic arrays/bytes and abi.encode for static types exactly as defined in the EIP-712 specification; mixing them causes hash mismatches.
5. Validate that order/rental deletion functions (e.g., removeRentals, cancelOrder) require a proof or check that all associated token amounts are zero or fully returned before deleting the storage slot.
6. Inspect calldata decoding routines for ERC-1155 function selectors: the token ID offset for safeTransferFrom is 4+32+32+32=100 bytes from calldata start, amount offset is 132, data offset is 164; for safeBatchTransferFrom the ids/amounts array offsets follow the same pattern. Offsets must match the canonical ABI encoding.
7. Confirm that any external call to a user-supplied address (including the onERC1155Received hook) is protected by a reentrancy guard (nonReentrant modifier) or follows the Checks-Effects-Interactions pattern.
8. Verify that balanceOfBatch and safeBatchTransferFrom handle array length mismatches (ids.length != amounts.length) by reverting immediately.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract FlawedERC1155 is ERC1155 {
    mapping(bytes32 => bool) public orders;
    mapping(bytes32 => uint256) public rentedAmount;

    constructor() ERC1155("") {}

    // Missing onERC1155Received call and magic-value check
    function unsafeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes memory data) external {
        _burn(from, id, amount);
        _mint(to, id, amount);
        emit TransferSingle(_msgSender(), from, to, id, amount);
        // No receiver hook -> breaks EIP-1155, enables reentrancy
    }

    // Deletes order before verifying rentedAmount is zero
    function removeRental(bytes32 orderHash) external {
        delete orders[orderHash]; // order erased while tokens still rented
        // rentedAmount[orderHash] never checked
    }

    // Uses abi.encode instead of abi.encodePacked for dynamic hook array
    function hashMetadata(uint256 duration, bytes32[] memory hooks) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("Metadata(uint256,bytes32[])"), duration, keccak256(abi.encode(hooks))));
    }

    // Calldata offset for token ID in safeTransferFrom is wrong (uses 68 instead of 100)
    function decodeTokenId(bytes memory data) internal pure returns (uint256) {
        return abi.decode(data[68:100], (uint256));
    }
}
```

The contract omits the mandatory onERC1155Received callback, deletes an order before confirming rented assets are returned, hashes metadata with abi.encode for a dynamic array causing EIP-712 mismatches, and uses an incorrect calldata offset when decoding the token ID from safeTransferFrom calldata.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract CompliantERC1155 is ERC1155, ReentrancyGuard {
    mapping(bytes32 => bool) public orders;
    mapping(bytes32 => uint256) public rentedAmount;

    constructor() ERC1155("") {}

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes memory data) public override nonReentrant {
        _burn(from, id, amount);
        _mint(to, id, amount);
        if (to.isContract()) {
            bytes4 ret = IERC1155Receiver(to).onERC1155Received(_msgSender(), from, id, amount, data);
            require(ret == IERC1155Receiver.onERC1155Received.selector, "ERC1155: receiver rejected");
        }
        emit TransferSingle(_msgSender(), from, to, id, amount);
    }

    function removeRental(bytes32 orderHash) external {
        require(rentedAmount[orderHash] == 0, "assets still rented");
        delete orders[orderHash];
        delete rentedAmount[orderHash];
    }

    function hashMetadata(uint256 duration, bytes32[] memory hooks) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256("Metadata(uint256,bytes32[])"), duration, keccak256(abi.encodePacked(hooks))));
    }

    function decodeTokenId(bytes calldata data) internal pure returns (uint256) {
        // selector(4) + from(32) + to(32) + id(32) = 100
        return abi.decode(data[100:132], (uint256));
    }
}
```

The fixed contract invokes onERC1155Received with the correct magic-value check, guards external calls with nonReentrant, verifies rentedAmount is zero before deleting the order, uses abi.encodePacked for the dynamic hooks array to match EIP-712, and decodes the token ID at the correct calldata offset (100).

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
