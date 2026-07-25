# Cross-Chain

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Cross-Chain**
Cross-chain protocols must enforce strict validation of chain identifiers, message origins, and asset handling to prevent unauthorized state changes and asset loss. A common flaw is accepting trusted addresses or configuration for arbitrary chains without verifying the caller's chain matches the configured chain, allowing an attacker on chain A to inject a trusted address for chain B. Another critical issue is burning or locking tokens on the source chain before the destination chain confirms execution, with no rollback or refund mechanism if the remote call fails or reverts. Rebase tokens exacerbate this: recording a fixed amount at lock time and later transferring that exact amount ignores supply changes, causing underpayment on positive rebase or reverts on negative rebase. Finally, missing chain ID validation in message payloads enables replay attacks across chains with identical contract addresses.

### Detection Checks

1. Verify that functions setting trusted addresses or chain-specific configuration validate the caller's chain origin (e.g., via `msg.sender` chain ID or gateway-provided source chain) against the target chain parameter.
2. Ensure token burns or locks occur only after the destination chain confirms successful execution, or implement a refund/re-mint mechanism callable on failure (e.g., via a `revertMessage` or `handleFailure` callback).
3. Check that cross-chain token transfers involving rebasing tokens (e.g., `stETH`, `aUSDC`) read the current balance at execution time rather than using a stale amount recorded at lock time.
4. Confirm that all inbound cross-chain messages include a chain ID or domain separator in the signed payload and that the receiver validates it matches the current chain.
5. Validate that remote deployment or initialization functions (e.g., `deployRemoteTokenManager`) restrict callers to the token owner, minter, or authorized roles via `onlyOwner` or role-based access control.
6. Ensure outbound messages encode the destination chain ID and that the gateway enforces it matches the actual target chain.
7. Verify that token amount handling uses `balanceOf` at execution for rebasing tokens, not a cached `amount` parameter.
8. Check that failed cross-chain calls trigger a compensating transaction (mint/unlock) on the source chain via a registered failure handler.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGateway {
    function callContract(string calldata chain, bytes calldata payload) external;
    function tokenAddresses(string calldata symbol) external view returns (address);
}

contract CrossChainBridge {
    IGateway public gateway;
    mapping(string => address) public trustedAddresses;
    
    function setTrustedAddress(string calldata chain, address addr) external {
        trustedAddresses[chain] = addr; // @audit no validation that caller is from 'chain'
    }
    
    function sendToken(string calldata destChain, string calldata symbol, uint256 amount) external {
        IERC20(gateway.tokenAddresses(symbol)).burnFrom(msg.sender, amount); // @audit burn before remote confirm
        gateway.callContract(destChain, abi.encode(symbol, amount)); // @audit no chain ID in payload
    }
    
    function receiveToken(string calldata srcChain, string calldata symbol, uint256 amount) external {
        require(msg.sender == trustedAddresses[srcChain], "untrusted");
        IERC20(gateway.tokenAddresses(symbol)).mint(msg.sender, amount); // @audit fixed amount, ignores rebase
    }
}
```

The contract allows setting trusted addresses for any chain without origin validation, burns tokens before remote confirmation with no rollback, omits chain ID in outbound payloads enabling replay, and mints a fixed amount on receipt ignoring rebasing token supply changes.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGateway {
    function callContract(string calldata chain, bytes calldata payload) external;
    function tokenAddresses(string calldata symbol) external view returns (address);
    function getSourceChain() external view returns (string memory);
}

contract CrossChainBridge {
    IGateway public gateway;
    mapping(string => address) public trustedAddresses;
    mapping(bytes32 => uint256) public pendingRefunds;
    
    function setTrustedAddress(string calldata chain, address addr) external {
        require(keccak256(bytes(gateway.getSourceChain())) == keccak256(bytes(chain)), "not origin chain");
        trustedAddresses[chain] = addr;
    }
    
    function sendToken(string calldata destChain, string calldata symbol, uint256 amount) external {
        bytes32 msgId = keccak256(abi.encode(destChain, symbol, amount, block.number, msg.sender));
        IERC20(gateway.tokenAddresses(symbol)).safeTransferFrom(msg.sender, address(this), amount); // lock, not burn
        gateway.callContract(destChain, abi.encode(msgId, destChain, symbol, amount, block.chainid)); // include chain ID
    }
    
    function receiveToken(string calldata srcChain, string calldata symbol, uint256 amount, uint256 srcChainId) external {
        require(msg.sender == trustedAddresses[srcChain], "untrusted");
        require(srcChainId == block.chainid, "chain ID mismatch");
        uint256 currentBal = IERC20(gateway.tokenAddresses(symbol)).balanceOf(address(this));
        require(currentBal >= amount, "insufficient balance for rebase");
        IERC20(gateway.tokenAddresses(symbol)).safeTransfer(msg.sender, amount);
    }
    
    function refundFailed(bytes32 msgId, string calldata symbol, uint256 amount) external {
        require(pendingRefunds[msgId] == amount, "invalid refund");
        IERC20(gateway.tokenAddresses(symbol)).safeTransfer(msg.sender, amount);
        delete pendingRefunds[msgId];
    }
}
```

The fix validates the caller's chain origin when setting trusted addresses, locks tokens instead of burning and adds a refund mechanism, includes destination chain ID in outbound payloads, verifies source chain ID on receipt, and checks current token balance at execution to handle rebasing tokens correctly.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
