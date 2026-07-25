# Cross-Chain

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Cross-Chain**
Cross-chain protocols bridge assets and messages between heterogeneous chains. Vulnerabilities arise when the protocol fails to validate the origin chain of trusted addresses, encodes addresses in EVM-only formats that cannot represent non-EVM chains (e.g., bech32, ed25519 pubkeys), uses msg.sender as the refund address instead of a caller-specified parameter, allows unauthorized callers to trigger remote deployments that initialize state on the destination chain, records static token amounts at lock time without accounting for rebasing supply changes, or burns/emits raw amounts without normalizing for decimal differences between chains. These flaws enable control bypass, message verification failures, fund misrouting, unauthorized state initialization, under/over-payment on rebase tokens, and value mismatch across chains.

### Detection Checks

1. Verify that functions setting trusted addresses or relayers validate the caller's chain origin (e.g., require chainId == localChainId or verify via gateway) before accepting the address.
2. Check that address parameters in cross-chain message hashing/encoding use string or bytes types instead of the Solidity `address` type to support non-EVM address formats.
3. Ensure cross-chain call functions (e.g., callContract, callContractWithToken) accept an explicit `refundAddress` parameter and emit it in events rather than defaulting to `msg.sender`.
4. Confirm that remote deployment or initialization functions (e.g., _deployRemoteTokenManager) restrict callers to token owners, authorized minters, or governance via onlyOwner/onlyRole modifiers.
5. Detect token locking/burning functions that cache an amount at initiation and later transfer that fixed amount without re-reading the current balance (totalSupply or balanceOf) to handle rebasing tokens.
6. Verify that token amount parameters in cross-chain transfers are normalized (e.g., scaled to 18 decimals) using the token's decimals() before burning, minting, or emitting events.
7. Check that replay protection uses globally unique commandIds (including sourceChain, nonce, or blockhash) and that executed commandIds are tracked in a mapping to prevent re-execution.
8. Ensure that gateway message verification validates the source chain ID and source address against a trusted registry before accepting payloads.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGateway {
    function tokenAddresses(string) external view returns (address);
    function isCommandExecuted(bytes32) external view returns (bool);
    function setTrustedAddress(string, string) external;
}

contract CrossChainBridge {
    IGateway public gateway;
    mapping(bytes32 => bool) public executed;
    mapping(string => string) public trustedAddress;
    
    function setTrustedAddress(string calldata chain, string calldata addr) external {
        trustedAddress[chain] = addr; // @audit no origin chain validation
    }
    
    function callContract(string calldata destChain, string calldata destAddr, bytes calldata payload) external {
        emit ContractCall(msg.sender, destChain, destAddr, keccak256(payload), payload); // @audit refund = msg.sender
    }
    
    function callContractWithToken(string calldata destChain, string calldata destAddr, bytes calldata payload, string calldata symbol, uint256 amount) external {
        address token = gateway.tokenAddresses(symbol);
        IERC20(token).burn(msg.sender, amount); // @audit no decimal normalization
        emit ContractCallWithToken(msg.sender, destChain, destAddr, keccak256(payload), payload, symbol, amount);
    }
    
    function executeWithToken(bytes32 commandId, string calldata srcChain, string calldata srcAddr, bytes calldata payload, string calldata symbol, uint256 amount) external {
        if (executed[commandId]) revert();
        executed[commandId] = true;
        address token = gateway.tokenAddresses(symbol);
        IERC20(token).mint(msg.sender, amount); // @audit fixed amount, ignores rebase
    }
    
    function _deployRemoteTokenManager(bytes32 tokenId, string calldata destChain, uint256 gas, uint8 type, bytes calldata params) internal {
        // @audit no caller authorization check
        bytes memory payload = abi.encode(1, tokenId, type, params);
        // _callContract(destChain, payload, gas);
    }
    
    event ContractCall(address refundAddress, string destChain, string destAddr, bytes32 payloadHash, bytes payload);
    event ContractCallWithToken(address refundAddress, string destChain, string destAddr, bytes32 payloadHash, bytes payload, string symbol, uint256 amount);
}
```

Missing origin-chain validation for trusted addresses, hardcoded msg.sender refund address, no decimal normalization on burn, fixed-amount mint ignoring rebase, and unauthorized remote deployment trigger.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGateway {
    function tokenAddresses(string) external view returns (address);
    function isCommandExecuted(bytes32) external view returns (bool);
    function setTrustedAddress(string, string) external;
    function getChainId() external view returns (uint256);
}

contract CrossChainBridgeFixed {
    IGateway public gateway;
    mapping(bytes32 => bool) public executed;
    mapping(string => string) public trustedAddress;
    uint256 public localChainId;
    
    constructor(uint256 _chainId) { localChainId = _chainId; }
    
    function setTrustedAddress(string calldata chain, string calldata addr) external {
        require(keccak256(bytes(chain)) == keccak256(abi.encodePacked(localChainId)), "not origin chain");
        trustedAddress[chain] = addr;
    }
    
    function callContract(string calldata destChain, string calldata destAddr, bytes calldata payload, address refundAddress) external {
        emit ContractCall(refundAddress, destChain, destAddr, keccak256(payload), payload);
    }
    
    function callContractWithToken(string calldata destChain, string calldata destAddr, bytes calldata payload, string calldata symbol, uint256 amount) external {
        address token = gateway.tokenAddresses(symbol);
        uint8 decimals = IERC20Metadata(token).decimals();
        uint256 normalized = amount * 10**(18 - decimals);
        IERC20(token).burn(msg.sender, amount);
        emit ContractCallWithToken(msg.sender, destChain, destAddr, keccak256(payload), payload, symbol, normalized);
    }
    
    function executeWithToken(bytes32 commandId, string calldata srcChain, string calldata srcAddr, bytes calldata payload, string calldata symbol, uint256 amount) external {
        if (executed[commandId]) revert();
        executed[commandId] = true;
        address token = gateway.tokenAddresses(symbol);
        uint256 currentBal = IERC20(token).balanceOf(address(this));
        require(currentBal >= amount, "insufficient balance for rebase");
        IERC20(token).safeTransfer(msg.sender, amount);
    }
    
    function _deployRemoteTokenManager(bytes32 tokenId, string calldata destChain, uint256 gas, uint8 type, bytes calldata params) internal {
        require(msg.sender == owner(), "unauthorized");
        bytes memory payload = abi.encode(1, tokenId, type, params);
        // _callContract(destChain, payload, gas);
    }
    
    function owner() internal view returns (address);
    
    event ContractCall(address refundAddress, string destChain, string destAddr, bytes32 payloadHash, bytes payload);
    event ContractCallWithToken(address refundAddress, string destChain, string destAddr, bytes32 payloadHash, bytes payload, string symbol, uint256 normalizedAmount);
}
```

Adds origin-chain validation for trusted addresses, accepts explicit refundAddress, normalizes token amounts to 18 decimals, verifies balance at execution time for rebase safety, and restricts remote deployment to owner.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
