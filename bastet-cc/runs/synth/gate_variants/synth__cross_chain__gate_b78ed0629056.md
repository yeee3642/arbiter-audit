# Cross-Chain Vulnerabilities

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Cross-Chain Vulnerabilities**
Cross-chain protocols must handle three fundamental failure modes: (1) Address format incompatibility — EVM addresses (20 bytes) cannot represent non-EVM chain addresses (bech32, ed25519 pubkeys, etc.), so encoding a destination or source address as `address` or `bytes20` breaks verification for heterogeneous chains. (2) Missing recovery/rollback — burning or locking tokens on the source chain before the destination chain executes the message creates irreversible loss if the remote call reverts, times out, or is never picked up; a refund or re-mint pathway keyed to a message ID and caller-specified refund address is required. (3) Decimal precision mismatch — tokens with the same symbol (e.g., USDC) may have different decimals on different chains (6 on Ethereum, 12 on some L2s, 8 on others); transmitting raw amounts without normalization causes value distortion. Additionally, cross-chain messages must include chain ID validation and replay protection (nonce or message ID) to prevent malicious replay across chains.

### Detection Checks

1. Functions that encode source/destination addresses for cross-chain messages use `address` or `bytes20` types instead of `bytes` or `string`, preventing representation of non-EVM address formats.
2. Token burn/lock operations (`_burn`, `transferFrom` to bridge, `lock`) execute before emitting the cross-chain message event, with no on-chain refund/re-mint logic gated by a message ID and a caller-specified refund address.
3. Cross-chain message emission (`emit ContractCall`, `emit ContractCallWithToken`) uses `msg.sender` as the refund/recipient address instead of accepting an explicit `refundAddress` or `destinationRecipient` parameter from the caller.
4. Amounts for cross-chain token transfers are passed through without decimal normalization — no lookup of token decimals on source chain, no conversion to a canonical representation (e.g., 18 decimals), and no validation that the destination chain expects the same decimal scale.
5. Cross-chain message payloads lack a source chain ID field or domain separator, enabling replay of messages from one chain on another chain with the same contract address.
6. Message verification on the destination chain does not validate that the reported source chain matches the expected chain ID, or that the source address format is compatible with the claimed source chain.
7. No timeout or expiration mechanism exists for pending cross-chain messages — messages can remain unexecuted indefinitely with no way for the user to reclaim locked/burned assets.
8. State updates (e.g., marking a message as executed, updating nonces) on the destination chain are not protected against reentrancy or out-of-order execution, allowing state inconsistency between chains.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossChainBridge {
    event ContractCall(address indexed sender, string destinationChain, string destinationContract, bytes32 payloadHash, bytes payload);
    event ContractCallWithToken(address indexed sender, string destinationChain, string destinationContract, bytes32 payloadHash, bytes payload, string symbol, uint256 amount);

    mapping(string => address) public tokenContracts;

    function callContract(
        string calldata destinationChain,
        string calldata destinationContractAddress,
        bytes calldata payload
    ) external {
        // @audit uses msg.sender as refund address; no caller-specified refundAddress
        emit ContractCall(msg.sender, destinationChain, destinationContractAddress, keccak256(payload), payload);
    }

    function callContractWithToken(
        string calldata destinationChain,
        string calldata destinationContractAddress,
        bytes calldata payload,
        string calldata symbol,
        uint256 amount
    ) external {
        // @audit burns before emit; no recovery if destination fails
        // @audit no decimal normalization for amount
        IERC20(tokenContracts[symbol]).burnFrom(msg.sender, amount);
        emit ContractCallWithToken(msg.sender, destinationChain, destinationContractAddress, keccak256(payload), payload, symbol, amount);
    }

    function _verifyApproval(
        bytes32 commandId,
        string memory sourceChain,
        string memory sourceAddress,
        address contractAddress,  // @audit address type cannot hold non-EVM addresses
        bytes32 payloadHash,
        string memory symbol,
        uint256 amount
    ) internal pure returns (bool) {
        // approval lookup uses address-typed contractAddress
        return true;
    }
}
```

The contract burns tokens before cross-chain emission with no refund path, uses msg.sender instead of a caller-specified refund address, encodes contract addresses as EVM-only `address` type, and passes raw token amounts without decimal normalization.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossChainBridgeFixed {
    event ContractCall(bytes caller, string destinationChain, string destinationContract, bytes32 payloadHash, bytes payload, bytes refundAddress);
    event ContractCallWithToken(bytes caller, string destinationChain, string destinationContract, bytes32 payloadHash, bytes payload, string symbol, uint256 amount, bytes refundAddress);
    event TokenRefunded(bytes indexed caller, string symbol, uint256 amount, bytes32 messageId);

    mapping(string => address) public tokenContracts;
    mapping(string => uint8) public tokenDecimals; // source chain decimals
    mapping(bytes32 => bool) public executedMessages;
    uint256 public constant MESSAGE_TIMEOUT = 7 days;
    mapping(bytes32 => uint256) public messageTimestamps;

    function callContract(
        string calldata destinationChain,
        string calldata destinationContractAddress,
        bytes calldata payload,
        bytes calldata refundAddress
    ) external {
        bytes32 messageId = keccak256(abi.encode(msg.sender, destinationChain, destinationContractAddress, payload, block.number));
        messageTimestamps[messageId] = block.timestamp;
        emit ContractCall(abi.encode(msg.sender), destinationChain, destinationContractAddress, keccak256(payload), payload, refundAddress);
    }

    function callContractWithToken(
        string calldata destinationChain,
        string calldata destinationContractAddress,
        bytes calldata payload,
        string calldata symbol,
        uint256 amount,
        bytes calldata refundAddress
    ) external {
        uint8 srcDecimals = tokenDecimals[symbol];
        uint256 normalizedAmount = (srcDecimals < 18) ? amount * 10**(18 - srcDecimals) : amount / 10**(srcDecimals - 18);
        bytes32 messageId = keccak256(abi.encode(msg.sender, destinationChain, destinationContractAddress, payload, symbol, normalizedAmount, block.number));
        messageTimestamps[messageId] = block.timestamp;
        // Lock instead of burn; refundable on timeout
        IERC20(tokenContracts[symbol]).transferFrom(msg.sender, address(this), amount);
        emit ContractCallWithToken(abi.encode(msg.sender), destinationChain, destinationContractAddress, keccak256(payload), payload, symbol, normalizedAmount, refundAddress);
    }

    function refundOnTimeout(bytes32 messageId, string calldata symbol, uint256 amount) external {
        require(block.timestamp > messageTimestamps[messageId] + MESSAGE_TIMEOUT, "not timed out");
        require(!executedMessages[messageId], "already executed");
        executedMessages[messageId] = true;
        IERC20(tokenContracts[symbol]).transfer(msg.sender, amount);
        emit TokenRefunded(abi.encode(msg.sender), symbol, amount, messageId);
    }

    function _verifyApproval(
        bytes32 commandId,
        string memory sourceChain,
        bytes memory sourceAddress,  // bytes supports any address format
        bytes memory contractAddress,
        bytes32 payloadHash,
        string memory symbol,
        uint256 amount
    ) internal pure returns (bool) {
        // approval lookup uses bytes for universal address representation
        return true;
    }
}
```

The fixed contract uses `bytes` for universal address representation, accepts explicit `refundAddress`, locks tokens instead of burning with a timeout-based refund mechanism, normalizes amounts to 18 decimals, includes message IDs with timestamps for replay protection and timeout handling, and marks messages as executed to prevent double-processing.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
