# Replay Attack

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Replay Attack**
A replay attack occurs when an attacker captures a valid signed message, transaction, or data payload and resubmits it to the contract, causing the same state change to execute again. In Solidity, this typically manifests when a contract accepts off-chain signatures (EIP-712, EIP-191) or on-chain commitments without tracking which nonces or message hashes have already been processed. The core mechanism is missing or insufficient uniqueness enforcement: the contract must record each used nonce or message hash in a mapping (e.g., `usedNonces[signer][nonce]` or `executedMessages[hash]`) and reject duplicates before applying state changes. Vulnerabilities arise when nonces are not incremented atomically with the effect, when the nonce space is shared across different actions allowing cross-function replay, when `msg.sender` is used as the sole replay guard but the signer differs from the sender (meta-transactions), or when chain ID and contract address are not included in the signed payload enabling cross-chain or cross-contract replay. Proper mitigation requires strict nonce validation, domain separation via EIP-712 `domainSeparator`, and marking the nonce as used before any external calls to prevent reentrancy-based replay.

### Detection Checks

1. Contract accepts a signature (ecrecover, EIP-712 _verify) but does not store and check a used-nonce mapping keyed by signer and nonce before executing effects.
2. Nonce is validated but not marked as consumed atomically with the state change, allowing reentrancy to replay the same nonce.
3. Signed payload lacks domain separator (chainId, verifyingContract) enabling cross-chain or cross-contract replay of the same signature.
4. Nonce scheme is shared across multiple functions or action types, permitting a nonce used for one action to be replayed for a different action.
5. Contract uses only `msg.sender` as replay protection for meta-transactions where the signer != `msg.sender`, allowing anyone to replay the signed payload via a different relayer.
6. Replay protection mapping is reset or cleared (e.g., via `delete` or array pop) without ensuring all pending nonces are finalized.
7. Off-chain signed message includes a deadline/expiration but contract does not enforce it, allowing indefinite replay window.
8. Contract implements EIP-2612 permit or similar but does not increment the owner's nonce after successful execution.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableMetaTx {
    mapping(address => uint256) public nonces;
    
    function executeMetaTx(
        address from,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        // @audit missing replay protection: no check that nonce is unused
        // @audit missing domain separator in signed payload
        bytes32 hash = keccak256(abi.encodePacked(from, data, nonce));
        address signer = ECDSA.recover(hash, signature);
        require(signer == from, "invalid signer");
        
        // @audit nonce not marked used before external call
        (bool success, ) = from.call(data);
        require(success, "call failed");
        
        nonces[from] = nonce + 1; // @audit too late, reentrancy can replay
    }
}
```

The contract verifies the signature but never checks whether the nonce was already used, does not include a domain separator, and increments the nonce only after the external call, enabling reentrancy-based replay.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract SecureMetaTx is EIP712 {
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedMessageHash;
    
    constructor() EIP712("SecureMetaTx", "1") {}
    
    function executeMetaTx(
        address from,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            keccak256("MetaTx(address from,bytes data,uint256 nonce)"),
            from, keccak256(data), nonce
        ));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        require(signer == from, "invalid signer");
        
        // @audit check and mark nonce used atomically before effects
        require(nonces[from] == nonce, "invalid nonce");
        nonces[from] = nonce + 1;
        
        // @audit optional: also track full message hash for defense in depth
        require(!usedMessageHash[digest], "message already executed");
        usedMessageHash[digest] = true;
        
        (bool success, ) = from.call(data);
        require(success, "call failed");
    }
}
```

The fixed contract uses EIP-712 domain separation, validates the nonce matches the expected sequential value, increments the nonce before the external call, and tracks the full message hash to prevent any replay.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
