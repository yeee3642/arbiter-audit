# Bridge-Insufficient Validation

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Bridge-Insufficient Validation**
Bridge contracts facilitate asset or data transfers between distinct blockchain networks by locking or burning assets on the source chain and minting or releasing equivalent assets on the destination chain after verifying a proof of the source-chain event. The core security assumption is that only valid, finalized, and non-replayed source-chain events trigger destination-chain actions. Vulnerabilities arise when the verification logic accepts proofs that are not yet final (e.g., insufficient block confirmations), does not bind the proof to a specific destination chain or recipient (allowing cross-chain replay), fails to enforce a strict nonce or message-id ordering (enabling reordering or omission attacks), or trusts an unauthenticated relayer to supply critical parameters such as token amounts or receiver addresses. An attacker who can submit a crafted proof or manipulate relayer-provided calldata can drain locked liquidity or mint unbacked tokens on the destination chain.

### Detection Checks

1. Verify that the bridge validates a minimum number of block confirmations or finality proofs (e.g., checking block headers against a trusted light client or waiting for a finalized epoch) before processing a deposit or withdrawal claim.
2. Ensure every cross-chain message carries a globally unique nonce or sequence number and that the contract rejects any message with a nonce <= lastProcessedNonce[sourceChain].
3. Confirm that the verification logic binds the proof to the intended destination chain ID and recipient address so the same proof cannot be replayed on a different chain or to a different user.
4. Check that token amounts, fee parameters, and receiver addresses are derived exclusively from the verified proof (Merkle root, storage proof, or signature set) and never taken directly from unauthenticated calldata supplied by the relayer.
5. Validate that the contract rejects proofs for source-chain events that have already been processed by maintaining a bitmap or mapping of consumed message hashes or nonces.
6. Ensure the bridge pauses or reverts when the underlying consensus or light client reports a re-org or finality failure on the source chain.
7. Verify that privileged functions such as upgrading the verification logic, changing the trusted validator set, or updating the destination chain ID are protected by a timelock or multisig and cannot be front-run by a malicious relayer.
8. Confirm that gas limits and execution deadlines for the destination-chain callback are enforced so a griefing relayer cannot cause the bridge to lock funds indefinitely.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBridge {
    mapping(bytes32 => bool) public processed;
    uint256 public lastNonce;
    
    function claimDeposit(
        bytes32 depositId,
        address token,
        uint256 amount,
        address recipient,
        bytes calldata proof
    ) external {
        // @audit no verification of proof authenticity or finality
        // @audit no nonce ordering enforcement
        // @audit token, amount, recipient taken from untrusted calldata
        require(!processed[depositId], "already claimed");
        processed[depositId] = true;
        IERC20(token).mint(recipient, amount);
    }
}
```

The claimDeposit function accepts token, amount, and recipient directly from calldata without cryptographic verification, lacks nonce ordering, and performs no finality check, allowing a relayer to mint arbitrary tokens.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureBridge {
    mapping(bytes32 => bool) public processed;
    uint256 public lastNonce;
    bytes32 public trustedRoot;
    
    function claimDeposit(
        uint256 sourceChainId,
        uint256 nonce,
        address token,
        uint256 amount,
        address recipient,
        bytes calldata proof
    ) external {
        // @audit enforce strict nonce ordering per source chain
        require(nonce > lastNonce, "stale or replayed nonce");
        lastNonce = nonce;
        
        // @audit verify Merkle proof against trusted root
        bytes32 leaf = keccak256(abi.encode(sourceChainId, nonce, token, amount, recipient));
        require(MerkleProof.verify(proof, trustedRoot, leaf), "invalid proof");
        
        // @audit prevent replay of same deposit
        bytes32 msgHash = keccak256(abi.encode(sourceChainId, nonce));
        require(!processed[msgHash], "already processed");
        processed[msgHash] = true;
        
        IERC20(token).mint(recipient, amount);
    }
}
```

The fixed version enforces monotonic nonce ordering, verifies a Merkle proof against a trusted root, binds all parameters to the proof, and tracks processed message hashes to prevent replay.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
