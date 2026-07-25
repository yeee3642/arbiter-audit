---
id: synth__replay_attack
name: "Replay Attack"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Replay Attack"]
routing_hints: ["nonce", "nonces", "ecrecover", "DOMAIN_SEPARATOR", "signature", "castVoteBySig", "checkAfterExecution"]
required_hints: []
prompt_chars: 5012
synthesized: true
gated: true
synth_provenance: {"train_findings": ["483"], "localization_rate": 0.5, "mode": "s2b", "hint_candidates": 21, "hints_rejected": 20, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 0.0, "fp": 1.0, "folds": 1, "repaired": true}}
---

# Replay Attack

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Replay Attack**
A replay attack occurs when an attacker resubmits a previously valid signed message or transaction to execute the same action multiple times. In Solidity, this typically manifests in signature-based functions (e.g., `castVoteBySig`, `permit`, `executeMetaTransaction`) where the signed payload lacks a nonce, timestamp, or chainId, allowing the same signature to be reused. The core mechanism is missing replay protection: the contract does not track used nonces or signatures, does not enforce increasing nonces per signer, or omits domain separators (EIP-712) that bind signatures to a specific chain and contract. Without these, an attacker can capture a valid signature off-chain and replay it on-chain repeatedly, draining allowances, concentrating votes, or executing state changes multiple times. State update ordering also matters: if the nonce is incremented after the external call or effect, a reentrancy or multi-call can replay before the nonce updates.

### Detection Checks

1. Signature verification function (e.g., `ecrecover`, `ECDSA.recover`) is called but the signed payload does not include a nonce or deadline that is checked against storage.
2. Contract has a `nonces` mapping (or similar) but it is not incremented or checked before executing the signed action.
3. Nonce is incremented after the main effect (transfer, vote, mint) rather than before, enabling reentrancy-based replay.
4. EIP-712 domain separator is missing or does not incorporate `chainId` and `verifyingContract`, allowing cross-chain or cross-contract replay.
5. Signed message includes a timestamp but no expiration check (`block.timestamp > deadline`) is enforced.
6. Function accepts a signature from any caller (`msg.sender != signer`) but does not mark the signature as used (e.g., no `usedSignatures` bitmap or nonce increment).
7. Permit-like function (`permit`, `permitBatch`) allows spender to submit signature multiple times because nonce is not consumed atomically with the allowance update.
8. Meta-transaction executor (`executeMetaTransaction`, `execute`) does not validate a relayed nonce against a sequential per-sender counter.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Voting {
    mapping(address => uint256) public votes;
    mapping(address => bool) public hasVoted;
    
    function castVoteBySig(address voter, uint256 candidate, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(voter, candidate)); // @audit no nonce, no deadline, no domain separator
        address recovered = ECDSA.recover(digest, v, r, s);
        require(recovered == voter, "invalid sig");
        require(!hasVoted[voter], "already voted"); // @audit only prevents same voter, not replay of same sig
        votes[candidate] += 1;
        hasVoted[voter] = true;
    }
}
```

The signed digest lacks a nonce or deadline, so the same signature can be replayed to vote multiple times; `hasVoted` only blocks the same address, not signature reuse.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract Voting is EIP712 {
    mapping(address => uint256) public nonces;
    mapping(address => bool) public hasVoted;
    mapping(uint256 => uint256) public votes;
    
    constructor() EIP712("Voting", "1") {}
    
    function castVoteBySig(address voter, uint256 candidate, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        require(nonce == nonces[voter], "invalid nonce");
        
        bytes32 structHash = keccak256(abi.encode(keccak256("Vote(address voter,uint256 candidate,uint256 nonce,uint256 deadline)"), voter, candidate, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = ECDSA.recover(digest, v, r, s);
        require(recovered == voter, "invalid sig");
        
        nonces[voter] = nonce + 1; // @audit nonce consumed before effect
        votes[candidate] += 1;
        hasVoted[voter] = true;
    }
}
```

EIP-712 domain separator binds signature to chain and contract; nonce is checked and incremented atomically before state change; deadline prevents stale signatures.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
