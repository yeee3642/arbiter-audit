# Replay Attack

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Replay Attack**
A replay attack occurs when an attacker captures a valid signed message or transaction and re-submits it to execute the same action again. In Solidity, this typically manifests in EIP-712 signature schemes where the signed digest lacks a nonce, chain ID, or contract address in the domain separator, allowing signatures to be reused across transactions or even across different chains. The vulnerability arises when the contract verifies a signature but does not track whether that specific digest (or its underlying nonce) has already been consumed. Proper defenses include: (1) a strictly incrementing per-signer nonce that is checked and marked used atomically with signature verification, (2) inclusion of `block.chainid` and `address(this)` in the EIP-712 domain separator to prevent cross-chain and cross-contract replay, and (3) ensuring the nonce is consumed only after the signature is validated as authentic and authorized, not before.

### Detection Checks

1. Signature verification (ecrecover or ECDSA.recover) occurs without a prior check that the associated nonce or message hash has not been used before.
2. A nonce or message hash is marked as consumed (e.g., via a mapping update) before the signature validity and signer authorization are confirmed, allowing a failed verification to still burn the nonce.
3. The EIP-712 domain separator omits `block.chainid` or `address(this)`, enabling signatures to be replayed on a different chain or a different contract instance.
4. The signed payload does not include a nonce, timestamp, or deadline, making every signed message reusable indefinitely.
5. A `nonce` mapping is read to build the digest but never incremented or deleted after successful execution, so the same nonce value remains valid for future replays.
6. The contract uses a global nonce instead of a per-signer nonce, allowing one user's signed message to block or replay another user's action if nonces collide.
7. Signature verification logic is split across multiple internal calls where the nonce consumption happens in a different call frame than the ecrecover, creating a window for reentrancy or state inconsistency.
8. The contract accepts signatures generated off-chain without enforcing an expiration deadline (e.g., `validAfter` / `validBefore` timestamps), permitting indefinite replay.

### Examples

#### Example 1: Incorrect Example

```solidity
contract ReplayVulnerable {
    mapping(address => uint256) public nonces;
    
    function execute(bytes calldata data, uint8 v, bytes32 r, bytes32 s) external {
        uint256 nonce = nonces[msg.sender];
        bytes32 digest = keccak256(abi.encodePacked(data, nonce));
        address signer = ecrecover(digest, v, r, s);
        require(signer == msg.sender, "Invalid signature");
        nonces[msg.sender] = nonce + 1;
        (bool success, ) = msg.sender.call(data);
        require(success, "Call failed");
    }
}
```

The nonce is included in the digest but incremented after the external call; a reentrant call can replay the same nonce before the increment takes effect.

#### Example 2: Correct Example

```solidity
contract ReplayFixed {
    mapping(address => uint256) public nonces;
    
    function execute(bytes calldata data, uint8 v, bytes32 r, bytes32 s) external {
        uint256 nonce = nonces[msg.sender];
        bytes32 digest = keccak256(abi.encodePacked(data, nonce, address(this), block.chainid));
        address signer = ecrecover(digest, v, r, s);
        require(signer == msg.sender, "Invalid signature");
        nonces[msg.sender] = nonce + 1;
        (bool success, ) = msg.sender.call(data);
        require(success, "Call failed");
    }
}
```

The digest binds the nonce, contract address, and chain ID; the nonce is incremented atomically after signature validation and before any external call.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
