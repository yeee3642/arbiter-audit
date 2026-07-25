# EIP712-StructuredDataHashingViolations

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**EIP712-StructuredDataHashingViolations**
EIP-712 requires a precise two-step hashing process for structured data: first compute the hash of each dynamic field (bytes, string, arrays) using keccak256(abi.encode(...)), then encode the typeHash followed by those field hashes (and static fields directly) into a final keccak256(abi.encode(typeHash, field1Hash, field2Hash, ...)). Common violations include (1) flattening everything into a single abi.encode inside one keccak256, which produces a different digest than the standard; (2) using abi.encodePacked on dynamic arrays instead of hashing them separately; (3) omitting required domain separator fields (name, version, chainId, verifyingContract) or mixing domain separator into the struct hash incorrectly; (4) failing to include a strictly incrementing nonce or deadline in the signed payload, enabling replay across transactions or contracts. The digest passed to ecrecover must be keccak256("\x19\x01" || domainSeparator || structHash). Any deviation causes legitimate signatures to fail or forged/replayed signatures to verify.

### Detection Checks

1. Verify that struct hashing uses two-layer encoding: keccak256(abi.encode(typeHash, keccak256(abi.encode(dynamicField1)), keccak256(abi.encode(dynamicField2)), staticField1, ...)) not a single keccak256(abi.encode(typeHash, dynamicField1, dynamicField2, ...)).
2. Confirm dynamic arrays (address[], uint256[], bytes[]) are hashed via keccak256(abi.encode(array)) before being included in the struct hash; abi.encodePacked(array) inside the outer encode is non-compliant.
3. Check that the domain separator is built exactly as keccak256(abi.encode(DOMAIN_TYPEHASH, name, version, chainId, verifyingContract)) with all fields present and correctly typed (bytes32 for name/version, uint256 for chainId, address for verifyingContract).
4. Ensure the final digest for ecrecover is keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)) -- no extra fields, no missing prefix.
5. Validate that every signed payload includes a nonce (incremented per signer) or a deadline (block.timestamp bound) that is checked during verification to prevent replay.
6. Confirm nonce state is updated atomically with signature verification (nonce incremented before or during the same call) and not read-only.
7. Check that the signer address recovered from the signature matches the expected authority (msg.sender, owner, or a role) and is not left unvalidated.
8. Verify that typeHash constants match the exact EIP-712 struct definition (field names, types, order) used off-chain; any mismatch causes digest mismatch.

### Examples

#### Example 1: Incorrect Example

```solidity
contract BurnVerifier {
    bytes32 constant BURN_TYPEHASH = keccak256("Burn(uint256 tokenId,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) nonces;
    
    function validateBurnSignature(bytes calldata sig, uint256 tokenId, uint256 nonce, uint256 deadline) external {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(BURN_TYPEHASH, tokenId, nonce, deadline))
        ));
        address signer = ECDSA.recover(digest, sig);
        require(signer == owner, "invalid signer");
        nonces[signer] = nonce + 1;
    }
}
```

The struct hash incorrectly uses abi.encodePacked inside a single keccak256 with the typeHash and all fields flattened, violating EIP-712's required two-step hashing for dynamic types (none here but pattern is wrong) and omitting domain separator construction.

#### Example 2: Correct Example

```solidity
contract BurnVerifier {
    bytes32 constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant BURN_TYPEHASH = keccak256("Burn(uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 DOMAIN_SEPARATOR;
    mapping(address => uint256) nonces;
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(DOMAIN_TYPEHASH, "MyApp", "1", block.chainid, address(this)));
    }
    
    function validateBurnSignature(bytes calldata sig, uint256 tokenId, uint256 nonce, uint256 deadline) external {
        require(nonce == nonces[msg.sender], "invalid nonce");
        require(deadline >= block.timestamp, "expired");
        bytes32 structHash = keccak256(abi.encode(BURN_TYPEHASH, tokenId, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(digest, sig);
        require(signer == msg.sender, "invalid signer");
        nonces[msg.sender]++;
    }
}
```

Correctly constructs domain separator, uses two-layer struct hashing with abi.encode, includes nonce and deadline checks, increments nonce atomically, and verifies signer matches msg.sender.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
