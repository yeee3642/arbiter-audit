# EIP712-Signature-Verification-Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**EIP712-Signature-Verification-Flaws**
EIP-712 structured data signing requires a precise hashing pipeline: the domain separator (chainId, verifyingContract, name, version, salt) is hashed once; each struct type gets a typehash = keccak256("TypeName(type1 field1,type2 field2,...)"); struct instances are encoded as keccak256(abi.encode(typehash, keccak256(abi.encode(field1)), keccak256(abi.encode(field2)), ...)) with dynamic fields (bytes, string, arrays) recursively hashed before inclusion. The final digest is keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)). Common deviations include: (1) skipping the domain separator or using an incorrect one, (2) hashing typehash and raw parameters together in a single abi.encode instead of hashing each dynamic field first, (3) using abi.encodePacked on dynamic arrays/bytes instead of keccak256(abi.encode(...)), (4) omitting nonce or deadline fields enabling replay, (5) verifying against a stale or wrong verifyingContract address. These flaws let attackers replay signatures across chains/contracts, forge valid-looking signatures for unauthorized actions, or cause legitimate signatures to fail.

### Detection Checks

1. Verify the digest construction follows keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)) exactly; missing prefix or wrong concatenation order breaks compliance.
2. Confirm domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, name, version, chainId, verifyingContract, salt)) with all fields present; immutable verifyingContract must reflect current contract address, not a factory-stored stale address.
3. Ensure each struct typehash is computed as keccak256("TypeName(fieldType1 fieldName1,fieldType2 fieldName2,...)") matching the exact EIP-712 type string; field order and names must match the struct definition.
4. Check that dynamic fields (bytes, string, arrays) are hashed via keccak256(abi.encode(...)) before being passed to the struct abi.encode; abi.encodePacked on dynamic data violates the spec.
5. Validate that structHash = keccak256(abi.encode(typehash, hashedField1, hashedField2, ...)) where each hashedField is already a 32-byte keccak256 digest for dynamic types or the raw value for static types; do not abi.encode raw dynamic arrays alongside typehash.
6. Require a strictly incrementing nonce (or equivalent replay protection) included in the signed struct and checked/updated atomically during verification; missing or non-incrementing nonce enables replay.
7. Enforce a deadline/expiration timestamp inside the signed payload and reject signatures where deadline < block.timestamp; absent deadline allows indefinite replay.
8. Confirm ecrecover uses the correct digest and that the recovered address matches the expected signer; do not skip signature length/format validation (r,s,v or r,s,vs).

### Examples

#### Example 1: Incorrect Example

```solidity
contract BurnVerifier {
    bytes32 constant BURN_TYPEHASH = keccak256("Burn(uint256 tokenId,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) nonces;
    
    function validateBurnSignature(bytes calldata signature, uint256 tokenId, uint256 nonce, uint256 deadline) external {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(BURN_TYPEHASH, tokenId, nonce, deadline)) // WRONG: dynamic fields not pre-hashed, but here all static so ok; real flaw: missing domain separator in example 2
        ));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "INVALID_SIG");
        nonces[signer] = nonce + 1;
    }
}
```

The digest omits the domain separator entirely and hashes typehash with raw parameters in one abi.encode, violating the two-step struct hashing required by EIP-712.

#### Example 2: Correct Example

```solidity
contract BurnVerifier {
    bytes32 constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant BURN_TYPEHASH = keccak256("Burn(uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) nonces;
    
    constructor(string memory name, string memory version) {
        DOMAIN_SEPARATOR = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, address(this)));
    }
    
    function validateBurnSignature(bytes calldata signature, uint256 tokenId, uint256 deadline) external {
        uint256 nonce = nonces[msg.sender]++;
        require(deadline >= block.timestamp, "EXPIRED");
        bytes32 structHash = keccak256(abi.encode(BURN_TYPEHASH, tokenId, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(digest, signature);
        require(signer == msg.sender, "INVALID_SIGNER");
    }
}
```

Correctly builds domain separator once in constructor, hashes struct with typehash and static fields via abi.encode, prefixes with "\x19\x01", includes incrementing nonce and deadline, and verifies recovered signer matches caller.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
