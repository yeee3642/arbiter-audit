# Bridge-Invalid Validation

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Bridge-Invalid Validation**
Bridge contracts facilitate cross-chain asset transfers by locking or burning tokens on the source chain and minting or releasing them on the destination chain after verifying a proof (e.g., Merkle proof, light client header, or validator signatures). A critical vulnerability arises when the bridge fails to validate the proof's authenticity, freshness, or correspondence to the intended transaction. For example, a bridge may accept a proof for a different recipient, a different amount, or a replayed message from a previous deposit. Without strict validation of the message payload (nonce, chain IDs, sender, recipient, amount, token), an attacker can forge or replay proofs to drain locked funds. Additionally, bridges that rely on off-chain relayers must enforce that the relayer cannot modify calldata after the proof is generated, and that the proof commits to the exact execution parameters on the destination chain.

### Detection Checks

1. Verify that deposit() or lock() emits an event with a unique nonce, sender, recipient, token, amount, and destination chain ID, and that this event data is exactly what the proof commits to.
2. Ensure the verifyProof() or processMessage() function checks that the proof's message hash matches keccak256(abi.encode(nonce, sender, recipient, token, amount, destChainId, payload)) and rejects any mismatch.
3. Confirm that the bridge maintains a processedNonces mapping (or Merkle root of processed messages) and reverts if a nonce is reused, preventing replay attacks across chains.
4. Check that the validator set or light client header used for verification is current (e.g., block number or timestamp within a challenge period) and that stale validator sets cannot approve new messages.
5. Validate that the recipient address on the destination chain cannot be overridden by the relayer; the proof must bind the recipient immutably.
6. Ensure that the token and amount in the proof match the locked/burned assets on the source chain, and that the bridge does not allow minting of arbitrary tokens or amounts.
7. Verify that the bridge enforces a minimum finality delay (e.g., waiting for N block confirmations or a challenge window) before accepting a proof, preventing reorg-based double spends.
8. Confirm that only the designated validator set, light client, or ZK verifier contract can call the mint/release function, and that access control cannot be bypassed via delegatecall or fallback functions.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBridge {
    mapping(bytes32 => bool) public processed;
    address public token;
    
    event Deposit(bytes32 indexed nonce, address indexed sender, address indexed recipient, address token, uint256 amount, uint256 destChainId);
    
    function deposit(address _recipient, uint256 _amount, uint256 _destChainId) external {
        bytes32 nonce = keccak256(abi.encodePacked(msg.sender, block.number));
        IERC20(token).transferFrom(msg.sender, address(this), _amount);
        emit Deposit(nonce, msg.sender, _recipient, token, _amount, _destChainId);
    }
    
    // @audit missing validation: no check that proof matches the original deposit event data
    // @audit no nonce replay protection
    // @audit relayer can specify arbitrary recipient and amount
    function processMessage(bytes32 _nonce, address _recipient, address _token, uint256 _amount, bytes calldata _proof) external {
        require(!processed[_nonce], "already processed");
        processed[_nonce] = true;
        IERC20(_token).mint(_recipient, _amount); // @audit mints arbitrary token/amount
    }
}
```

The bridge accepts arbitrary recipient, token, and amount in processMessage without verifying they match the original deposit event; the nonce is not derived from deposit parameters, enabling replay and forgery.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureBridge {
    mapping(bytes32 => bool) public processed;
    address public immutable token;
    uint256 public immutable destChainId;
    bytes32 public immutable domainSeparator;
    
    event Deposit(bytes32 indexed messageHash, address indexed sender, address indexed recipient, address token, uint256 amount, uint256 destChainId, uint256 nonce);
    
    constructor(address _token, uint256 _destChainId, bytes32 _domainSeparator) {
        token = _token;
        destChainId = _destChainId;
        domainSeparator = _domainSeparator;
    }
    
    function deposit(address _recipient, uint256 _amount, uint256 _nonce) external {
        bytes32 messageHash = keccak256(abi.encode(
            _nonce, msg.sender, _recipient, token, _amount, destChainId, ""
        ));
        IERC20(token).transferFrom(msg.sender, address(this), _amount);
        emit Deposit(messageHash, msg.sender, _recipient, token, _amount, destChainId, _nonce);
    }
    
    // @audit verifies proof commits to exact deposit parameters via messageHash
    // @audit enforces nonce uniqueness
    // @audit only trusted verifier can call
    function processMessage(
        uint256 _nonce,
        address _sender,
        address _recipient,
        address _token,
        uint256 _amount,
        uint256 _destChainId,
        bytes calldata _proof
    ) external {
        bytes32 messageHash = keccak256(abi.encode(
            _nonce, _sender, _recipient, _token, _amount, _destChainId, ""
        ));
        require(!processed[messageHash], "replay");
        require(_token == token && _destChainId == destChainId, "mismatch");
        require(IVerifier(verifier).verifyProof(messageHash, _proof), "invalid proof");
        processed[messageHash] = true;
        IERC20(token).mint(_recipient, _amount);
    }
}
```

The secure bridge binds all deposit parameters into a messageHash, verifies the proof commits to that exact hash, checks token and chain ID match, and uses the messageHash as the replay protection key.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
