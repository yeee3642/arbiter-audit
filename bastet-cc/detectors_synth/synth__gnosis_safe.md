---
id: synth__gnosis_safe
name: "Gnosis Safe Extension Missing Authorization and Validation"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Gnosis safe"]
routing_hints: ["checkSignatures", "getOwners", "isOwner", "Enum.Operation", "checkAfterExecution", "checkTransaction", "enableModule", "fallbackHandler", "stopRent", "setGuard", "execTransactionFromModule", "Errors.GuardPolicy_UnauthorizedSelector", "_calculatePaymentProRata"]
required_hints: []
prompt_chars: 8137
synthesized: true
gated: true
synth_provenance: {"train_findings": ["465", "486"], "localization_rate": 1.0, "mode": "s2b", "hint_candidates": 28, "hints_rejected": 19, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 1.0, "fp": 0.0, "folds": 1, "repaired": false}}
---

# Gnosis Safe Extension Missing Authorization and Validation

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Gnosis Safe Extension Missing Authorization and Validation**
Gnosis Safe extensions (Guards, Modules, Handlers) integrate with the Safe's execTransaction flow and must enforce their own authorization because the Safe only checks the module's signature, not the parameters passed to it. A Guard's checkTransaction/checkAfterExecution must validate calldata, target, value, and operation type before approving execution; missing checks allow any owner to bypass the Guard's policy. Modules that expose enable/disable or configuration functions (e.g., setFallbackHandler, setGuard) must restrict callers to the Safe itself or authorized roles and validate the new address (non-zero, not a malicious contract, implements expected interface). Handlers that process asset transfers (ERC20, ERC721, ERC1155) must handle transfer failures gracefully: if a token reverts on transfer (blocklisted USDT, fee-on-transfer, non-standard ERC20), the rental/vesting/escrow state must not be left in an inconsistent state (NFT stuck, rental unclosable). Use try/catch or low-level calls with success checks, and revert the entire operation or provide a recovery path. State transitions (rental active -> stopped, module enabled -> disabled) must be atomic with external calls; updating state before an external call that can revert breaks invariants.

### Detection Checks

1. Guard checkTransaction/checkAfterExecution does not validate calldata selector, target address, value, or operation against an allowlist/denylist.
2. Module enable/disable function (e.g., setGuard, setFallbackHandler, enableModule) lacks onlyOwner/onlySafe modifier or does not verify msg.sender == address(this) when called via delegatecall.
3. Configuration setter (setFallbackHandler, setGuard, setModule) accepts address parameter without zero-address check, interface support check (ERC165), or validation that the address is a contract.
4. External token transfer in stopRent/closeRental/withdraw uses ERC20.transfer/ERC721.safeTransferFrom without try/catch or success boolean check, allowing a reverting transfer to brick the rental.
5. State variable (rental status, module enabled flag) is updated before the external call that can revert, violating checks-effects-interactions ordering.
6. Fallback handler execution path does not verify the handler implements IFallbackHandler or that the call succeeds, allowing arbitrary delegatecall to malicious code.
7. Module's processTransaction/execTransactionFromModule does not re-validate the Safe's nonce or threshold after the module's internal logic, enabling replay or threshold bypass.
8. Guard's checkAfterExecution does not verify post-execution state changes (e.g., balance deltas, storage slots) against expected invariants.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function ownerOf(uint256 tokenId) external view returns (address);
}

contract RentalGuard {
    address public safe;
    mapping(uint256 => address) public rentalNft; // rentalId -> nft
    mapping(uint256 => bool) public rentalActive;
    IERC20 public paymentToken;
    address public fallbackHandler;

    constructor(address _safe, address _paymentToken) {
        safe = _safe;
        paymentToken = IERC20(_paymentToken);
    }

    // @audit missing onlySafe/onlyOwner, no validation on _handler
    function setFallbackHandler(address _handler) external {
        fallbackHandler = _handler;
    }

    // @audit no validation of calldata, target, value, operation
    function checkTransaction(address to, uint256 value, bytes memory data, Enum.Operation op) external returns (bool) {
        return true;
    }

    function checkAfterExecution(address to, uint256 value, bytes memory data, Enum.Operation op, bool success) external returns (bool) {
        return true;
    }

    // @audit state updated before external call; transfer not wrapped in try/catch
    function stopRent(uint256 rentalId) external {
        require(rentalActive[rentalId], "not active");
        rentalActive[rentalId] = false; // state change before external call
        address nft = rentalNft[rentalId];
        IERC721(nft).safeTransferFrom(address(this), safe, rentalId); // can revert
        paymentToken.transfer(msg.sender, 100); // can revert, no success check
    }
}
```

The Guard lacks authorization on setFallbackHandler, performs no validation in checkTransaction/checkAfterExecution, updates rentalActive before external calls, and uses unchecked token transfers that can revert and leave the NFT stuck in the contract.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function ownerOf(uint256 tokenId) external view returns (address);
}
interface IFallbackHandler {
    function handlePayment(address from, uint256 amount) external;
}

contract RentalGuard {
    address public safe;
    mapping(uint256 => address) public rentalNft;
    mapping(uint256 => bool) public rentalActive;
    IERC20 public paymentToken;
    address public fallbackHandler;

    constructor(address _safe, address _paymentToken) {
        safe = _safe;
        paymentToken = IERC20(_paymentToken);
    }

    modifier onlySafe() {
        require(msg.sender == safe, "not safe");
        _;
    }

    function setFallbackHandler(address _handler) external onlySafe {
        require(_handler != address(0), "zero address");
        require(ERC165Checker.supportsInterface(_handler, type(IFallbackHandler).interfaceId), "invalid handler");
        fallbackHandler = _handler;
    }

    function checkTransaction(address to, uint256 value, bytes memory data, Enum.Operation op) external onlySafe returns (bool) {
        // validate calldata selector against allowlist
        bytes4 selector = bytes4(data[:4]);
        require(allowedSelectors[selector], "selector not allowed");
        require(to != address(0), "zero target");
        require(value == 0 || allowedValueTargets[to], "value not allowed");
        return true;
    }

    function checkAfterExecution(address to, uint256 value, bytes memory data, Enum.Operation op, bool success) external onlySafe returns (bool) {
        require(success, "execution failed");
        // verify post-state invariants
        return true;
    }

    function stopRent(uint256 rentalId) external onlySafe {
        require(rentalActive[rentalId], "not active");
        address nft = rentalNft[rentalId];
        // external calls first, then state change
        (bool nftOk, ) = address(nft).call(abi.encodeWithSelector(IERC721(nft).safeTransferFrom.selector, address(this), safe, rentalId));
        require(nftOk, "nft transfer failed");
        (bool payOk, ) = address(paymentToken).call(abi.encodeWithSelector(paymentToken.transfer.selector, msg.sender, 100));
        require(payOk, "payment transfer failed");
        rentalActive[rentalId] = false;
    }
}
```

The fixed Guard restricts setFallbackHandler to the Safe, validates the handler implements IFallbackHandler, enforces calldata/target/value checks in checkTransaction, verifies post-execution success, and performs external transfers before state updates with low-level calls that check success booleans.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
