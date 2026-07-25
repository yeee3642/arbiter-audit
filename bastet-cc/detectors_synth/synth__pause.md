---
id: synth__pause
name: "Pause"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Pause"]
routing_hints: ["pause", "unpause", "whenNotPaused", "whenPaused", "Pausable", "ownerOf", "tokenId"]
required_hints: []
prompt_chars: 6940
synthesized: true
gated: false
synth_provenance: {"train_findings": ["221", "208", "350", "301"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 29, "hints_rejected": 26, "hint_coverage": 1.0, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 0.667, "fp": 0.167, "folds": 3, "repaired": false}}
---

# Pause

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Pause**
Pause mechanisms (Pausable, whenPaused/whenNotPaused modifiers) are critical safety controls that halt contract operations during emergencies. Flaws arise when: (1) pause checks are missing from state-changing functions, allowing operations to proceed while paused; (2) pause/unpause logic uses unreliable state conditions (e.g., tokenId == 0) that can be true during valid operations, causing re-initialization or state corruption; (3) external calls inside try/catch blocks catch Out-of-Gas errors (EIP-150 63/64 rule), letting attackers force a pause by starving the sub-call of gas; (4) ownership or authorization checks depend on external contracts that may be deactivated or return stale data when paused, blocking legitimate recovery actions like withdrawing leftover balances; (5) unpause transitions automatically trigger sensitive operations (e.g., starting auctions, transferring ownership) without validating preconditions, leading to invariant violations. Auditors must verify every state-mutating entry point has the correct pause modifier, that pause/unpause guards are idempotent and based on dedicated boolean flags, that try/catch does not swallow OOG errors into pause logic, and that recovery paths remain executable when paused.

### Detection Checks

1. Every external/public state-changing function (except pause/unpause themselves) uses whenNotPaused or whenPaused modifier consistently with its intended behavior during a pause.
2. No try/catch block wraps an external call and invokes _pause() in the catch clause, because EIP-150 63/64 gas rule lets an attacker force an Out-of-Gas error that is caught and triggers an unintended pause.
3. Pause/unpause state transitions do not rely on mutable data fields (e.g., tokenId == 0, auction.settled) as proxies for "first run" or "safe to resume"; a dedicated boolean flag (paused) must be the sole source of truth.
4. Functions that read ownership or authorization from external contracts (e.g., IVault(owner).ownerOf) include a fallback or validation when the external contract is deactivated (vaults[owner] == false) so recovery actions like withdrawLeftoverBalances do not revert incorrectly.
5. unpause() does not automatically execute high-impact operations (transferOwnership, _createAuction) without explicit pre-condition checks (e.g., auction not already active, ownership transfer only once).
6. State-changing internal functions called by external entry points (e.g., _unfollowIfHasFollower) are either protected by the same pause modifier or documented as intentionally pause-bypassing with a security review note.
7. Events (Paused, Unpaused) are emitted exactly once per state change and include the account that triggered the change, enabling off-chain monitoring and governance response.
8. The contract provides a governance-controlled or time-delayed unpause path; immediate unpause by a single key without timelock or multisig is flagged as centralization risk.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract FlawedAuction is Pausable, Ownable {
    IERC721 public token;
    uint256 public auctionTokenId;
    bool public auctionSettled;
    
    constructor(address _token) {
        token = IERC721(_token);
    }
    
    function _createAuction() internal {
        try token.mint() returns (uint256 tokenId) {
            auctionTokenId = tokenId;
            auctionSettled = false;
        } catch Error(string memory) {
            _pause(); // @audit catches OOG, attacker can force pause via 63/64 rule
        }
    }
    
    function unpause() external onlyOwner {
        _unpause();
        if (auctionTokenId == 0) { // @audit tokenId 0 can be valid active auction
            transferOwnership(0xDAO);
            _createAuction();
        } else if (auctionSettled) {
            _createAuction();
        }
    }
    
    function settleAuction() external whenNotPaused {
        auctionSettled = true;
    }
    
    // @audit missing whenNotPaused - can unfollow while paused
    function removeFollower(uint256 tokenId) external {
        _unfollowIfHasFollower(tokenId);
    }
    
    function _unfollowIfHasFollower(uint256 tokenId) internal {
        // ... unfollow logic
    }
}
```

The contract catches all errors from token.mint() including Out-of-Gas, allowing an attacker to force a pause via the 63/64 gas rule; unpause() uses auctionTokenId == 0 as a first-run check but tokenId 0 can be a valid active auction, causing re-initialization and ownership transfer; removeFollower lacks whenNotPaused modifier, permitting state changes while paused.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract FixedAuction is Pausable, Ownable {
    IERC721 public token;
    uint256 public auctionTokenId;
    bool public auctionSettled;
    bool public firstAuctionStarted;
    
    constructor(address _token) {
        token = IERC721(_token);
    }
    
    function _createAuction() internal {
        uint256 tokenId = token.mint(); // @audit no try/catch, OOG bubbles up
        auctionTokenId = tokenId;
        auctionSettled = false;
        firstAuctionStarted = true;
    }
    
    function unpause() external onlyOwner {
        _unpause();
        if (!firstAuctionStarted) { // @audit dedicated boolean flag
            transferOwnership(0xDAO);
            _createAuction();
        } else if (auctionSettled) {
            _createAuction();
        }
    }
    
    function settleAuction() external whenNotPaused {
        auctionSettled = true;
    }
    
    function removeFollower(uint256 tokenId) external whenNotPaused {
        _unfollowIfHasFollower(tokenId);
    }
    
    function _unfollowIfHasFollower(uint256 tokenId) internal {
        // ... unfollow logic
    }
}
```

Removes try/catch around mint so Out-of-Gas reverts the transaction instead of triggering pause; replaces auctionTokenId == 0 with a dedicated firstAuctionStarted boolean; adds whenNotPaused to removeFollower to block state changes while paused.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
