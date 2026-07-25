# Pause

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Pause**
Pause mechanisms (OpenZeppelin Pausable, custom whenPaused/whenNotPaused modifiers) are critical safety valves. Three recurring flaw patterns appear in audits:

1. 1/64 Gas Rule abuse: A try/catch around an external call (e.g., token.mint()) catches Out-of-Gas errors. An attacker forwards exactly 63/64 of the gas limit, forcing the call to OOG while the catch block executes _pause(), permanently halting the system.

2. Invalid pause-state validation: Using a sentinel value like `auction.tokenId == 0` to detect "first auction" or "uninitialized" state is unsafe when 0 is a valid tokenId. This causes re-initialization on unpause, overwriting active auction state and orphaning NFTs/bids.

3. Missing pause guards on state-changing functions: Functions that mutate protocol state (removeFollower, transfer, mint, burn, etc.) omit the whenNotPaused modifier, allowing disallowed operations during a pause. The pause flag is checked in some entry points but not others, creating inconsistent enforcement.

Auditors must verify: (a) no catch-all error handling triggers pause, (b) pause/unpause logic uses explicit boolean flags not sentinel values, (c) every external/write function has the correct pause modifier, (d) unpause cannot be front-run or re-entered to corrupt state.

### Detection Checks

1. Check that no try/catch block catches generic Error or Panic and calls _pause() in the catch clause — this enables 1/64 gas griefing.
2. Verify that unpause() does not rely on sentinel values (tokenId == 0, totalSupply == 0, etc.) to decide whether to re-initialize state; use an explicit initialized boolean or version counter.
3. Confirm every external/public function that writes state (mint, burn, transfer, updateSettings, removeFollower, claim, settle, etc.) has either whenNotPaused or whenPaused modifier matching the intended pause semantics.
4. Ensure _pause() and _unpause() are internal and only callable via access-controlled external functions (onlyOwner, onlyRole, onlyGovernance).
5. Check that pause/unpause events (Paused, Unpaused) are emitted with the correct account (msg.sender) for off-chain monitoring.
6. Validate that unpause() cannot be front-run: if unpause triggers automatic state transitions (e.g., _createAuction), those transitions must be idempotent or guarded against re-entry.
7. Verify that view/pure functions do not incorrectly revert when paused unless they are explicitly gated (some protocols allow reads during pause).
8. Confirm the contract has a recovery path: if pause is permanent (no unpause role), document as centralization risk; if unpause exists, ensure it cannot be blocked by a stuck state variable.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract FlawedAuction is ERC721, Pausable {
    struct Auction {
        uint256 tokenId;
        uint40 startTime;
        uint40 endTime;
        uint256 highestBid;
        address highestBidder;
        bool settled;
    }
    Auction public auction;
    address public treasury;

    constructor() ERC721("Auction", "AUC") {
        treasury = msg.sender;
    }

    function _createAuction() internal {
        try this.mint(msg.sender) returns (uint256 tokenId) { // self-mint for demo
            auction.tokenId = tokenId;
            auction.startTime = uint40(block.timestamp);
            auction.endTime = uint40(block.timestamp + 3600);
            auction.highestBid = 0;
            auction.highestBidder = address(0);
            auction.settled = false;
        } catch Error(string memory) {
            _pause(); // @audit 1/64 gas griefing: catch-all pauses contract
        }
    }

    function unpause() external onlyOwner {
        _unpause();
        if (auction.tokenId == 0) { // @audit invalid validation: tokenId 0 is valid
            transferOwnership(treasury);
            _createAuction();
        } else if (auction.settled) {
            _createAuction();
        }
    }

    function removeFollower(uint256 tokenId) external {
        // @audit missing whenNotPaused modifier
        _burn(tokenId);
    }
}
```

The contract exhibits all three flaw patterns: (1) try/catch around mint catches OOG and calls _pause(), enabling 1/64 gas griefing; (2) unpause uses auction.tokenId == 0 as sentinel, but tokenId 0 is a valid ERC721 token, causing re-initialization that overwrites active auction; (3) removeFollower lacks whenNotPaused, allowing burns during pause.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract FixedAuction is ERC721, Pausable, Ownable {
    struct Auction {
        uint256 tokenId;
        uint40 startTime;
        uint40 endTime;
        uint256 highestBid;
        address highestBidder;
        bool settled;
    }
    Auction public auction;
    bool public initialized = false;

    constructor() ERC721("Auction", "AUC") Ownable(msg.sender) {}

    function _createAuction() internal {
        uint256 tokenId = _mint(msg.sender); // no try/catch, revert on failure
        auction.tokenId = tokenId;
        auction.startTime = uint40(block.timestamp);
        auction.endTime = uint40(block.timestamp + 3600);
        auction.highestBid = 0;
        auction.highestBidder = address(0);
        auction.settled = false;
    }

    function unpause() external onlyOwner {
        _unpause();
        if (!initialized) {
            initialized = true;
            transferOwnership(treasury);
            _createAuction();
        } else if (auction.settled) {
            _createAuction();
        }
    }

    function removeFollower(uint256 tokenId) external whenNotPaused {
        _burn(tokenId);
    }
}
```

Fixes: (1) removed try/catch, let mint revert naturally so OOG bubbles up; (2) replaced tokenId == 0 sentinel with explicit initialized boolean; (3) added whenNotPaused to removeFollower.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
