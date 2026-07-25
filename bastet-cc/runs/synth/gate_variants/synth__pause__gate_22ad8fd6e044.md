# Pause

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Pause**
Pause mechanisms (Pausable, whenPaused, whenNotPaused) guard critical state transitions. Flaws arise when: (1) a catch-all try/catch swallows Out-of-Gas errors (EIP-150 63/64 rule) and triggers _pause() on mint failure, letting an attacker force a pause by starving gas; (2) pause/unpause logic uses sentinel values like tokenId == 0 to detect "first auction", but tokenId 0 can be a valid active auction, causing re-initialization that overwrites state and orphans NFTs/bids; (3) ownership checks for paused-state recovery read from deactivated vaults (vaults[owner] == false) and call IVault(owner).ownerOf(tokenId), which reverts or returns stale data, permanently locking leftover balances. Correct designs must: avoid catch-all error handling around external calls that can be gas-griefed; use explicit boolean flags (e.g., auctionInitialized) instead of sentinel token IDs; and ensure recovery paths validate vault activation before delegating ownership queries.

### Detection Checks

1. try/catch around external calls (mint, transfer, etc.) catches all errors including Out-of-Gas and calls _pause() in the catch block, enabling gas-griefing pause attacks
2. unpause() or recovery logic uses tokenId == 0 (or similar sentinel) to detect first initialization, but tokenId 0 is a valid minted token ID
3. pause/unpause state transitions lack reentrancy guards or allow re-entry during state flip
4. functions that must be blocked when paused lack whenNotPaused modifier (or equivalent manual require(!paused()))
5. functions that must be allowed when paused lack whenPaused modifier, or pause modifier logic is inverted
6. owner/admin can call pause/unpause without timelock or multisig, enabling centralized rug-pull or accidental permanent lock
7. recovery/withdrawal functions during paused state read ownership from deactivated/disabled components (vaults[owner] == false) without guarding the delegate call
8. pause state variable is not immutable after finalization, allowing indefinite toggling with no recovery mechanism

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
    
    constructor(address _treasury) ERC721("Auction", "AUC") {
        treasury = _treasury;
    }

    function _createAuction() internal {
        try this.mint(msg.sender) returns (uint256 tokenId) {
            auction.tokenId = tokenId;
            auction.startTime = uint40(block.timestamp);
            auction.endTime = uint40(block.timestamp + 3600);
            auction.highestBid = 0;
            auction.highestBidder = address(0);
            auction.settled = false;
        } catch Error(string memory) {
            _pause(); // @audit catches OOG, attacker can force pause via 63/64 rule
        }
    }

    function unpause() external onlyOwner {
        _unpause();
        if (auction.tokenId == 0) { // @audit tokenId 0 can be valid active auction
            transferOwnership(treasury);
            _createAuction();
        } else if (auction.settled) {
            _createAuction();
        }
    }

    function withdrawLeftover(uint256 tokenId) external whenPaused {
        address owner = ownerOf(tokenId);
        if (vaults[owner]) { // @audit vaults mapping not defined, but pattern matches evidence
            owner = IVault(owner).ownerOf(tokenId); // @audit reverts if vault deactivated
        }
        require(owner == msg.sender, "Unauthorized");
        // ... withdraw logic
    }

    mapping(address => bool) public vaults;
    interface IVault { function ownerOf(uint256) external view returns (address); }
}
```

The catch-all in _createAuction() lets an attacker force a pause via gas griefing; unpause() uses tokenId == 0 as first-auction sentinel but tokenId 0 is valid; withdrawLeftover() delegates to deactivated vaults without checking activation state, locking funds.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract FixedAuction is ERC721, Pausable {
    struct Auction {
        uint256 tokenId;
        uint40 startTime;
        uint40 endTime;
        uint256 highestBid;
        address highestBidder;
        bool settled;
    }
    Auction public auction;
    bool public auctionInitialized;
    address public treasury;
    
    constructor(address _treasury) ERC721("Auction", "AUC") {
        treasury = _treasury;
    }

    function _createAuction() internal {
        uint256 tokenId = _mint(msg.sender); // @audit no try/catch, revert propagates
        auction.tokenId = tokenId;
        auction.startTime = uint40(block.timestamp);
        auction.endTime = uint40(block.timestamp + 3600);
        auction.highestBid = 0;
        auction.highestBidder = address(0);
        auction.settled = false;
        auctionInitialized = true;
    }

    function unpause() external onlyOwner {
        _unpause();
        if (!auctionInitialized) { // @audit explicit boolean flag, not sentinel
            transferOwnership(treasury);
            _createAuction();
        } else if (auction.settled) {
            _createAuction();
        }
    }

    function withdrawLeftover(uint256 tokenId) external whenPaused {
        address owner = ownerOf(tokenId);
        if (vaults[owner] && IVault(owner).isActive()) { // @audit check vault active before delegate
            owner = IVault(owner).ownerOf(tokenId);
        }
        require(owner == msg.sender, "Unauthorized");
        // ... withdraw logic
    }

    mapping(address => bool) public vaults;
    interface IVault {
        function ownerOf(uint256) external view returns (address);
        function isActive() external view returns (bool);
    }
}
```

Removes try/catch so OOG reverts instead of triggering pause; uses auctionInitialized boolean instead of tokenId == 0 sentinel; adds isActive() check before delegating to vault in paused withdrawal.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
