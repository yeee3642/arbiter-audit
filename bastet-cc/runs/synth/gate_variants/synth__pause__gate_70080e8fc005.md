# Pause-Bypassable Pause Logic

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Pause-Bypassable Pause Logic**
Pause mechanisms (OpenZeppelin Pausable, custom whenPaused/whenNotPaused modifiers) are intended to halt sensitive operations during emergencies. A bypass occurs when state-changing functions that should be gated by the pause flag omit the modifier, allowing users to execute disallowed actions while the system is paused. Common patterns include: (1) multiple entry points to the same logical operation where only one path is guarded (e.g., unfollow() guarded but removeFollower() and burn() are not), (2) admin-only functions that assume the pause flag is checked elsewhere, and (3) withdrawal or claim functions that rely on an "active" flag instead of the global pause state, causing funds to become stuck when the contract is paused or deactivated. The pause flag is typically a single boolean (paused) toggled by a privileged role; any function that mutates protocol-critical state must explicitly enforce whenNotPaused or equivalent logic, otherwise the pause is ineffective.

### Detection Checks

1. Identify all functions that modify protocol-critical state (transfers, mints, burns, role changes, parameter updates) and verify each is annotated with whenNotPaused or an equivalent pause check.
2. Check for alternative entry points to the same logical operation (e.g., removeFollower, burn, transferFrom) that lack the pause modifier while the primary entry point (e.g., unfollow) has it.
3. Verify that pause/unpause functions are restricted to the correct privileged role (onlyOwner, onlyPauser, onlyAdmin) and cannot be called by arbitrary users.
4. Ensure the pause state is a single source of truth; avoid duplicate flags like "active", "deactivated", "paused" that diverge and cause inconsistent gating.
5. Confirm that view/pure functions do not incorrectly rely on pause state for access control (they cannot enforce it).
6. Check that unpause does not silently re-enable functions that were individually disabled or that have separate deactivation logic.
7. Validate that emergency withdrawal or rescue functions are callable when paused (whenPaused) if intended, or are also blocked if not intended.
8. Look for reentrancy or callback paths that could mutate state while paused by invoking unguarded external calls.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract FollowNFT is ERC721, Ownable, Pausable {
    mapping(uint256 => address) public followers;
    mapping(address => uint256) public followCount;

    constructor() ERC721("FollowNFT", "FOLLOW") {}

    function follow(address to) external whenNotPaused {
        uint256 tokenId = totalSupply() + 1;
        _mint(to, tokenId);
        followers[tokenId] = msg.sender;
        followCount[msg.sender]++;
    }

    function unfollow(uint256 tokenId) external whenNotPaused {
        require(followers[tokenId] == msg.sender, "Not follower");
        _burn(tokenId);
        followCount[msg.sender]--;
        delete followers[tokenId];
    }

    // @audit missing whenNotPaused - bypasses pause
    function removeFollower(uint256 tokenId) external {
        require(followers[tokenId] == msg.sender, "Not follower");
        _burn(tokenId);
        followCount[msg.sender]--;
        delete followers[tokenId];
    }

    // @audit missing whenNotPaused - bypasses pause
    function burn(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender, "Not owner");
        _burn(tokenId);
        followCount[msg.sender]--;
        delete followers[tokenId];
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
```

unfollow() is correctly guarded with whenNotPaused, but removeFollower() and burn() omit the modifier, allowing users to unfollow/burn while the system is paused.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract FollowNFT is ERC721, Ownable, Pausable {
    mapping(uint256 => address) public followers;
    mapping(address => uint256) public followCount;

    constructor() ERC721("FollowNFT", "FOLLOW") {}

    function follow(address to) external whenNotPaused {
        uint256 tokenId = totalSupply() + 1;
        _mint(to, tokenId);
        followers[tokenId] = msg.sender;
        followCount[msg.sender]++;
    }

    function unfollow(uint256 tokenId) external whenNotPaused {
        require(followers[tokenId] == msg.sender, "Not follower");
        _burn(tokenId);
        followCount[msg.sender]--;
        delete followers[tokenId];
    }

    function removeFollower(uint256 tokenId) external whenNotPaused {
        require(followers[tokenId] == msg.sender, "Not follower");
        _burn(tokenId);
        followCount[msg.sender]--;
        delete followers[tokenId];
    }

    function burn(uint256 tokenId) external whenNotPaused {
        require(ownerOf(tokenId) == msg.sender, "Not owner");
        _burn(tokenId);
        followCount[msg.sender]--;
        delete followers[tokenId];
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
```

All state-changing entry points (unfollow, removeFollower, burn) now consistently enforce whenNotPaused, eliminating the bypass.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
