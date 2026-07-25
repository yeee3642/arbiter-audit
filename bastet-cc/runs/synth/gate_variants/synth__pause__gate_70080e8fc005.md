# Pause-Bypassable Pause Controls

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Pause-Bypassable Pause Controls**
Contracts using OpenZeppelin's Pausable pattern or custom pause logic rely on `whenNotPaused` / `whenPaused` modifiers to gate critical operations. A bypass occurs when state-changing functions that should be blocked during a pause lack the modifier, or when an alternative code path (e.g., a different external function, internal helper, or fallback) reaches the same state transition without passing through the guarded entry point. The result is that privileged pause/unpause roles cannot actually halt the system: users continue to mint, burn, transfer, or withdraw while `paused() == true`. A second failure mode is a permanent lock — `unpause` is gated behind a role that can no longer be called (e.g., the only account with `UNPAUSER_ROLE` is a contract that self-destructed), or the pause flag is written to storage in a way that cannot be flipped back.

### Detection Checks

1. Every external / public function that mutates protocol-critical state (mint, burn, transfer, deposit, withdraw, claim, follow, unfollow, setApprovalForAll, etc.) either has `whenNotPaused` or an explicit `require(!paused(), "Pausable: paused")` at the top of the function body.
2. No internal helper (_burn, _mint, _transfer, _withdraw, _unfollow, etc.) that performs the actual state change is callable from an unguarded external entry point; trace all call paths to each state-changing internal function.
3. The `pause()` and `unpause()` functions themselves are protected by the correct access-control modifier (e.g., `onlyPauser`, `onlyRole(PAUSER_ROLE)`) and there is no path to call them without authorization.
4. There exists at least one viable path to call `unpause()` after a pause — i.e., the unpauser role is not assigned to an address that can be permanently frozen, a contract without `receive()`/`fallback()`, or an EOA that could be lost; preferably the role is held by a timelock or multisig.
5. State variables that control the pause flag (`_paused`, `paused`, `isPaused`) are not written directly anywhere except inside `pause()` / `unpause()`; no `assembly { sstore(...) }` or delegatecall proxy storage collision can flip the flag.
6. If the contract inherits `PausableUpgradeable` / `Pausable`, the initializer (`__Pausable_init`, `initialize`) sets the initial pause state explicitly and cannot be re-entered to flip it.
7. Functions that read `paused()` to decide logic (e.g., `withdrawLeftoverBalances`, `deactivateVault`) must behave correctly when `paused() == true` — they should either revert or follow a documented fallback that does not leave user funds stuck.
8. Events `Paused(address account)` and `Unpaused(address account)` are emitted exactly once per state transition and the `account` matches `msg.sender` (or the authorized role bearer) to enable off-chain monitoring.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract FollowNFT is ERC721, AccessControl, Pausable {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    mapping(uint256 => address) public followers;
    
    constructor() ERC721("FollowNFT", "FOLLOW") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
    }
    
    function follow(address to) external whenNotPaused {
        uint256 tokenId = totalSupply();
        _mint(to, tokenId);
        followers[tokenId] = msg.sender;
    }
    
    // @audit missing whenNotPaused — bypasses pause
    function removeFollower(uint256 tokenId) external {
        require(followers[tokenId] == msg.sender);
        _burn(tokenId);
        delete followers[tokenId];
    }
    
    // @audit missing whenNotPaused — bypasses pause
    function burn(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender);
        _burn(tokenId);
        delete followers[tokenId];
    }
    
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }
    
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}
```

removeFollower() and burn() mutate critical state (burn tokens, delete mappings) but lack whenNotPaused, so users can unfollow/burn while the system is paused.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract FollowNFT is ERC721, AccessControl, Pausable {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    mapping(uint256 => address) public followers;
    
    constructor() ERC721("FollowNFT", "FOLLOW") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
    }
    
    function follow(address to) external whenNotPaused {
        uint256 tokenId = totalSupply();
        _mint(to, tokenId);
        followers[tokenId] = msg.sender;
    }
    
    function removeFollower(uint256 tokenId) external whenNotPaused {
        require(followers[tokenId] == msg.sender);
        _burn(tokenId);
        delete followers[tokenId];
    }
    
    function burn(uint256 tokenId) external whenNotPaused {
        require(ownerOf(tokenId) == msg.sender);
        _burn(tokenId);
        delete followers[tokenId];
    }
    
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }
    
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}
```

All state-changing external functions now carry whenNotPaused, so pause() actually halts follow, removeFollower, and burn.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
