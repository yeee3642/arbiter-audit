# ERC1155-Enumeration State Inconsistency

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC1155-Enumeration State Inconsistency**
ERC1155 enumeration extensions maintain two parallel data structures: a global `_allTokens` array tracking every tokenId with non-zero total supply, and per-owner `_ownedTokens` arrays tracking tokenIds each address holds. The invariants are: (1) a tokenId exists in `_allTokens` iff `_idTotalSupply[id] > 0`; (2) a tokenId exists in `_ownedTokens[owner]` iff `balanceOf(owner, id) > 0`. These invariants must hold after every mint, burn, and transfer. The standard pattern updates supply/balance first, then decides whether to add or remove from enumeration arrays based on the *post-update* value. If the check uses the pre-update value (e.g., `_idTotalSupply[id] == 0` before `+= amount`), a tokenId that already has supply will never be re-added to `_allTokens` after it was removed when supply hit zero. Conversely, if the code only checks `supply == 0` without verifying the tokenId is absent from `_allTokens`, a re-mint after a full burn creates a duplicate entry. For owner enumeration, the same logic applies using `balanceOf(to, id)` before the transfer increments it. Callbacks (`onERC1155Received`, `onERC1155BatchReceived`) must be invoked *after* all state updates (Checks-Effects-Interactions) to prevent reentrancy that could observe broken invariants.

### Detection Checks

1. In `_addTokenEnumeration` (mint path), the condition `_idTotalSupply[id] == 0` is evaluated *before* `_idTotalSupply[id] += amount`; it must be evaluated after the increment (or rewritten as `_idTotalSupply[id] == amount` post-increment) to correctly detect the first mint of a previously zero-supply token.
2. In `_addTokenEnumeration`, there is no guard ensuring `id` is not already present in `_allTokens` before calling `_addTokenToAllTokensEnumeration(id)`; a duplicate entry occurs if the token was burned to zero supply and later minted again.
3. In `_removeTokenEnumeration` (burn path), the condition `_idTotalSupply[id] == 0` is evaluated *before* `_idTotalSupply[id] -= amount`; it must be evaluated after the decrement (or rewritten as `_idTotalSupply[id] == amount` pre-decrement) to correctly detect when the last tokens are burned.
4. In `_removeTokenEnumeration`, there is no guard ensuring `id` is actually present in `_allTokens` before calling `_removeTokenFromAllTokensEnumeration(id)`; a missing entry causes an out-of-bounds or logic error.
5. Owner enumeration updates in both functions use `balanceOf(to, id) == 0` / `balanceOf(from, id) == 0` *before* the balance changes; the check must use the post-transfer balance (or compare against `amount`) to avoid missing additions/removals.
6. The internal helpers `_addTokenToAllTokensEnumeration`, `_removeTokenFromAllTokensEnumeration`, `_addTokenToOwnerEnumeration`, `_removeTokenFromOwnerEnumeration` do not validate that the tokenId is absent/present in the target array before inserting/removing, allowing duplicates or failed removals.
7. Callbacks (`onERC1155Received`, `onERC1155BatchReceived`) are invoked before enumeration state is fully updated, violating Checks-Effects-Interactions and enabling reentrancy that observes inconsistent enumeration arrays.
8. Functions that mint or burn (e.g., `mint`, `mintBatch`, `burn`, `burnBatch`, `_mint`, `_burn`) do not wrap the entire operation including enumeration updates in a `nonReentrant` modifier, leaving a window for reentrant calls to corrupt enumeration state.

### Examples

#### Example 1: Incorrect Example

```solidity
contract ERC1155EnumerableFlawed is ERC1155 {
    uint256[] private _allTokens;
    mapping(uint256 => uint256) private _idTotalSupply;
    mapping(address => uint256[]) private _ownedTokens;
    mapping(uint256 => mapping(address => uint256)) private _ownedTokenIndex;
    mapping(uint256 => uint256) private _allTokensIndex;

    function _addTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (from == address(0)) {
            if (_idTotalSupply[id] == 0) _addTokenToAllTokensEnumeration(id); // @audit pre-increment check
            _idTotalSupply[id] += amount;
        }
        if (to != address(0) && to != from) {
            if (balanceOf(to, id) == 0) _addTokenToOwnerEnumeration(to, id); // @audit pre-transfer check
        }
    }

    function _removeTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (to == address(0)) {
            if (_idTotalSupply[id] == 0) _removeTokenFromAllTokensEnumeration(id); // @audit pre-decrement check
            _idTotalSupply[id] -= amount;
        }
        if (from != address(0) && from != to) {
            if (balanceOf(from, id) == 0) _removeTokenFromOwnerEnumeration(from, id); // @audit pre-transfer check
        }
    }

    function _addTokenToAllTokensEnumeration(uint256 id) internal {
        _allTokensIndex[id] = _allTokens.length;
        _allTokens.push(id); // @audit no duplicate guard
    }

    function _removeTokenFromAllTokensEnumeration(uint256 id) internal {
        uint256 index = _allTokensIndex[id];
        uint256 last = _allTokens[_allTokens.length - 1];
        _allTokens[index] = last;
        _allTokensIndex[last] = index;
        _allTokens.pop(); // @audit no presence guard
    }

    function _addTokenToOwnerEnumeration(address account, uint256 id) internal {
        _ownedTokenIndex[id][account] = _ownedTokens[account].length;
        _ownedTokens[account].push(id); // @audit no duplicate guard
    }

    function _removeTokenFromOwnerEnumeration(address account, uint256 id) internal {
        uint256 index = _ownedTokenIndex[id][account];
        uint256 last = _ownedTokens[account][_ownedTokens[account].length - 1];
        _ownedTokens[account][index] = last;
        _ownedTokenIndex[id][account] = index;
        _ownedTokens[account].pop(); // @audit no presence guard
    }
}
```

Pre-update supply/balance checks cause missed enumeration additions/removals; missing duplicate/presence guards in array helpers allow corrupted enumeration state.

#### Example 2: Correct Example

```solidity
contract ERC1155EnumerableFixed is ERC1155, ReentrancyGuard {
    uint256[] private _allTokens;
    mapping(uint256 => uint256) private _idTotalSupply;
    mapping(address => uint256[]) private _ownedTokens;
    mapping(uint256 => mapping(address => uint256)) private _ownedTokenIndex;
    mapping(uint256 => uint256) private _allTokensIndex;

    function _addTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (from == address(0)) {
            _idTotalSupply[id] += amount;
            if (_idTotalSupply[id] == amount) _addTokenToAllTokensEnumeration(id); // @audit post-increment check
        }
        if (to != address(0) && to != from) {
            uint256 newBal = balanceOf(to, id) + amount;
            if (newBal == amount) _addTokenToOwnerEnumeration(to, id); // @audit post-transfer check
        }
    }

    function _removeTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (to == address(0)) {
            if (_idTotalSupply[id] == amount) _removeTokenFromAllTokensEnumeration(id); // @audit pre-decrement check equals amount
            _idTotalSupply[id] -= amount;
        }
        if (from != address(0) && from != to) {
            if (balanceOf(from, id) == amount) _removeTokenFromOwnerEnumeration(from, id); // @audit pre-transfer check equals amount
        }
    }

    function _addTokenToAllTokensEnumeration(uint256 id) internal {
        require(_allTokensIndex[id] == 0 && _allTokens.length == 0 || _allTokens[_allTokensIndex[id]] != id, "already enumerated");
        _allTokensIndex[id] = _allTokens.length;
        _allTokens.push(id);
    }

    function _removeTokenFromAllTokensEnumeration(uint256 id) internal {
        require(_allTokensIndex[id] < _allTokens.length && _allTokens[_allTokensIndex[id]] == id, "not enumerated");
        uint256 index = _allTokensIndex[id];
        uint256 last = _allTokens[_allTokens.length - 1];
        _allTokens[index] = last;
        _allTokensIndex[last] = index;
        _allTokens.pop();
    }

    function _addTokenToOwnerEnumeration(address account, uint256 id) internal {
        require(_ownedTokenIndex[id][account] == 0 && _ownedTokens[account].length == 0 || _ownedTokens[account][_ownedTokenIndex[id][account]] != id, "already owned");
        _ownedTokenIndex[id][account] = _ownedTokens[account].length;
        _ownedTokens[account].push(id);
    }

    function _removeTokenFromOwnerEnumeration(address account, uint256 id) internal {
        require(_ownedTokenIndex[id][account] < _ownedTokens[account].length && _ownedTokens[account][_ownedTokenIndex[id][account]] == id, "not owned");
        uint256 index = _ownedTokenIndex[id][account];
        uint256 last = _ownedTokens[account][_ownedTokens[account].length - 1];
        _ownedTokens[account][index] = last;
        _ownedTokenIndex[id][account] = index;
        _ownedTokens[account].pop();
    }

    function mint(address to, uint256 id, uint256 amount, bytes calldata data) external nonReentrant {
        _mint(to, id, amount, data);
    }

    function burn(address from, uint256 id, uint256 amount) external nonReentrant {
        _burn(from, id, amount);
    }
}
```

Post-update checks ensure enumeration matches actual supply/balance; array helpers validate presence/absence; nonReentrant guards mint/burn entry points.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
