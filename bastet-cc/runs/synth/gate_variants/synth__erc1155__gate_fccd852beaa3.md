# ERC1155-Enumeration Supply Check Ordering

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC1155-Enumeration Supply Check Ordering**
ERC1155 enumeration arrays (_allTokens, _ownerTokens) must stay consistent with _idTotalSupply and per-account balances. The standard pattern is to update the supply counter first, then decide whether to add or remove the tokenId from enumeration based on the *post-update* value. If the check reads the supply before the increment/decrement, the logic inverts: a brand-new tokenId (supply 0 -> amount) fails the `supply == 0` test because it reads 0 before the add, but the addition happens after; conversely, burning the last tokens (supply amount -> 0) reads a non-zero supply before the subtraction, so the removal branch is skipped. Both cases leave stale entries or missing entries in the enumeration arrays, breaking `totalSupply()`, `tokenByIndex()`, and owner token iteration, and can enable reward manipulation or asset mismatches. Additionally, the mint path must guard against re-adding a tokenId that already exists in _allTokens (e.g., after a prior burn cycle) to avoid duplicates.

### Detection Checks

1. In mint/_addTokenEnumeration: the condition `_idTotalSupply[id] == 0` is evaluated *before* `_idTotalSupply[id] += amount`; it must be evaluated after the increment (or use the post-increment value).
2. In burn/_removeTokenEnumeration: the condition `_idTotalSupply[id] == 0` is evaluated *before* `_idTotalSupply[id] -= amount`; it must be evaluated after the decrement (or use the post-decrement value).
3. In mint/_addTokenEnumeration: when `from == address(0)` and the post-increment supply equals `amount` (i.e., was zero before), the code calls `_addTokenToAllTokensEnumeration(id)` without verifying `id` is not already present in `_allTokens`, allowing duplicates if the same id is minted again after a full burn.
4. In mint/_addTokenEnumeration: the owner enumeration addition uses `balanceOf(to, id) == 0` *before* the balance is increased; this check must use the post-mint balance (or be moved after the balance update) to avoid missing the first mint to an account.
5. In burn/_removeTokenEnumeration: the owner enumeration removal uses `balanceOf(from, id) == 0` *before* the balance is decreased; this check must use the post-burn balance (or be moved after the balance update) to correctly remove the tokenId when the account reaches zero.
6. Any external mint/burn entry point (mint, mintBatch, burn, burnBatch, _mint, _burn, _mintBatch, _burnBatch) that calls the internal enumeration helpers must follow Checks-Effects-Interactions: update supply and balances before enumeration mutations, and before any `onERC1155Received`/`onERC1155BatchReceived` callbacks.
7. The contract must not emit `TransferSingle`/`TransferSingle` events with incorrect `from`/`to`/`id`/`value` that would mislead indexers relying on enumeration consistency.
8. If the contract implements `ERC1155Enumerable` (or similar), verify that `totalSupply()` returns `_allTokens.length` and `tokenByIndex(index)` returns `_allTokens[index]` without gaps or duplicates.

### Examples

#### Example 1: Incorrect Example

```solidity
contract ERC1155Flawed is ERC1155 {
    uint256[] private _allTokens;
    mapping(uint256 => uint256) private _idTotalSupply;
    mapping(uint256 => mapping(address => uint256)) private _balances;

    function _addTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (from == address(0)) {
            // BUG: reads supply before increment
            if (_idTotalSupply[id] == 0) _allTokens.push(id);
            _idTotalSupply[id] += amount;
        }
        if (to != address(0) && to != from) {
            // BUG: reads balance before increment
            if (_balances[id][to] == 0) _addTokenToOwnerEnumeration(to, id);
        }
    }

    function _removeTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (to == address(0)) {
            // BUG: reads supply before decrement
            if (_idTotalSupply[id] == 0) _removeTokenFromAllTokensEnumeration(id);
            _idTotalSupply[id] -= amount;
        }
        if (from != address(0) && from != to) {
            // BUG: reads balance before decrement
            if (_balances[id][from] == 0) _removeTokenFromOwnerEnumeration(from, id);
        }
    }

    function _mint(address to, uint256 id, uint256 amount, bytes memory data) internal {
        _addTokenEnumeration(address(0), to, id, amount);
        _balances[id][to] += amount;
        emit TransferSingle(address(0), address(0), to, id, amount);
        if (to.isContract()) IERC1155Receiver(to).onERC1155Received(address(0), address(0), id, amount, data);
    }

    function _burn(address from, uint256 id, uint256 amount) internal {
        _removeTokenEnumeration(from, address(0), id, amount);
        _balances[id][from] -= amount;
        emit TransferSingle(address(0), from, address(0), id, amount);
    }
}
```

The mint path checks `_idTotalSupply[id] == 0` before incrementing, so a brand-new tokenId passes the check but the addition happens after; the burn path checks `_idTotalSupply[id] == 0` before decrementing, so burning the last tokens sees non-zero supply and skips removal. Owner enumeration checks also read balances before updates. This leaves _allTokens with missing or duplicate entries.

#### Example 2: Correct Example

```solidity
contract ERC1155Fixed is ERC1155 {
    uint256[] private _allTokens;
    mapping(uint256 => uint256) private _idTotalSupply;
    mapping(uint256 => mapping(address => uint256)) private _balances;
    mapping(uint256 => uint256) private _allTokensIndex; // tokenId -> index+1

    function _addTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (from == address(0)) {
            uint256 oldSupply = _idTotalSupply[id];
            _idTotalSupply[id] = oldSupply + amount;
            // Add to global enumeration only if this is the first mint (oldSupply == 0) and not already tracked
            if (oldSupply == 0 && _allTokensIndex[id] == 0) {
                _allTokensIndex[id] = _allTokens.push(id);
            }
        }
        if (to != address(0) && to != from) {
            uint256 oldBal = _balances[id][to];
            _balances[id][to] = oldBal + amount;
            if (oldBal == 0) _addTokenToOwnerEnumeration(to, id);
        }
    }

    function _removeTokenEnumeration(address from, address to, uint256 id, uint256 amount) internal {
        if (to == address(0)) {
            uint256 oldSupply = _idTotalSupply[id];
            _idTotalSupply[id] = oldSupply - amount;
            // Remove from global enumeration only if supply hits zero
            if (_idTotalSupply[id] == 0) {
                _removeTokenFromAllTokensEnumeration(id);
                _allTokensIndex[id] = 0;
            }
        }
        if (from != address(0) && from != to) {
            uint256 oldBal = _balances[id][from];
            _balances[id][from] = oldBal - amount;
            if (_balances[id][from] == 0) _removeTokenFromOwnerEnumeration(from, id);
        }
    }

    function _mint(address to, uint256 id, uint256 amount, bytes memory data) internal {
        _addTokenEnumeration(address(0), to, id, amount);
        emit TransferSingle(address(0), address(0), to, id, amount);
        if (to.isContract()) IERC1155Receiver(to).onERC1155Received(address(0), address(0), id, amount, data);
    }

    function _burn(address from, uint256 id, uint256 amount) internal {
        _removeTokenEnumeration(from, address(0), id, amount);
        emit TransferSingle(address(0), from, address(0), id, amount);
    }
}
```

Supply and balances are updated first (capturing old values), then enumeration mutations use post-update state. Global enumeration adds only when oldSupply==0 and the tokenId is not already indexed; removes only when post-burn supply==0. Owner enumeration uses pre-update balance to detect 0->non-zero and non-zero->0 transitions correctly. Callbacks occur after all state changes (CEI).

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
