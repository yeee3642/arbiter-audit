# Solmate-Missing Return Check on SafeTransferLib

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Solmate-Missing Return Check on SafeTransferLib**
Solmate's SafeTransferLib implements ERC20 transfers via low-level calls that return a boolean success flag. Unlike OpenZeppelin's SafeERC20, Solmate's safeTransfer and safeTransferFrom do not revert on a false return value; they simply return the boolean to the caller. If the caller ignores this return value, a transfer to an address with no code (e.g., a non-existent token contract or an EOA) will succeed silently, leaving the contract's internal accounting out of sync with the actual token balances. Attackers can exploit this by directing transfers to addresses that return no code, causing the protocol to credit users for tokens that never moved, enabling theft of future deposits.

### Detection Checks

1. Call to SafeTransferLib.safeTransfer or safeTransferFrom whose return value is not assigned to a variable or used in a require/assert statement.
2. The call occurs inside a function that updates internal balance accounting (e.g., mint, deposit, createVault) after the transfer.
3. No explicit check of the target address via extcodesize or a prior isContract validation before the transfer.
4. The token address parameter is user-supplied or derived from untrusted input without verification that it is a deployed contract.
5. The function does not revert when the transfer returns false, allowing execution to continue and state to be updated.
6. No fallback to a wrapper that enforces the return check (e.g., a custom safeTransfer that requires success).
7. The transfer is not wrapped in a try/catch that handles the false return, nor is the boolean result propagated to an external caller that must handle it.
8. The codebase imports Solmate's SafeTransferLib (import "solmate/utils/SafeTransferLib.sol") and uses its functions directly.

### Examples

#### Example 1: Incorrect Example

```solidity
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";

contract VaultFactory {
    mapping(address => uint256) public shares;
    
    function createVault(address token, uint256 amount) external {
        ERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount; // @audit missing return check
    }
}
```

The safeTransferFrom return value is ignored; a transfer to a non-contract address succeeds silently and the user's share balance is incorrectly increased.

#### Example 2: Correct Example

```solidity
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";

contract VaultFactory {
    mapping(address => uint256) public shares;
    
    function createVault(address token, uint256 amount) external {
        bool success = ERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        if (!success) revert TransferFailed();
        shares[msg.sender] += amount;
    }
    
    error TransferFailed();
}
```

The boolean return value is captured and the transaction reverts on failure, preventing state updates when the transfer does not actually move tokens.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
