# Zksync-EVM-Compatibility-Payable-Receive

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Zksync-EVM-Compatibility-Payable-Receive**
ZKsync Era is an EVM-compatible ZK-rollup that diverges from Ethereum in several subtle ways. Contracts deployed on ZKsync must account for differences in gas metering, opcode support, and system contract interactions. A common class of issues arises when contracts assume Ethereum's behavior for payable functions and the receive() hook. On ZKsync, the default account abstraction (AA) implementation means that external calls from EOAs may arrive via the `DefaultAccount` contract, which forwards calldata and value differently than a raw EOA call on L1. Specifically, `msg.sender` inside a payable function or receive() may be the `DefaultAccount` system contract address rather than the original EOA, and `tx.origin` is not available. Additionally, ZKsync's gas model charges for calldata and computation differently; a receive() hook that performs storage writes or external calls can exceed the 2300 gas stipend that Ethereum's transfer() imposes, but ZKsync does not enforce this stipend, so reentrancy risk is higher. Contracts that rely on `msg.value` in receive() or fallback to distinguish deposit types, or that assume `msg.sender == tx.origin` for access control, will misbehave. Another incompatibility is the handling of `payable` on constructors and `selfdestruct`: ZKsync does not support `selfdestruct` and constructor `msg.value` is always zero. Finally, the `receive()` function is only triggered when calldata is empty; on ZKsync, AA transactions often include non-empty calldata even for simple transfers, so `fallback()` may be invoked instead.

### Detection Checks

1. Check that payable functions and receive()/fallback() do not use `tx.origin` for authentication or logic, as it is always `address(0)` on ZKsync.
2. Verify that contracts do not assume `msg.sender` in receive()/fallback() is the original EOA; it may be the `DefaultAccount` system contract (address 0x8000...). Use `msg.sender` only for value accounting, not identity.
3. Ensure no reliance on the 2300 gas stipend for reentrancy protection in receive()/fallback(); ZKsync does not enforce it. Apply reentrancy guards (e.g., OpenZeppelin ReentrancyGuard) on all state-changing payable entry points.
4. Confirm that constructor is not marked `payable` expecting to receive funds; ZKsync constructors cannot receive value. Move any funding logic to an explicit `initialize()` or `deposit()` function.
5. Check for use of `selfdestruct`; it is not supported on ZKsync and will revert. Replace with a withdrawal pattern and contract deactivation flag.
6. Validate that `receive()` and `fallback()` correctly handle non-empty calldata from account abstraction wallets; do not assume empty calldata means EOA transfer.
7. Ensure that `msg.value` accounting in payable functions matches the actual value received; on ZKsync, `msg.value` is correct but the sender may be a system contract, so do not use `msg.sender` for balance mapping keys without translation.
8. Check that contracts do not use `block.gaslimit` or `gasleft()` for precise gas calculations, as ZKsync's gas metering differs and these values are not equivalent to L1.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableDeposit {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() payable {
        owner = msg.sender;
        // @audit constructor cannot receive value on ZKsync
    }

    receive() external payable {
        // @audit assumes msg.sender is EOA, but may be DefaultAccount
        // @audit no reentrancy guard, ZKsync has no 2300 gas stipend
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        // @audit tx.origin is address(0) on ZKsync, breaks auth
        require(tx.origin == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    function kill() external {
        // @audit selfdestruct not supported on ZKsync
        selfdestruct(payable(owner));
    }
}
```

Constructor marked payable, receive() trusts msg.sender and lacks reentrancy guard, withdraw() uses tx.origin, and kill() uses selfdestruct — all incompatible with ZKsync.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract FixedDeposit is ReentrancyGuard {
    mapping(address => uint256) public balances;
    address public owner;
    bool public active = true;

    constructor() {
        owner = msg.sender; // msg.sender is deployer, no value expected
    }

    function initialize() external payable {
        // explicit funding after deployment
        require(msg.sender == owner, "only owner");
    }

    receive() external payable {
        _deposit(msg.sender, msg.value);
    }

    fallback() external payable {
        _deposit(msg.sender, msg.value);
    }

    function _deposit(address from, uint256 value) internal nonReentrant {
        // from may be DefaultAccount; use it as key or map via AA context
        balances[from] += value;
    }

    function withdraw() external nonReentrant {
        require(msg.sender == owner, "not owner");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function deactivate() external {
        require(msg.sender == owner, "not owner");
        active = false;
    }
}
```

Removes payable constructor, adds explicit initialize(), uses ReentrancyGuard on receive/fallback/withdraw, replaces tx.origin with msg.sender, replaces selfdestruct with deactivation flag, and handles both receive() and fallback() for AA compatibility.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
