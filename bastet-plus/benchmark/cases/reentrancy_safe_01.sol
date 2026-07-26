// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Same escrow, following checks-effects-interactions and guarded.
contract GuardedEtherBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    address public owner;
    uint256 private _locked = 1;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier nonReentrant() {
        require(_locked == 1, "reentrant call");
        _locked = 2;
        _;
        _locked = 1;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @dev Effects before interactions, plus a reentrancy guard.
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient balance");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}
