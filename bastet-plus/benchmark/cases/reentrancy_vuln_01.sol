// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Simple ETH escrow with per-user balances.
contract EtherBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    address public owner;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @dev State is updated only after the external call returns.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}
