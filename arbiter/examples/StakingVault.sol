// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Deliberately vulnerable contract for ARBITER's local end-to-end demo.
contract StakingVault {
    mapping(address => uint256) public stakeOf;
    uint256 public totalStaked;

    constructor() payable {
        stakeOf[msg.sender] = msg.value;
        totalStaked = msg.value;
    }

    function stake() external payable {
        require(msg.value > 0, "amount is zero");
        stakeOf[msg.sender] += msg.value;
        totalStaked += msg.value;
    }

    function unstake() external {
        uint256 amount = stakeOf[msg.sender];
        require(amount > 0, "no position");

        // Deliberate reentrancy bug: state is cleared after the external call.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");

        totalStaked -= amount;
        stakeOf[msg.sender] = 0;
    }
}
