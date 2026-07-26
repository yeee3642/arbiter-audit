// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Same distributor, checking every external call.
contract GuardedPayoutDistributor {
    address public owner;
    IERC20 public immutable token;
    mapping(address => uint256) public paid;

    event Payout(address indexed to, uint256 amount);

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function distribute(address[] calldata recipients, uint256[] calldata amounts) external {
        require(msg.sender == owner, "not owner");
        require(recipients.length == amounts.length, "length mismatch");
        for (uint256 i = 0; i < recipients.length; i++) {
            bool ok = token.transfer(recipients[i], amounts[i]);
            require(ok, "token transfer failed");
            paid[recipients[i]] += amounts[i];
            emit Payout(recipients[i], amounts[i]);
        }
    }

    function refundEther(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ether refund failed");
    }

    receive() external payable {}
}
