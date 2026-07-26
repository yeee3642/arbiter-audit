// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Batch payout contract used to distribute grants.
contract PayoutDistributor {
    address public owner;
    IERC20 public immutable token;
    mapping(address => uint256) public paid;

    event Payout(address indexed to, uint256 amount);

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    /// @dev Return values of the token transfers are discarded, so a token that
    ///      returns false on failure is treated as a successful payout.
    function distribute(address[] calldata recipients, uint256[] calldata amounts) external {
        require(msg.sender == owner, "not owner");
        require(recipients.length == amounts.length, "length mismatch");
        for (uint256 i = 0; i < recipients.length; i++) {
            token.transfer(recipients[i], amounts[i]);
            paid[recipients[i]] += amounts[i];
            emit Payout(recipients[i], amounts[i]);
        }
    }

    /// @dev Low-level call result is never inspected.
    function refundEther(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        to.call{value: amount}("");
    }

    receive() external payable {}
}
